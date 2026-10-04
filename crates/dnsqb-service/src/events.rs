//! T-277 — `GET /admin/events`, the Server-Sent Events stream that replaces
//! `/admin/ui`'s 2 s poll. Each frame names a [`Topic`]; the page re-fetches
//! that topic's data through its ordinary `GET` route. The one exception is
//! `status`, whose frame carries the `AdminStatusResponse` JSON itself: it is
//! sampled here once a second (its counters, watchdog state and cert trust
//! change with no writer in this process) and sent only when it changed.
//!
//! [`serve_streaming`] is what the accept loop hands every request to: it
//! takes `GET /admin/events` itself and delegates everything else to
//! [`dispatch::serve`] unchanged, so that function and its tests keep their
//! `Full<Bytes>` body type.
//!
//! Bounds: at most [`MAX_EVENT_SUBSCRIBERS`] streams at once (`503` past
//! that; the page falls back to polling), a `ping` frame every
//! [`PING_INTERVAL`] so the page can tell a silent service from a dead one,
//! and every stream ends when `/admin/shutdown` fires, so graceful shutdown
//! never waits out its timeout on an open page. Privacy: frames carry a
//! topic name and a version counter, or the status DTO the page already
//! reads from `GET /admin/status` — never a domain name.

use crate::change_bus::Topic;
use crate::dispatch::{self, AppState, ADMIN_EVENTS_PATH};
use crate::upstream::DohClient;
use bytes::Bytes;
use futures_util::future::select_all;
use futures_util::stream;
use http_body_util::{combinators::BoxBody, BodyExt, StreamBody};
use hyper::body::{Body, Frame};
use hyper::{header, Method, Request, Response, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, OwnedSemaphorePermit};

/// Open `/admin/events` streams allowed at once — one per open `/admin/ui`
/// tab is the expected load; HTTP/2 multiplexes them onto one connection.
pub(crate) const MAX_EVENT_SUBSCRIBERS: usize = 4;

/// How often an otherwise idle stream sends a `ping` frame. The page treats
/// 25 s of silence as "service unreachable", so this must stay well below.
pub(crate) const PING_INTERVAL: Duration = Duration::from_secs(10);

/// How often the status sampler rebuilds `AdminStatusResponse` while at least
/// one stream is open (an accepted write route also wakes it at once).
pub(crate) const STATUS_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// The response body type the accept loop serves.
pub(crate) type EventBody = BoxBody<Bytes, Infallible>;

/// The accept loop's request handler: `GET /admin/events` here, everything
/// else through [`dispatch::serve`].
///
/// # Errors
///
/// Never — every failure maps to an HTTP status, as in [`dispatch::serve`].
pub async fn serve_streaming<C, B>(
    req: Request<B>,
    state: Arc<AppState<C>>,
) -> Result<Response<EventBody>, Infallible>
where
    C: DohClient + Sync + Send + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if req.uri().path() == ADMIN_EVENTS_PATH && req.method() == Method::GET {
        return Ok(open_event_stream(&state));
    }
    let response = dispatch::serve(req, state).await?;
    Ok(response.map(BodyExt::boxed))
}

fn plain_status(status: StatusCode) -> Response<EventBody> {
    let mut response = Response::new(http_body_util::Empty::new().map_err(|e| match e {}).boxed());
    *response.status_mut() = status;
    response
}

struct StreamState {
    status: watch::Receiver<Arc<str>>,
    topics: Vec<(Topic, watch::Receiver<u64>)>,
    shutdown: watch::Receiver<bool>,
    ping: tokio::time::Interval,
    send_status_first: bool,
    // Held for the stream's lifetime; dropping the stream frees the slot.
    _slot: OwnedSemaphorePermit,
}

fn open_event_stream<C: DohClient + Sync>(state: &AppState<C>) -> Response<EventBody> {
    let Ok(slot) = Arc::clone(state.event_slots()).try_acquire_owned() else {
        return plain_status(StatusCode::SERVICE_UNAVAILABLE);
    };
    let shutdown = state.shutdown_handle();
    if *shutdown.borrow() {
        return plain_status(StatusCode::SERVICE_UNAVAILABLE);
    }
    let status = state.status_feed().subscribe();
    state.status_subscriber_arrived().notify_one();
    let bus = state.change_bus();
    let topics = Topic::ALL
        .into_iter()
        .filter(|topic| *topic != Topic::Status)
        .map(|topic| (topic, bus.subscribe(topic)))
        .collect();
    let mut ping =
        tokio::time::interval_at(tokio::time::Instant::now() + PING_INTERVAL, PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let initial = StreamState {
        status,
        topics,
        shutdown,
        ping,
        send_status_first: true,
        _slot: slot,
    };
    let frames = stream::unfold(initial, |mut st| async move {
        let frame = next_frame(&mut st).await?;
        Some((Ok::<_, Infallible>(Frame::data(frame)), st))
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-store")
        .body(StreamBody::new(frames).boxed())
        .unwrap_or_else(|_| plain_status(StatusCode::INTERNAL_SERVER_ERROR))
}

/// The next SSE frame, or `None` to end the stream (shutdown, or the
/// service's `AppState` going away).
async fn next_frame(st: &mut StreamState) -> Option<Bytes> {
    if st.send_status_first {
        st.send_status_first = false;
        let json = Arc::clone(&st.status.borrow_and_update());
        if !json.is_empty() {
            return Some(status_frame(&json));
        }
    }
    if *st.shutdown.borrow() {
        return None;
    }
    let StreamState {
        status,
        topics,
        shutdown,
        ping,
        ..
    } = st;
    tokio::select! {
        changed = shutdown.changed() => {
            // A send of `true` or a dropped sender both mean "stop".
            let _ = changed;
            None
        }
        changed = status.changed() => {
            changed.ok()?;
            let json = Arc::clone(&status.borrow_and_update());
            Some(status_frame(&json))
        }
        topic = next_topic(topics) => {
            let (topic, version) = topic?;
            Some(Bytes::from(format!("event: {}\ndata: {version}\n\n", topic.event_name())))
        }
        _ = ping.tick() => Some(Bytes::from_static(b"event: ping\ndata: \n\n")),
    }
}

fn status_frame(json: &str) -> Bytes {
    // serde_json never emits a raw newline, so the JSON is one `data:` line.
    Bytes::from(format!("event: status\ndata: {json}\n\n"))
}

async fn next_topic(topics: &mut [(Topic, watch::Receiver<u64>)]) -> Option<(Topic, u64)> {
    let waits = topics.iter_mut().map(|(topic, rx)| {
        Box::pin(async move {
            rx.changed().await.ok()?;
            let version = *rx.borrow_and_update();
            Some((*topic, version))
        })
    });
    let (next, _, _) = select_all(waits).await;
    next
}

/// The one status sampler for the whole service. Parks while no stream is
/// open; otherwise rebuilds the status JSON every [`STATUS_SAMPLE_INTERVAL`]
/// (or at once on a `Status` bump) and publishes it only when it changed.
pub(crate) async fn run_status_sampler<C: DohClient + Sync>(state: Arc<AppState<C>>) {
    let mut wake = state.change_bus().subscribe(Topic::Status);
    loop {
        if state.status_feed().receiver_count() == 0 {
            state.status_subscriber_arrived().notified().await;
            continue;
        }
        if let Some(json) = state.status_json() {
            state.status_feed().send_if_modified(|current| {
                if **current == *json {
                    false
                } else {
                    *current = Arc::from(json);
                    true
                }
            });
        }
        tokio::select! {
            () = tokio::time::sleep(STATUS_SAMPLE_INTERVAL) => {}
            changed = wake.changed() => {
                // The bus lives as long as `state`, which this task holds.
                let _ = changed;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{run_status_sampler, serve_streaming, EventBody, MAX_EVENT_SUBSCRIBERS};
    use crate::dispatch::tests::{admin_post_json, no_op_client, state_with, MockClient};
    use crate::dispatch::{serve, AppState};
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{Method, Request, Response, StatusCode};
    use std::sync::Arc;
    use std::time::Duration;

    async fn open(state: &Arc<AppState<MockClient>>, method: Method) -> Response<EventBody> {
        let Ok(req) = Request::builder()
            .method(method)
            .uri("/admin/events")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        match serve_streaming(req, Arc::clone(state)).await {
            Ok(response) => response,
            Err(err) => match err {},
        }
    }

    /// The next data frame as text; `None` when the stream ended.
    async fn next_text(body: &mut EventBody) -> Option<String> {
        next_text_within(body, Duration::from_secs(5)).await
    }

    async fn next_text_within(body: &mut EventBody, limit: Duration) -> Option<String> {
        loop {
            match tokio::time::timeout(limit, body.frame()).await {
                Ok(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        return Some(String::from_utf8_lossy(&data).into_owned());
                    }
                }
                Ok(Some(Err(err))) => match err {},
                Ok(None) => return None,
                Err(elapsed) => panic!("no frame within {limit:?}: {elapsed}"),
            }
        }
    }

    async fn post(state: &Arc<AppState<MockClient>>, req: Request<Full<Bytes>>) -> StatusCode {
        match serve_streaming(req, Arc::clone(state)).await {
            Ok(response) => response.status(),
            Err(err) => match err {},
        }
    }

    #[tokio::test]
    async fn a_stream_starts_with_status_then_pushes_a_changed_topic() {
        let state = state_with(no_op_client());
        tokio::spawn(run_status_sampler(Arc::clone(&state)));
        let response = open(&state, Method::GET).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .map(hyper::header::HeaderValue::as_bytes),
            Some(&b"text/event-stream"[..])
        );
        let mut body = response.into_body();
        let first = next_text(&mut body).await.unwrap_or_default();
        assert!(first.starts_with("event: status\ndata: {"), "got {first:?}");

        let added = admin_post_json(
            "/admin/overrides/add",
            &serde_json::json!({ "pattern": "example.com", "list": "blocklist" }),
        );
        assert!(post(&state, added).await.is_success());
        let mut seen = Vec::new();
        while !seen
            .iter()
            .any(|f: &String| f.starts_with("event: overrides\n"))
        {
            let Some(frame) = next_text(&mut body).await else {
                panic!("stream ended before the overrides event; saw {seen:?}");
            };
            seen.push(frame);
        }
        for frame in &seen {
            assert!(
                !frame.contains("example.com") || frame.starts_with("event: status\n"),
                "a topic frame must carry only a version: {frame:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_fifth_stream_is_refused_and_a_closed_one_frees_its_slot() {
        let state = state_with(no_op_client());
        let mut open_streams = Vec::new();
        for _ in 0..MAX_EVENT_SUBSCRIBERS {
            let response = open(&state, Method::GET).await;
            assert_eq!(response.status(), StatusCode::OK);
            open_streams.push(response);
        }
        assert_eq!(
            open(&state, Method::GET).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(open_streams.pop());
        assert_eq!(open(&state, Method::GET).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn shutdown_ends_an_open_stream() {
        let state = state_with(no_op_client());
        let mut body = open(&state, Method::GET).await.into_body();
        // Already waiting inside the stream when shutdown fires - the case a
        // page open across `/admin/shutdown` is in.
        let reader = tokio::spawn(async move { next_text(&mut body).await });
        tokio::task::yield_now().await;
        let shutdown = Request::builder()
            .method(Method::POST)
            .uri("/admin/shutdown")
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(b"{}")));
        let Ok(shutdown) = shutdown else {
            panic!("fixture request must build");
        };
        assert!(post(&state, shutdown).await.is_success());
        let ended = match reader.await {
            Ok(frame) => frame,
            Err(err) => panic!("reader task failed: {err}"),
        };
        assert_eq!(ended, None, "the stream must end on shutdown");
        assert_eq!(
            open(&state, Method::GET).await.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "no new stream once shutting down"
        );
    }

    #[tokio::test]
    async fn a_non_get_is_405_and_serve_alone_answers_400() {
        let state = state_with(no_op_client());
        assert_eq!(
            open(&state, Method::POST).await.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        let Ok(req) = Request::builder()
            .method(Method::GET)
            .uri("/admin/events")
            .body(Full::new(Bytes::new()))
        else {
            panic!("fixture request must build");
        };
        let status = match serve(req, Arc::clone(&state)).await {
            Ok(response) => response.status(),
            Err(err) => match err {},
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unchanged_status_is_not_resent_and_an_idle_stream_pings() {
        let state = state_with(no_op_client());
        tokio::spawn(run_status_sampler(Arc::clone(&state)));
        let mut body = open(&state, Method::GET).await.into_body();
        let first = next_text(&mut body).await.unwrap_or_default();
        assert!(first.starts_with("event: status\n"), "got {first:?}");
        // Ten 1 s samples of an unchanged status pass; the next frame is the
        // 10 s ping, not another status.
        let started = tokio::time::Instant::now();
        let next = next_text_within(&mut body, Duration::from_secs(15))
            .await
            .unwrap_or_default();
        assert_eq!(next, "event: ping\ndata: \n\n");
        assert!(
            started.elapsed() >= Duration::from_secs(9),
            "the ping came early"
        );
    }

    #[tokio::test]
    async fn a_rejected_write_pushes_nothing() {
        let state = state_with(no_op_client());
        let mut body = open(&state, Method::GET).await.into_body();
        let invalid = admin_post_json(
            "/admin/overrides/add",
            &serde_json::json!({ "pattern": "not a domain!", "list": "blocklist" }),
        );
        assert!(post(&state, invalid).await.is_client_error());
        let cleared = admin_post_json("/admin/log/clear", &serde_json::json!({}));
        assert!(post(&state, cleared).await.is_success());
        let frame = next_text(&mut body).await.unwrap_or_default();
        assert!(
            frame.starts_with("event: log\n"),
            "the first frame must be the accepted clear, not the rejected add: {frame:?}"
        );
    }
}

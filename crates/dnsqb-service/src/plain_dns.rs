//! Plain DNS on port 53 (T-305 batch 3b): RFC 1035 UDP and TCP, RFC 7766
//! framing, on `127.0.0.1` and `::1` only. Opt-in (`[plain_dns] enabled`);
//! the app never changes the OS DNS settings — pointing Windows here is the
//! user's own step.
//!
//! The addresses are constants: nothing in config or on the admin channel can
//! make this listen beyond loopback (SECURITY.md). Every query goes through
//! the same [`Resolve`] function as `DoH` (`dispatch::resolve_message`); this
//! module only frames, bounds and truncates.
//!
//! Each listener is one task that owns its socket, and the per-query and
//! per-connection tasks live in that task's own `JoinSet`: aborting the
//! listener task drops all of them, so the port is free again at once.

use crate::log_throttle::WarnThrottle;
use crate::wire::{decode_wire_message, encode_wire_message, formerr_for_undecodable};
use futures_util::future::BoxFuture;
use hickory_proto::op::Message;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;

/// The well-known DNS port (RFC 1035 §4.2).
pub(crate) const PLAIN_DNS_PORT: u16 = 53;

/// The only addresses ever bound.
const LOOPBACK: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::LOCALHOST),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
];

/// Largest UDP query read; anything longer is cut and fails to decode.
const UDP_RECV_BUFFER: usize = 4096;
/// UDP queries being resolved at once per socket; more are dropped (counted).
const UDP_IN_FLIGHT: usize = 256;
/// TCP connections open at once per listener; more are closed at accept.
const TCP_CONNECTIONS: usize = 64;
/// Queries one TCP connection may send before it is closed.
const TCP_QUERIES_PER_CONNECTION: usize = 100;
/// Deadline for reading one whole TCP message (length + body), and for
/// writing one answer: a trickling peer can't hold a slot.
const TCP_MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);
/// RFC 1035 §4.2.1: the UDP size without EDNS.
const UDP_PLAIN_LIMIT: u16 = 512;
/// The largest UDP answer we send whatever the client's OPT says (DNS Flag
/// Day 2020) — the same value we advertise in our own OPT.
const UDP_EDNS_LIMIT: u16 = 1232;
/// Pause after a socket error that is not about one datagram, so a broken
/// socket can't spin the loop.
const SOCKET_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Runs one decoded query through the pipeline. `None`: send nothing.
pub(crate) type Resolve = Arc<dyn Fn(Message) -> BoxFuture<'static, Option<Message>> + Send + Sync>;

/// Why the listeners could not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindFailure {
    /// Another program holds the port.
    PortInUse,
    /// The OS refused (on Windows also an excluded or reserved port).
    PermissionDenied,
    /// Anything else.
    Other,
}

impl BindFailure {
    fn from_io(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::AddrInUse => Self::PortInUse,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => Self::Other,
        }
    }
}

/// Bound sockets, not yet served.
#[derive(Debug)]
pub(crate) struct Sockets {
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
}

impl Sockets {
    /// The bound UDP addresses (TCP uses the same ones).
    pub(crate) fn local_addrs(&self) -> Vec<SocketAddr> {
        self.udp
            .iter()
            .filter_map(|socket| socket.local_addr().ok())
            .collect()
    }
}

/// Binds UDP and TCP on `127.0.0.1:port` and `[::1]:port`. `::1` missing
/// (IPv6 off) is skipped; any other failure on either address fails the
/// whole bind, so no half-listening state exists. Must run inside a Tokio
/// runtime.
pub(crate) fn bind(port: u16) -> Result<Sockets, BindFailure> {
    let mut sockets = Sockets {
        udp: Vec::new(),
        tcp: Vec::new(),
    };
    for ip in LOOPBACK {
        match bind_one(SocketAddr::new(ip, port)) {
            Ok((udp, tcp)) => {
                sockets.udp.push(udp);
                sockets.tcp.push(tcp);
            }
            Err(err) if ip.is_ipv6() && err.kind() == io::ErrorKind::AddrNotAvailable => {
                tracing::info!("plain DNS: ::1 is not available, listening on 127.0.0.1 only");
            }
            Err(err) => {
                tracing::warn!("plain DNS: bind failed: {err}");
                return Err(BindFailure::from_io(&err));
            }
        }
    }
    Ok(sockets)
}

/// Attempts at a free UDP+TCP port pair when port 0 (tests) is asked for.
const ANY_PORT_ATTEMPTS: u64 = 64;

/// UDP and TCP on one address. Port 0 means "any free pair" (tests only):
/// Windows hands out ephemeral ports in sequence for both protocols, so a
/// port the other protocol has excluded (Hyper-V ranges of 100) would fail
/// every retry in a row — each attempt takes a random high port instead.
fn bind_one(addr: SocketAddr) -> io::Result<(UdpSocket, TcpListener)> {
    let bind_pair = |at: SocketAddr| {
        std::net::UdpSocket::bind(at).and_then(|udp| {
            let tcp = std::net::TcpListener::bind(udp.local_addr()?)?;
            Ok((udp, tcp))
        })
    };
    let (udp, tcp) = if addr.port() == 0 {
        use std::hash::BuildHasher;
        let seed = std::collections::hash_map::RandomState::new();
        let mut attempt: u64 = 0;
        loop {
            attempt += 1;
            let offset = u16::try_from(seed.hash_one(attempt) % 16_384).unwrap_or(0);
            match bind_pair(SocketAddr::new(addr.ip(), 49_152 + offset)) {
                Ok(pair) => break pair,
                Err(_) if attempt < ANY_PORT_ATTEMPTS => {}
                Err(err) => return Err(err),
            }
        }
    } else {
        bind_pair(addr)?
    };
    udp.set_nonblocking(true)?;
    tcp.set_nonblocking(true)?;
    Ok((UdpSocket::from_std(udp)?, TcpListener::from_std(tcp)?))
}

/// Counters the admin status reads.
#[derive(Debug, Default)]
pub(crate) struct Counters {
    /// UDP queries dropped because [`UDP_IN_FLIGHT`] were already running.
    pub(crate) udp_dropped: AtomicU64,
}

/// Serves `sockets` until the returned set is dropped or aborted.
pub(crate) fn spawn(sockets: Sockets, resolve: &Resolve, counters: &Arc<Counters>) -> JoinSet<()> {
    let mut tasks = JoinSet::new();
    for socket in sockets.udp {
        tasks.spawn(serve_udp(socket, Arc::clone(resolve), Arc::clone(counters)));
    }
    for listener in sockets.tcp {
        tasks.spawn(serve_tcp(listener, Arc::clone(resolve)));
    }
    tasks
}

/// Logs `message` at most once a minute per loop.
fn throttled_warn(throttle: &mut WarnThrottle, message: &str, err: &io::Error) {
    if let Some(suppressed) = throttle.admit(Instant::now()) {
        tracing::warn!("plain DNS: {message}: {err} ({suppressed} more suppressed)");
    }
}

/// Errors `recv_from` reports for one datagram on Windows: WSAECONNRESET
/// (an ICMP port-unreachable for an earlier reply) and WSAEMSGSIZE (a
/// datagram longer than the buffer). The socket is fine; read the next one.
fn is_per_datagram(err: &io::Error) -> bool {
    matches!(err.kind(), io::ErrorKind::ConnectionReset)
        || matches!(err.raw_os_error(), Some(10040 | 10054))
}

async fn serve_udp(socket: UdpSocket, resolve: Resolve, counters: Arc<Counters>) {
    let mut queries: JoinSet<(Option<Vec<u8>>, SocketAddr)> = JoinSet::new();
    let mut buf = vec![0u8; UDP_RECV_BUFFER];
    let mut throttle = WarnThrottle::default();
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let (len, peer) = match received {
                    Ok(received) => received,
                    Err(err) => {
                        throttled_warn(&mut throttle, "receive failed", &err);
                        if !is_per_datagram(&err) {
                            tokio::time::sleep(SOCKET_ERROR_BACKOFF).await;
                        }
                        continue;
                    }
                };
                if queries.len() >= UDP_IN_FLIGHT {
                    counters.udp_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let wire = buf.get(..len).unwrap_or_default().to_vec();
                let resolve = Arc::clone(&resolve);
                queries.spawn(async move { (answer(&wire, &resolve, true).await, peer) });
            }
            Some(done) = queries.join_next(), if !queries.is_empty() => {
                // A query task only ends by returning: nothing aborts it
                // while this loop runs, and a panic has nothing to send.
                let Ok((Some(reply), peer)) = done else { continue };
                if let Err(err) = socket.send_to(&reply, peer).await {
                    throttled_warn(&mut throttle, "send failed", &err);
                }
            }
        }
    }
}

async fn serve_tcp(listener: TcpListener, resolve: Resolve) {
    let mut connections: JoinSet<()> = JoinSet::new();
    let mut throttle = WarnThrottle::default();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        if connections.len() >= TCP_CONNECTIONS {
                            drop(stream);
                            continue;
                        }
                        connections.spawn(serve_tcp_connection(stream, Arc::clone(&resolve)));
                    }
                    Err(err) => {
                        throttled_warn(&mut throttle, "accept failed", &err);
                        tokio::time::sleep(SOCKET_ERROR_BACKOFF).await;
                    }
                }
            }
            // Reaps finished connections so the count above stays true; a
            // connection's end (or panic) needs no further action.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

/// RFC 7766: length-prefixed messages, answered in order. Closes on EOF, a
/// zero length, a message not read within [`TCP_MESSAGE_TIMEOUT`], a failed
/// write, or after [`TCP_QUERIES_PER_CONNECTION`] queries.
async fn serve_tcp_connection(mut stream: TcpStream, resolve: Resolve) {
    for _ in 0..TCP_QUERIES_PER_CONNECTION {
        let read = tokio::time::timeout(TCP_MESSAGE_TIMEOUT, read_message(&mut stream)).await;
        let Ok(Ok(Some(wire))) = read else {
            return;
        };
        let Some(reply) = answer(&wire, &resolve, false).await else {
            continue;
        };
        let Ok(len) = u16::try_from(reply.len()) else {
            return;
        };
        let mut framed = Vec::with_capacity(reply.len().saturating_add(2));
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&reply);
        let written = tokio::time::timeout(TCP_MESSAGE_TIMEOUT, stream.write_all(&framed)).await;
        if !matches!(written, Ok(Ok(()))) {
            return;
        }
    }
}

/// One length-prefixed message; `None` on a clean EOF or a zero length.
async fn read_message(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    match stream.read_exact(&mut len).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let len = usize::from(u16::from_be_bytes(len));
    if len == 0 {
        return Ok(None);
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// The wire answer to one query, or `None` to send nothing (shorter than a
/// header, or a response). UDP answers are cut to the client's size limit.
async fn answer(wire: &[u8], resolve: &Resolve, udp: bool) -> Option<Vec<u8>> {
    match crate::wire::precheck_raw(wire) {
        crate::wire::RawPrecheck::Drop => return None,
        crate::wire::RawPrecheck::Reply(bytes) => return Some(bytes),
        crate::wire::RawPrecheck::Decode => {}
    }
    let Ok(query) = decode_wire_message(wire) else {
        return formerr_for_undecodable(wire);
    };
    let limit = udp.then(|| udp_limit(&query));
    let response = resolve(query).await?;
    let bytes = encode_wire_message(&response).ok()?;
    match limit {
        Some(limit) if bytes.len() > usize::from(limit) => {
            // RFC 1035 §4.2.1 / RFC 6891 §7: TC=1 with the question (and our
            // OPT) only; the client retries over TCP.
            let truncated = encode_wire_message(&response.truncate()).ok()?;
            (truncated.len() <= usize::from(limit)).then_some(truncated)
        }
        Some(_) | None => Some(bytes),
    }
}

/// The largest UDP answer `query`'s sender takes: its OPT size within
/// 512…1232, or 512 without OPT.
fn udp_limit(query: &Message) -> u16 {
    query.edns.as_ref().map_or(UDP_PLAIN_LIMIT, |edns| {
        edns.max_payload().clamp(UDP_PLAIN_LIMIT, UDP_EDNS_LIMIT)
    })
}

#[cfg(test)]
mod tests {
    use super::{answer, bind, spawn, udp_limit, BindFailure, Counters, Resolve};
    use crate::wire::{decode_wire_message, encode_wire_message};
    use hickory_proto::op::{Edns, Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Answers with `records` A records for the question.
    fn answering(records: usize) -> Resolve {
        Arc::new(move |query: Message| {
            Box::pin(async move {
                let mut response = Message::new(
                    query.metadata.id,
                    MessageType::Response,
                    query.metadata.op_code,
                );
                response.queries.clone_from(&query.queries);
                if let Some(edns) = &query.edns {
                    let mut own = Edns::new();
                    own.set_max_payload(1232);
                    own.set_dnssec_ok(edns.flags().dnssec_ok);
                    response.set_edns(own);
                }
                let name = query.queries.first().map(|q| q.name().clone())?;
                for i in 0..records {
                    let last = u8::try_from(i % 250).unwrap_or(0);
                    response.answers.push(Record::from_rdata(
                        name.clone(),
                        60,
                        RData::A(A(Ipv4Addr::new(192, 0, 2, last))),
                    ));
                }
                Some(response)
            })
        })
    }

    fn query(edns_size: Option<u16>) -> Message {
        let mut query = Message::query();
        query.metadata.id = 0x1234;
        let Ok(name) = Name::from_str("example.com.") else {
            panic!("fixture name");
        };
        query.add_query(Query::query(name, RecordType::A));
        if let Some(size) = edns_size {
            let mut edns = Edns::new();
            edns.set_max_payload(size);
            query.set_edns(edns);
        }
        query
    }

    fn wire(message: &Message) -> Vec<u8> {
        match encode_wire_message(message) {
            Ok(bytes) => bytes,
            Err(err) => panic!("encode: {err}"),
        }
    }

    fn decoded(bytes: &[u8]) -> Message {
        match decode_wire_message(bytes) {
            Ok(message) => message,
            Err(err) => panic!("decode: {err}"),
        }
    }

    #[test]
    fn the_udp_limit_follows_the_client_opt_within_bounds() {
        assert_eq!(udp_limit(&query(None)), 512);
        assert_eq!(udp_limit(&query(Some(4096))), 1232);
        assert_eq!(udp_limit(&query(Some(1400))), 1232);
        assert_eq!(udp_limit(&query(Some(800))), 800);
        assert_eq!(udp_limit(&query(Some(100))), 512);
    }

    #[tokio::test]
    async fn a_small_answer_goes_out_whole() {
        let Some(bytes) = answer(&wire(&query(None)), &answering(2), true).await else {
            panic!("must answer");
        };
        let reply = decoded(&bytes);
        assert_eq!(reply.answers.len(), 2);
        assert!(!reply.metadata.truncation);
    }

    // RFC 1035 §4.2.1: without OPT a UDP answer is at most 512 bytes; a
    // larger one is cut to the question with TC=1.
    #[tokio::test]
    async fn a_large_udp_answer_without_opt_is_truncated_to_512() {
        let Some(bytes) = answer(&wire(&query(None)), &answering(60), true).await else {
            panic!("must answer");
        };
        assert!(bytes.len() <= 512, "{}", bytes.len());
        let reply = decoded(&bytes);
        assert!(reply.metadata.truncation);
        assert!(reply.answers.is_empty());
        assert_eq!(reply.queries.len(), 1);
        assert_eq!(reply.metadata.id, 0x1234);
    }

    // OPT 4096 is honoured only up to 1232; the truncated answer keeps OPT.
    #[tokio::test]
    async fn an_opt_size_above_1232_is_capped() {
        let Some(bytes) = answer(&wire(&query(Some(4096))), &answering(100), true).await else {
            panic!("must answer");
        };
        assert!(bytes.len() <= 1232);
        let medium = answer(&wire(&query(Some(4096))), &answering(40), true).await;
        let Some(medium) = medium else {
            panic!("must answer");
        };
        // 40 records fit in 1232 but not in 512.
        assert!(medium.len() > 512 && medium.len() <= 1232);
        assert!(!decoded(&medium).metadata.truncation);
        let reply = decoded(&bytes);
        assert!(reply.metadata.truncation && reply.edns.is_some());
    }

    #[tokio::test]
    async fn tcp_answers_are_never_truncated() {
        let Some(bytes) = answer(&wire(&query(None)), &answering(60), false).await else {
            panic!("must answer");
        };
        let reply = decoded(&bytes);
        assert!(!reply.metadata.truncation);
        assert_eq!(reply.answers.len(), 60);
    }

    // Misuse: garbage after a valid header gets FORMERR; a response or a
    // short packet gets nothing (no reflection).
    #[tokio::test]
    async fn garbage_is_formerr_and_responses_or_runts_are_silent() {
        let mut garbage = vec![0xab, 0xcd, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        garbage.extend_from_slice(&[0xff; 7]);
        let Some(bytes) = answer(&garbage, &answering(1), true).await else {
            panic!("garbage gets FORMERR");
        };
        assert_eq!(
            decoded(&bytes).metadata.response_code,
            ResponseCode::FormErr
        );
        let mut response = query(None);
        response.metadata.message_type = MessageType::Response;
        assert_eq!(answer(&wire(&response), &answering(1), true).await, None);
        assert_eq!(answer(&[0u8; 11], &answering(1), true).await, None);
    }

    fn served() -> (tokio::task::JoinSet<()>, SocketAddr, Arc<Counters>) {
        let sockets = match bind(0) {
            Ok(sockets) => sockets,
            Err(err) => panic!("bind port 0: {err:?}"),
        };
        let Some(addr) = sockets.local_addrs().into_iter().find(SocketAddr::is_ipv4) else {
            panic!("127.0.0.1 is always bound");
        };
        let counters = Arc::new(Counters::default());
        (spawn(sockets, &answering(1), &counters), addr, counters)
    }

    #[tokio::test]
    async fn a_udp_query_is_answered() {
        let (_tasks, addr, _) = served();
        let client = match tokio::net::UdpSocket::bind("127.0.0.1:0").await {
            Ok(client) => client,
            Err(err) => panic!("client bind: {err}"),
        };
        if let Err(err) = client.send_to(&wire(&query(None)), addr).await {
            panic!("send: {err}");
        }
        let mut buf = [0u8; 1500];
        let received = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf)).await;
        let Ok(Ok(len)) = received else {
            panic!("no UDP answer");
        };
        let reply = decoded(buf.get(..len).unwrap_or_default());
        assert_eq!(reply.metadata.id, 0x1234);
        assert_eq!(reply.answers.len(), 1);
    }

    async fn tcp_exchange(stream: &mut tokio::net::TcpStream, message: &[u8]) -> Message {
        let Ok(len) = u16::try_from(message.len()) else {
            panic!("fixture fits");
        };
        let mut framed = len.to_be_bytes().to_vec();
        framed.extend_from_slice(message);
        if let Err(err) = stream.write_all(&framed).await {
            panic!("write: {err}");
        }
        let mut len = [0u8; 2];
        if let Err(err) = stream.read_exact(&mut len).await {
            panic!("read length: {err}");
        }
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
        if let Err(err) = stream.read_exact(&mut body).await {
            panic!("read body: {err}");
        }
        decoded(&body)
    }

    // RFC 7766: several queries on one connection, answered in order.
    #[tokio::test]
    async fn tcp_queries_on_one_connection_are_answered_in_order() {
        let (_tasks, addr, _) = served();
        let mut stream = match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => stream,
            Err(err) => panic!("connect: {err}"),
        };
        for id in [1u16, 2, 3] {
            let mut q = query(None);
            q.metadata.id = id;
            let reply = tcp_exchange(&mut stream, &wire(&q)).await;
            assert_eq!(reply.metadata.id, id);
        }
    }

    // The connection closes after its query budget.
    #[tokio::test]
    async fn a_tcp_connection_closes_after_its_query_budget() {
        let (_tasks, addr, _) = served();
        let mut stream = match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => stream,
            Err(err) => panic!("connect: {err}"),
        };
        for _ in 0..super::TCP_QUERIES_PER_CONNECTION {
            tcp_exchange(&mut stream, &wire(&query(None))).await;
        }
        let mut probe = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut probe)).await;
        assert!(matches!(closed, Ok(Ok(0) | Err(_))), "{closed:?}");
    }

    // Slow loris: a connection that never sends a whole message is closed
    // after the message deadline, even if it trickles bytes.
    #[tokio::test(start_paused = true)]
    async fn a_trickling_tcp_peer_is_closed_at_the_message_deadline() {
        let (_tasks, addr, _) = served();
        let mut stream = match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => stream,
            Err(err) => panic!("connect: {err}"),
        };
        // Length 100, then one byte every 4 s.
        if let Err(err) = stream.write_all(&[0, 100]).await {
            panic!("write: {err}");
        }
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_secs(4)).await;
            if stream.write_all(&[0]).await.is_err() {
                break;
            }
        }
        let mut probe = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut probe)).await;
        assert!(matches!(closed, Ok(Ok(0) | Err(_))), "{closed:?}");
    }

    // Saturation: past the in-flight cap a datagram is dropped and counted,
    // never queued.
    #[tokio::test]
    async fn udp_queries_past_the_in_flight_cap_are_dropped_and_counted() {
        let started = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&started);
        let stuck: Resolve = Arc::new(move |_query| {
            seen.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::pending())
        });
        let sockets = match bind(0) {
            Ok(sockets) => sockets,
            Err(err) => panic!("bind: {err:?}"),
        };
        let Some(addr) = sockets.local_addrs().into_iter().find(SocketAddr::is_ipv4) else {
            panic!("127.0.0.1 is always bound");
        };
        let counters = Arc::new(Counters::default());
        let _tasks = spawn(sockets, &stuck, &counters);
        let client = match tokio::net::UdpSocket::bind("127.0.0.1:0").await {
            Ok(client) => client,
            Err(err) => panic!("client bind: {err}"),
        };
        let extra = 20;
        for _ in 0..super::UDP_IN_FLIGHT + extra {
            if let Err(err) = client.send_to(&wire(&query(None)), addr).await {
                panic!("send: {err}");
            }
        }
        for _ in 0..200 {
            if counters.udp_dropped.load(Ordering::SeqCst) >= u64::try_from(extra).unwrap_or(0) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(started.load(Ordering::SeqCst) <= super::UDP_IN_FLIGHT);
        assert!(counters.udp_dropped.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn binding_a_taken_port_is_port_in_use() {
        let taken = match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(socket) => socket,
            Err(err) => panic!("bind: {err}"),
        };
        let port = match taken.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => panic!("local_addr: {err}"),
        };
        assert_eq!(bind(port).err(), Some(BindFailure::PortInUse));
    }

    // Aborting the served set frees the port at once (the sockets live only
    // in the listener tasks).
    #[tokio::test]
    async fn dropping_the_served_set_frees_the_port() {
        let (tasks, addr, _) = served();
        drop(tasks);
        tokio::task::yield_now().await;
        let mut rebound = None;
        for _ in 0..50 {
            if let Ok(sockets) = bind(addr.port()) {
                rebound = Some(sockets);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(rebound.is_some(), "port {} still held", addr.port());
    }
}

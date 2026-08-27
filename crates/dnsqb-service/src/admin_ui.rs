//! Embedded web UI served directly by `dnsqb-service` on the same admin
//! channel (T-149) — `GET /admin/ui`, `/admin/ui/main.js`, `/admin/ui/
//! style.css` — replacing the deleted Tauri desktop window (T-52).
//! Compiled into the binary via `include_str!`: no filesystem I/O at
//! runtime, so there is no path parameter and therefore no path-traversal
//! surface to reason about at all.
//!
//! Ported from the former `dnsqb-ui/ui/*` (same layout/labels, same "no
//! local optimistic state, every action refetches" philosophy) with two
//! changes: `window.__TAURI__.core.invoke(...)` calls became same-origin
//! `fetch()` calls (no CORS needed — `dispatch::content_type_is_json`'s
//! CSRF gate on `/admin/config`/`/admin/reset` still applies the same way),
//! and styles moved to an external `style.css` file so this page can ship a
//! strict CSP (no `unsafe-inline`) from the start — the Tauri version never
//! achieved this (T-55, now moot, that crate no longer exists).
//!
//! `default-src 'self'` does **not** restrain `main.js`'s own
//! `innerHTML`-based render — that's Trusted Types, a separate policy this
//! CSP doesn't set. The render is safe today only because nothing in
//! [`crate::AdminStatusResponse`] is domain-derived (booleans/enums/counts
//! only) — a future screen that interpolates a domain into `innerHTML`
//! (e.g. a T-46/T-47 log preview) must revisit this, not assume the CSP
//! above already covers it.

use crate::dispatch::status_response;
use bytes::Bytes;
use http::{header, HeaderName, HeaderValue, Method, Response, StatusCode};
use http_body_util::Full;

const INDEX_HTML: &str = include_str!("../ui/index.html");
const MAIN_JS: &str = include_str!("../ui/main.js");
const STYLE_CSS: &str = include_str!("../ui/style.css");

/// `GET /admin/ui` — the config page itself, the only one of the three that
/// carries the strict CSP (the response a browser actually navigates to).
pub(crate) fn serve_html(method: &Method) -> Response<Full<Bytes>> {
    respond(method, INDEX_HTML, "text/html; charset=utf-8", true)
}

/// `GET /admin/ui/main.js`.
pub(crate) fn serve_js(method: &Method) -> Response<Full<Bytes>> {
    respond(method, MAIN_JS, "text/javascript; charset=utf-8", false)
}

/// `GET /admin/ui/style.css`.
pub(crate) fn serve_css(method: &Method) -> Response<Full<Bytes>> {
    respond(method, STYLE_CSS, "text/css; charset=utf-8", false)
}

/// Any other method on one of these three paths is 405 — same convention as
/// every other route in `dispatch.rs`.
///
/// `frame-ancestors 'none'` is set alongside `default-src 'self'` on the
/// document response, not left to `default-src` alone — `default-src` does
/// not cover framing. Today an untrusted self-signed cert (T-49 still open)
/// incidentally blocks a cross-origin frame from ever completing the TLS
/// handshake; the moment the cert is trust-store-installed, `/admin/ui`
/// would become iframe-able and the provider toggles clickjackable without
/// this header. It's set unconditionally, not contingent on T-49's status.
fn respond(
    method: &Method,
    body: &'static str,
    content_type: &str,
    is_document: bool,
) -> Response<Full<Bytes>> {
    if *method != Method::GET {
        return status_response(StatusCode::METHOD_NOT_ALLOWED);
    }
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        );
    if is_document {
        builder = builder.header(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"),
        );
    }
    builder
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap_or_else(|_| status_response(StatusCode::INTERNAL_SERVER_ERROR))
}

#[cfg(test)]
mod tests {
    use super::{serve_css, serve_html, serve_js};
    use http::{Method, StatusCode};

    #[test]
    fn serve_html_returns_ok_with_a_strict_csp_header() {
        let response = serve_html(&Method::GET);
        assert_eq!(response.status(), StatusCode::OK);
        let csp = response
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok());
        assert_eq!(csp, Some("default-src 'self'; frame-ancestors 'none'"));
    }

    #[test]
    fn serve_html_rejects_non_get() {
        assert_eq!(
            serve_html(&Method::POST).status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    #[test]
    fn serve_js_has_no_csp_header_but_still_has_nosniff() {
        let response = serve_js(&Method::GET);
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("content-security-policy").is_none());
        assert!(response.headers().get("x-content-type-options").is_some());
    }

    #[test]
    fn serve_css_rejects_non_get() {
        assert_eq!(
            serve_css(&Method::POST).status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
}

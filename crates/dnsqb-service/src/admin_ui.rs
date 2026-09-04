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
/// every other route in `dispatch.rs`. Unlike the four `serve_admin_*`
/// handlers there (T-59), this check is **not** redundant with `dispatch::
/// ROUTES` and stays: these three functions are `pub(crate)`, not private to
/// one call site, and this module's own tests below call them directly,
/// bypassing `dispatch::serve` entirely — removing this check would make
/// those tests describe behavior that no longer exists.
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
    use super::{serve_css, serve_html, serve_js, INDEX_HTML, MAIN_JS};
    use http::{Method, StatusCode};

    // T-70: MSIX has no uninstall-time code hook, so the danger-zone card is
    // the only place the trusted cert / Credential Manager secrets ever get
    // cleared — it must actually call the real route, warn about the
    // certificate and every secret by name, and say plainly that this does
    // not remove the app itself.
    #[test]
    fn danger_zone_calls_the_uninstall_route_and_names_every_consequence() {
        assert!(INDEX_HTML.contains("uninstall-local-state-btn"));
        assert!(
            MAIN_JS.contains("/admin/uninstall-local-state"),
            "the button must call the real route"
        );
        for word in ["сертифікат", "TLS-ключ", "MaxMind"] {
            assert!(
                INDEX_HTML.contains(word),
                "the danger-zone warning must name {word} as something it removes"
            );
        }
        assert!(
            INDEX_HTML.contains("не</strong> видаляє сам застосунок"),
            "must say plainly that this does not remove the app itself"
        );
    }

    // T-96: the passive query-log-persistence warning is rendered only when
    // the flag is true, and it names the file and how to turn it off (a
    // config-file edit - there is no toggle in the UI by design).
    #[test]
    fn main_js_shows_the_persistence_warning_gated_on_the_status_flag() {
        assert!(
            MAIN_JS.contains("status.encrypted_persistence.query_log"),
            "the warning must be gated on the status flag, not always shown"
        );
        assert!(MAIN_JS.contains("query-log.enc"));
        assert!(
            MAIN_JS.contains("persist_query_log = false"),
            "the warning must tell the operator how to disable persistence"
        );
    }

    // T-97: the cache-persistence warning is the same shape - gated on its own
    // `encrypted_persistence.cache` flag, names `cache.enc`, and tells the
    // operator the config-file edit that turns it off.
    #[test]
    fn main_js_shows_the_cache_persistence_warning_gated_on_the_status_flag() {
        assert!(
            MAIN_JS.contains("status.encrypted_persistence.cache"),
            "the warning must be gated on the status flag, not always shown"
        );
        assert!(MAIN_JS.contains("cache.enc"));
        assert!(
            MAIN_JS.contains("persist_cache = false"),
            "the warning must tell the operator how to disable persistence"
        );
    }

    // T-81: DB-IP Lite's CC BY 4.0 licence requires the "IP Geolocation by
    // DB-IP" anchor text AND a link back to db-ip.com in the *same* element,
    // on any page displaying data derived from the database - and this page
    // shows GeoIP-derived country data. Checked quote-agnostically and by
    // proving the two live in one <a>, not as two independent substrings
    // (which would pass with the text in one place and a bare URL in a
    // comment elsewhere - the "hostname appears somewhere" gap). MaxMind's
    // GeoLite2 attribution is likewise required whenever that source is in
    // use (T-80).
    #[test]
    fn index_html_carries_the_required_geoip_data_attributions() {
        let html = INDEX_HTML.replace('\'', "\"");
        // Match the closing tag too, so a mention of the phrase in a comment
        // (which has no `</a>` after it) can't be picked up instead of the
        // real element.
        let Some((before_anchor, _)) = html.split_once("IP Geolocation by DB-IP</a>") else {
            panic!("the db-ip.com-mandated anchor element is missing");
        };
        let Some(tag_start) = before_anchor.rfind("<a ") else {
            panic!("the DB-IP anchor text is not inside an <a> element");
        };
        assert!(
            before_anchor[tag_start..].contains("db-ip.com"),
            "the DB-IP attribution anchor must link back to db-ip.com (CC BY 4.0 requirement)"
        );
        assert!(
            html.contains("creativecommons.org/licenses/by/4.0"),
            "the licence must be named and linked, and it is CC BY 4.0 (not -SA)"
        );
        // Scoped to the <footer id="credits"> slice, not the whole document:
        // since T-162 the string "GeoLite2" also appears in a card heading, so
        // a plain `html.contains("GeoLite2")` would no longer fail if the
        // GeoLite2 line were deleted from the footer (the same "phrase
        // present somewhere" gap the DB-IP assertion above already guards
        // against, reopened on the MaxMind half).
        let Some((_, footer)) = html.split_once("<footer id=\"credits\">") else {
            panic!("the #credits footer element is missing");
        };
        let Some((credits, _)) = footer.split_once("</footer>") else {
            panic!("the #credits footer is not closed");
        };
        assert!(
            credits.contains("GeoLite2") && credits.contains("maxmind.com"),
            "MaxMind GeoLite2 attribution must be in the #credits footer (T-80 advanced mode)"
        );
    }

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

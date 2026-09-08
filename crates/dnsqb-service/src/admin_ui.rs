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

    // T-176 — the basic/advanced split is a structural property, so (per the
    // T-59 lesson) the test reads it as data: an explicit expected list of
    // top-level section ids, and which side of the <details> boundary each
    // one sits on. A card silently moved between levels, added, or dropped
    // fails here.

    /// Section ids that must render in the **basic** view — before the
    /// `<details id="advanced-settings">` disclosure.
    const BASIC_SECTION_IDS: &[&str] = &[
        "protection-hero",
        "filter-controls-body",
        "app-body",
        "browser-setup-body",
        "overrides-body",
        "log-body",
    ];
    /// Section ids that must render **inside** the advanced disclosure.
    const ADVANCED_SECTION_IDS: &[&str] = &[
        "timeout-config-body",
        "providers-body",
        "cache-config-body",
        "geoip-body",
        "geoip-maxmind-body",
        "danger-zone-body",
    ];

    #[test]
    fn index_html_places_every_section_on_the_expected_side_of_the_advanced_disclosure() {
        let Some((before_details, rest)) =
            INDEX_HTML.split_once("<details id=\"advanced-settings\">")
        else {
            panic!("the advanced-settings <details> disclosure is missing");
        };
        let Some((inside_details, after_details)) = rest.split_once("</details>") else {
            panic!("the advanced-settings <details> is not closed");
        };

        for id in BASIC_SECTION_IDS {
            let marker = format!("id=\"{id}\"");
            assert!(
                before_details.contains(&marker),
                "basic section {id} must render before the advanced disclosure"
            );
            assert!(
                !inside_details.contains(&marker),
                "basic section {id} must not be inside the advanced disclosure"
            );
        }
        for id in ADVANCED_SECTION_IDS {
            let marker = format!("id=\"{id}\"");
            assert!(
                inside_details.contains(&marker),
                "advanced section {id} must render inside the advanced disclosure"
            );
        }
        // The credits footer stays outside both levels, on every render.
        assert!(
            after_details.contains("<footer id=\"credits\">"),
            "the attribution footer must sit outside the advanced disclosure"
        );
    }

    #[test]
    fn advanced_disclosure_is_collapsed_by_default() {
        assert!(
            INDEX_HTML.contains("<details id=\"advanced-settings\">"),
            "the disclosure must exist"
        );
        assert!(
            !INDEX_HTML.contains("<details id=\"advanced-settings\" open"),
            "the disclosure must be collapsed by default - a non-technical user \
             should never land on the engineering controls"
        );
    }

    #[test]
    fn browser_setup_card_carries_the_doh_url_field_and_the_verification_pointer() {
        assert!(INDEX_HTML.contains("id=\"browser-setup-body\""));
        assert!(
            INDEX_HTML.contains("id=\"doh-url\""),
            "the card must show the DoH URL in a copyable field"
        );
        assert!(
            INDEX_HTML.contains("id=\"doh-url-copy\""),
            "the DoH URL must have a copy button (main.js wires it)"
        );
        assert!(
            INDEX_HTML.contains("ERR_ADDRESS_INVALID"),
            "the steps must point at the real browser-uses-local-DoH check, not just \"the site opened\""
        );
    }

    // T-189 — the browser-setup card carries a static step block per browser
    // family (advisor: keep them in markup, main.js only unhides one), Firefox
    // included, with the real settings-page string, and the detector wires
    // Brave's async refinement.
    #[test]
    fn browser_setup_card_has_a_static_step_block_per_browser_family() {
        for id in [
            "browser-steps-chromium",
            "browser-steps-firefox",
            "browser-steps-other",
        ] {
            assert!(
                INDEX_HTML.contains(id),
                "the {id} step block must be present in static markup"
            );
        }
        assert!(
            INDEX_HTML.contains("about:preferences#privacy"),
            "the Firefox block must name the real settings page"
        );
        for token in ["detectBrowserFamily", "isBrave", "edge://settings"] {
            assert!(
                MAIN_JS.contains(token),
                "the browser detector must handle {token}"
            );
        }
    }

    #[test]
    fn protection_hero_container_exists_for_main_js_to_fill() {
        assert!(
            INDEX_HTML.contains("id=\"protection-hero\""),
            "main.js renders the computed protection status into this container"
        );
    }

    // T-188 — the protection hero gains a cert-trust branch: it fetches
    // GET /admin/cert-status, distinguishes NOT_TRUSTED (with an install
    // action) from UNKNOWN, and the install button POSTs the real route.
    #[test]
    fn main_js_wires_the_cert_trust_hero_branch_and_install_action() {
        assert!(
            MAIN_JS.contains("/admin/cert-status"),
            "the hero must fetch the cert-trust state"
        );
        assert!(
            MAIN_JS.contains("/admin/install-cert"),
            "the install button must call the real route"
        );
        for token in ["NOT_TRUSTED", "UNKNOWN"] {
            assert!(
                MAIN_JS.contains(token),
                "the hero must treat {token} as its own distinct cert state"
            );
        }
        assert!(
            !MAIN_JS.contains("setInterval(refreshCertStatus"),
            "cert-status must not be polled - each call is two certutil spawns server-side"
        );
    }

    // T-176 — the basic-view master + category toggles must call the new
    // atomic route, cover all three categories, and the master switch must
    // never reach for /admin/shutdown (which would kill the admin channel and
    // the tray poll too).
    #[test]
    fn main_js_wires_the_category_toggles_to_the_atomic_route() {
        assert!(
            MAIN_JS.contains("/admin/providers/set-category-enabled"),
            "the category toggles must use the atomic backend route"
        );
        for category in ["SECURITY", "ADS_TRACKERS", "ADULT_CONTENT"] {
            assert!(
                MAIN_JS.contains(category),
                "a basic-view toggle for {category} must be wired"
            );
        }
        assert!(
            MAIN_JS.contains("flipAllCategories"),
            "the master switch flips every category, sequentially"
        );
        assert!(
            !MAIN_JS.contains("/admin/shutdown"),
            "the master switch must not shut the service down - only disable voters"
        );
    }

    // T-176 — the hero status is computed from the same conditions
    // diagrams/ui-status-indicator.md defines (the subset this page sees):
    // watchdog, network, and whether any provider is active.
    #[test]
    fn main_js_computes_the_hero_from_watchdog_network_and_provider_state() {
        for token in [
            "computeProtectionState",
            "GAVE_UP",
            "RESTARTING",
            "OFFLINE",
            "active_providers",
        ] {
            assert!(
                MAIN_JS.contains(token),
                "the hero state computation must consider {token}"
            );
        }
    }

    // T-193 — a tray pause keeps the service up, so nothing else in
    // computeProtectionState fires; without this branch the hero would read
    // green "Захищено" while every query is unfiltered. It ranks between
    // OFFLINE and the 0-providers case, matching the pipeline fast-path order.
    #[test]
    fn main_js_hero_has_a_dedicated_paused_state() {
        let Some((_, after)) = MAIN_JS.split_once("function computeProtectionState(") else {
            panic!("computeProtectionState must exist");
        };
        let Some((body, _)) = after.split_once("\nfunction ") else {
            panic!("computeProtectionState must be a bounded function");
        };
        assert!(
            body.contains("status.paused"),
            "the hero must branch on status.paused"
        );
        assert!(
            body.contains("Фільтрацію призупинено"),
            "the paused hero must name the state, not read as green"
        );
        let offline_at = body.find("OFFLINE").unwrap_or(usize::MAX);
        let paused_at = body.find("status.paused").unwrap_or(0);
        let providers_at = body.find("active_providers").unwrap_or(usize::MAX);
        assert!(
            offline_at < paused_at && paused_at < providers_at,
            "offline must outrank paused, which must outrank the 0-providers case"
        );
    }

    // T-176 — the fan-out privacy line and the pass-through warning moved into
    // the basic view (renderFilterControls), so they render even when the
    // advanced disclosure is collapsed (CLAUDE.md "not buried" / SPEC.md §8.1).
    #[test]
    fn main_js_keeps_the_fanout_and_passthrough_notices_in_the_basic_view() {
        let Some((_, filter_controls)) = MAIN_JS.split_once("function renderFilterControls(")
        else {
            panic!("renderFilterControls must exist");
        };
        let Some((body, _)) = filter_controls.split_once("\nfunction ") else {
            panic!("renderFilterControls must be a bounded function");
        };
        assert!(
            body.contains("third_party_count"),
            "the fan-out privacy line must render in the basic view"
        );
        assert!(
            body.contains("filtering_active"),
            "the pass-through warning must render in the basic view"
        );
    }

    // T-176 closing-advisor — the master switch ("Фільтрація" on) must never
    // create a voter. On a default install ADULT_CONTENT is empty, and
    // set-category-enabled auto-adds opendns-familyshield when that category is
    // switched on with none configured - a path reserved for the explicit adult
    // toggle. flipAllCategories must skip a category with zero configured
    // voters, so turning filtering back on can't silently enable adult
    // filtering (DEFAULT_PROVIDER_IDS / T-170: adult stays opt-in).
    #[test]
    fn main_js_master_switch_only_flips_categories_that_already_have_a_voter() {
        let Some((_, after)) = MAIN_JS.split_once("async function flipAllCategories(") else {
            panic!("flipAllCategories must exist");
        };
        let Some((body, _)) = after.split_once("\nfunction ") else {
            panic!("flipAllCategories must be a bounded function");
        };
        assert!(
            body.contains("entry.category === cat.key"),
            "the master switch must check category membership before flipping"
        );
        assert!(
            body.contains("continue"),
            "a category with no configured voter must be skipped, not created"
        );
    }

    // T-176 closing-advisor — the danger-zone sits inside the collapsed
    // <details>, so a two-step confirm that armed its button must reset the
    // label even on the success path, or a re-collapsed disclosure hides a
    // button stuck reading "Точно видалити все?" (the live-verified gap the
    // clear-log button already guards against with its own finally).
    #[test]
    fn main_js_resets_the_danger_zone_confirm_label_after_the_action() {
        let Some((_, after)) = MAIN_JS.split_once("uninstall-local-state-btn") else {
            panic!("the danger-zone button must be wired");
        };
        let window = &after[..after.len().min(2000)];
        assert!(
            window.contains("finally"),
            "the armed confirm label must reset in a finally, not only on success"
        );
    }
}

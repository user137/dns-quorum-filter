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
        // T-180: CrUX (rating-filter "bubble" popularity source) is CC BY 4.0
        // and its attribution must ride in the same footer. The PSL line
        // (MPL-2.0) is required for the same reason - it is used to derive
        // the published lists.
        assert!(
            credits.contains("Chrome UX Report") && credits.contains("Google"),
            "CrUX attribution must be in the #credits footer (T-180, CC BY 4.0)"
        );
        assert!(
            credits.contains("publicsuffix.org") && credits.contains("MPL 2.0"),
            "Public Suffix List attribution must be in the #credits footer (T-180)"
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
        // T-128 — the always-visible rating-filter «bubble» activity badge.
        "rating-filter-badge",
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
        // T-127/T-111 — the rating-filter «bubble» zone-config card. A niche
        // opt-in, so it lives with the engineering controls.
        "rating-filter-body",
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

    // T-188 / T-204 — the cert-trust branch of the hero moved to the server
    // (admin.rs::compute_hero_state, tested there). `main.js` now only renders
    // the CERT_NOT_TRUSTED / CERT_UNKNOWN presentation and wires the install
    // button; it must NOT fetch /admin/cert-status any more (T-211 made that a
    // pure cache read that the 2s status poll already carries).
    #[test]
    fn main_js_renders_the_cert_hero_states_without_its_own_cert_fetch() {
        for key in ["CERT_NOT_TRUSTED", "CERT_UNKNOWN"] {
            assert!(
                MAIN_JS.contains(key),
                "HERO_PRESENTATION must carry a {key} row"
            );
        }
        assert!(
            MAIN_JS.contains("/admin/install-cert"),
            "the install button must call the real route"
        );
        assert!(
            !MAIN_JS.contains("/admin/cert-status") && !MAIN_JS.contains("refreshCertStatus"),
            "the page must not fetch cert-status itself - it rides on status.hero_state"
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

    // T-176 / T-204 (finding 3-B) — the decisive hero priority ladder
    // (watchdog > offline > paused > 0-voters > cert) moved to the server
    // (admin.rs::compute_hero_state, executed by
    // `admin::hero_and_category_tests`, not just asserted to exist as text —
    // the T-59 lesson). `main.js` must only *render* `status.hero_state`
    // through the HERO_PRESENTATION lookup, never re-derive the ladder.
    #[test]
    fn main_js_renders_the_hero_from_the_server_computed_state() {
        assert!(
            MAIN_JS.contains("heroPresentation(status.hero_state"),
            "render() must map status.hero_state, not recompute it"
        );
        assert!(
            !MAIN_JS.contains("computeProtectionState")
                && !MAIN_JS.contains(r#"status.watchdog === "GAVE_UP""#),
            "the client must not carry the priority ladder any more"
        );
        // Every server variant needs a presentation row (plus the
        // client-only SERVICE_UNREACHABLE synthesised on a failed fetch).
        for key in [
            "SERVICE_UNREACHABLE",
            "WATCHDOG_GAVE_UP",
            "WATCHDOG_RESTARTING",
            "OFFLINE",
            "PAUSED",
            "NO_PROVIDERS",
            "CERT_NOT_TRUSTED",
            "CERT_UNKNOWN",
            "PROTECTED",
        ] {
            assert!(
                MAIN_JS.contains(key),
                "HERO_PRESENTATION must have a {key} row"
            );
        }
    }

    // T-193 / T-204 — the paused hero must name the state and not read as
    // green. (That a pause *outranks* the 0-voters case is the server's job
    // now — `admin::hero_and_category_tests::hero_state_offline_outranks_paused`
    // and the paused-not-protected test.)
    #[test]
    fn main_js_hero_has_a_dedicated_paused_presentation() {
        let Some((_, after)) = MAIN_JS.split_once("PAUSED: {") else {
            panic!("HERO_PRESENTATION.PAUSED must exist");
        };
        let Some((row, _)) = after.split_once("},") else {
            panic!("the PAUSED row must be a bounded object literal");
        };
        assert!(
            row.contains("Фільтрацію призупинено"),
            "the paused hero must name the state plainly"
        );
        assert!(
            row.contains("is-warn"),
            "paused is a warning, not the green is-ok class"
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

    // T-176 closing-advisor / T-204 — the master switch must never create a
    // voter: turning it on must not opt a user into adult filtering with a
    // preset they never chose (set-category-enabled auto-adds
    // opendns-familyshield to an empty ADULT_CONTENT). That guard is now the
    // server's `master_switch_targets` (admin.rs), executed by
    // `admin::hero_and_category_tests::master_switch_targets_excludes_a_
    // category_with_no_configured_voter`. `main.js` must iterate that field,
    // not re-derive membership.
    #[test]
    fn main_js_master_switch_iterates_the_server_target_list() {
        let Some((_, after)) = MAIN_JS.split_once("async function flipAllCategories(") else {
            panic!("flipAllCategories must exist");
        };
        let Some((body, _)) = after.split_once("\nfunction ") else {
            panic!("flipAllCategories must be a bounded function");
        };
        assert!(
            MAIN_JS.contains("flipAllCategories(want, data.master_switch_targets)"),
            "the master switch must be driven by the server's target list"
        );
        assert!(
            !body.contains("entry.category === cat.key"),
            "the client must not re-derive category membership any more"
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

    // T-127/T-111 — the rating-filter card must (1) post to the dedicated
    // write route, (2) gate turn-on behind an explicit confirm step (not a
    // bare checkbox — SPEC.md §8.1 "an always-on warning is functionally
    // identical to no warning"), and (3) build the zone picker from the
    // server's own available_lists, not a hard-coded client list, so a new
    // dataset is one const edit server-side (the mockup's Артборд E rationale).
    #[test]
    fn main_js_rating_filter_card_arms_turn_on_and_drives_the_zone_picker_from_the_server() {
        assert!(
            MAIN_JS.contains("/admin/rating-filter"),
            "the card must post to the dedicated rating-filter route"
        );
        assert!(
            MAIN_JS.contains("Підтвердити ввімкнення"),
            "turning the bubble on must require an explicit confirm step"
        );
        assert!(
            MAIN_JS.contains("rf.available_lists"),
            "the zone picker must render from status.rating_filter.available_lists, \
             not a hard-coded client constant"
        );
        assert!(
            MAIN_JS.contains("aria-activedescendant"),
            "the hand-rolled combobox must be keyboard-navigable"
        );
        assert!(
            MAIN_JS.contains("setRatingFilter(false,"),
            "turning the bubble off must be immediate (no confirm), unlike turn-on"
        );
        assert!(
            MAIN_JS.contains("!rf.available_lists.includes(code)"),
            "a picked code outside available_lists (a config written before T-127) \
             must still render as a removable row, not be silently hidden"
        );
    }

    // T-122 (Батч 4.2) — a gov-* zone is one blanket suffix, not a
    // popularity count; showing "1 дом." next to it would read as broken
    // (the T-66 "never a fake count" discipline). The picked-zone row must
    // render a coverage label instead of the raw domain count for those.
    #[test]
    fn main_js_shows_coverage_not_a_domain_count_for_a_gov_zone() {
        assert!(
            MAIN_JS.contains(r#"code.startsWith("gov-")"#),
            "zoneMeta must special-case the gov-* blanket-suffix codes"
        );
        assert!(
            MAIN_JS.contains("весь простір"),
            "a gov-* zone's row must say it covers a whole domain space, \
             not a misleading single-digit count"
        );
    }

    // T-128 — the always-visible activity indicator: a slot under the hero,
    // filled by renderRatingFilterBadge from the 2s status poll (via
    // render()), and gated on status.rating_filter.enabled so it is an empty
    // div whenever the bubble is off.
    #[test]
    fn main_js_renders_the_rating_filter_badge_from_the_status_poll() {
        assert!(
            INDEX_HTML.contains("id=\"rating-filter-badge\""),
            "the badge needs its slot under the hero"
        );
        assert!(
            MAIN_JS.contains("renderRatingFilterBadge(status.rating_filter)"),
            "the badge must render from the 2s status poll (render()), not go stale"
        );
        assert!(
            MAIN_JS.contains("if (!rf || !rf.enabled)"),
            "the badge must be gated on rating_filter.enabled - empty div when off"
        );
    }
}

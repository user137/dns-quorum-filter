"""Hand-written rows of review/QA-MATRIX.md (Кроки / Очікувано / покриття).

Consumed by qa-matrix-gen.py, which merges these rows into QA-MATRIX.md by ID
and never overwrites the Вердикт / Доказ / Баг columns already filled in there.
An ID is a stable slug of the point x category -- never renumber.

Category codes: HP Happy path, SB Security & Boundary, MF Misuse & Fool,
EP Error path, CR Concurrency/Recovery.
Executor codes: AUTO = MCP-AUTO, PART = MCP-PARTIAL, USER = USER-MANUAL,
CODE = CODE-ONLY.
cov: exact test fn names (checked against the source by the generator), or
"smoke.js:<call>" for ui/smoke.js, or free text starting with "~" (not checked).
"""

import re

ROWS = []


def R(id, surf, point, cat, steps, expect, cov=(), who="AUTO", bug=""):
    ROWS.append(dict(id=id, surf=surf, point=point, cat=cat, steps=steps,
                     expect=expect, cov=list(cov), who=who, bug=bug))


# Cross-route tests that cover every POST/GET route at once.
CSRF_ALL = "every_json_post_route_rejects_a_missing_or_wrong_content_type"
FUZZ_ALL = "serve_never_panics_on_arbitrary_input_for_any_documented_route"
TABLE_ALL = "serve_matches_the_documented_admin_route_allowlist"

GATE_SB = ("POST без Content-Type; з `text/plain`; з `application/x-www-form-urlencoded` "
           "(валідне тіло)")
GATE_SB_EXP = "415 на кожен, стан/файл не змінено (CSRF-гейт, SPEC §8.1)"
BODY_MF = ("тіло >4096 байт; обрізаний JSON; `[]`; відсутнє обов'язкове поле; поле зі "
           "зайвим ключем `{..., \"x\":1}`; невірний тип поля")
BODY_MF_EXP = ("400 на розмір/обрізаний/тип/відсутнє поле; зайвий ключ -- приймається "
               "(у DTO немає `deny_unknown_fields`) -- зафіксувати фактичну поведінку")
METHOD_EP = "GET/PUT/DELETE на цей шлях"
METHOD_EP_EXP = "405, тіло порожнє"


def post_route(slug, path, hp_steps, hp_exp, hp_cov, ep_steps, ep_exp, ep_cov=(),
               mf_extra="", mf_cov=(), cr_steps="", cr_exp="", cr_cov=(), who="AUTO",
               bug=""):
    p = f"POST {path}"
    R(f"A-{slug}-HP", "A", p, "HP", hp_steps, hp_exp, hp_cov, who, bug)
    R(f"A-{slug}-SB", "A", p, "SB", GATE_SB, GATE_SB_EXP, [CSRF_ALL], who)
    R(f"A-{slug}-MF", "A", p, "MF", BODY_MF + (("; " + mf_extra) if mf_extra else ""),
      BODY_MF_EXP, [FUZZ_ALL, *mf_cov], who)
    R(f"A-{slug}-EP", "A", p, "EP", f"{METHOD_EP}; {ep_steps}",
      f"{METHOD_EP_EXP}; {ep_exp}", [TABLE_ALL, *ep_cov], who)
    if cr_steps:
        R(f"A-{slug}-CR", "A", p, "CR", cr_steps, cr_exp, cr_cov, who)


def get_route(slug, path, hp_steps, hp_exp, hp_cov, sb_steps, sb_exp, sb_cov=(),
              mf_steps="", mf_exp="", mf_cov=(), who="AUTO"):
    p = f"GET {path}"
    R(f"A-{slug}-HP", "A", p, "HP", hp_steps, hp_exp, hp_cov, who)
    R(f"A-{slug}-SB", "A", p, "SB", sb_steps, sb_exp, [TABLE_ALL, *sb_cov], who)
    if mf_steps:
        R(f"A-{slug}-MF", "A", p, "MF", mf_steps, mf_exp, [FUZZ_ALL, *mf_cov], who)
    R(f"A-{slug}-EP", "A", p, "EP", "POST/PUT на цей шлях", "405", [TABLE_ALL], who)


PERSIST_EP = ("`resolver_config.toml` тимчасово read-only (атрибут), запит, потім зняти "
              "атрибут")
PERSIST_EP_EXP = ("200 + `persisted:false`, зміна живе в пам'яті; після зняття атрибута "
                  "наступний запис -- `persisted:true` (SPEC §8.1 «A failed disk save»)")

# ---------------------------------------------------------------- A: HTTP API
R("A-dns-query-HP", "A", "GET /dns-query", "HP",
  "RFC 8484 GET `?dns=<base64url>` на A `example.com` (curl, cert пінований)",
  "200, `application/dns-message`, реальна A-відповідь; рядок у `/admin/log`",
  ["serve_answers_a_valid_get_request_with_200_and_the_encoded_response"])
R("A-dns-query-HP2", "A", "POST /dns-query", "HP",
  "POST `application/dns-message`, wire A `example.com`; той самий домен у blocklist -> A",
  "200; дозволений -> реальні IP; заблокований -> `0.0.0.0`/`::` (SPEC §3.2, не NXDOMAIN)",
  ["serve_answers_a_valid_post_request_with_200"])
R("A-dns-query-SB", "A", "GET|POST /dns-query", "SB",
  "POST тіло 65536 байт; GET `dns=` невалідний base64; POST з `Content-Type: text/plain`",
  "413 / 400 / 400 (`text/plain` на /dns-query -- 400 за задумом, тест `serve_returns_400_for_a_post_with_the_wrong_content_type`), без звернення до апстрімів",
  ["serve_returns_413_for_an_oversized_post_body", "serve_returns_400_for_a_malformed_get_query_string",
   "serve_returns_400_for_a_post_with_the_wrong_content_type", FUZZ_ALL])
R("A-dns-query-MF", "A", "GET|POST /dns-query", "MF",
  "GET без `dns=`; GET із percent-encoded base64; POST з валідним заголовком і сміттям у тілі; "
  "запит HTTPS/SVCB-типу",
  "400 на сміття; HTTPS/SVCB проксіюється одному апстріму, без кворуму (SPEC §3)",
  ["wire_bytes_from_get_rejects_a_missing_dns_param",
   "resolve_doh_request_proxies_a_non_a_aaaa_query_to_a_single_upstream"])
R("A-dns-query-EP", "A", "GET|POST /dns-query", "EP", "PUT/DELETE /dns-query; шлях `/dns-query/`",
  "405; 404", ["serve_returns_405_for_an_unsupported_method_on_dns_query",
               "serve_returns_404_for_a_path_other_than_dns_query"])
R("A-dns-query-CR", "A", "GET|POST /dns-query", "CR",
  "20 паралельних запитів на overrides-домен (не доходять до апстрімів)",
  "усі 200, `stats.in_flight` повертається в 0",
  ["resolve_doh_request_leaves_in_flight_at_zero_after_completing"])

get_route("health", "/health",
          "curl /health", "200 `{active_providers, geoip}`, без мережевих викликів (SPEC §7.1 #10)",
          ["serve_health_returns_200_with_pipeline_status"],
          "запит без пінованого cert (`-k` заборонено, лише перевірка, що TLS піднято на 127.0.0.1); "
          "з'єднання на 0.0.0.0/LAN-IP", "слухач лише 127.0.0.1 -- з LAN-IP відмова з'єднання")
get_route("admin-status", "/admin/status",
          "curl /admin/status", "200, `schema_version`=6, `app_version`=0.8.0, усі поля DTO "
          "(UI-SPEC §2.1), `hero_state` відповідає стану", ["serve_admin_status_returns_the_default_live_settings",
                                                           "serve_admin_status_hero_state_tracks_the_live_pause_and_cert_flags"],
          "запит з `Origin: https://evil.test`", "200 (read-only, CSRF не потрібен), CORS-заголовків "
          "немає -> браузер чужого сайту не прочитає відповідь", (),
          "GET із `?x=1` і довгим query", "200, query ігнорується")
post_route("admin-config", "/admin/config",
           "`{timeout_mode:\"degraded\", serve_baseline_when_filters_unreachable:true}` -> "
           "GET status -> файл -> повернути як було",
           "200, `persisted:true`, `/admin/status` і `resolver_config.toml` відображають обидва поля",
           ["serve_admin_config_persists_a_change_to_disk_when_a_config_path_is_set",
            "serve_admin_config_round_trips_the_baseline_fallback_toggle"],
           PERSIST_EP + "; невідомий `timeout_mode:\"x\"`", PERSIST_EP_EXP + "; 400",
           ["serve_admin_config_reports_not_persisted_when_no_config_path_is_set",
            "serve_admin_config_rejects_a_malformed_body"],
           mf_cov=["serve_admin_config_never_panics_on_arbitrary_bodies"],
           cr_steps="паралельно POST /admin/config і POST /admin/cache-config/apply",
           cr_exp="обидві зміни і в пам'яті, і на диску (persist_lock)",
           cr_cov=["concurrent_admin_config_and_cache_config_posts_leave_disk_matching_both_live_fields"])
post_route("admin-reset", "/admin/reset",
           "трей «Скинути кеш і лог» або POST `{}`", "200, лог і кеш порожні, конфіг перечитано з диска",
           ["serve_admin_reset_reloads_settings_and_clears_state"],
           "зіпсований `overrides.toml` / `resolver_config.toml` >64 КБ (на копії, з відкатом)",
           "500, живий стан не змінено (prepare-then-commit)",
           ["serve_admin_reset_returns_500_for_a_malformed_overrides_file_and_leaves_state_untouched",
            "serve_admin_reset_returns_500_for_an_oversized_resolver_config_file"],
           cr_steps="POST /admin/reset паралельно з /admin/cache-config/apply",
           cr_exp="диск і пам'ять узгоджені",
           cr_cov=["concurrent_admin_reset_and_cache_config_apply_leave_disk_matching_live_cache_config"])
post_route("admin-shutdown", "/admin/shutdown",
           "ДЕСТРУКТИВНО (правило 5): POST `{}` -> спостерігати процес і watcher",
           "200; процес сервісу завершується gracefully; watcher респавнить його (не `quit.flag`)",
           ["serve_admin_shutdown_returns_200_and_signals_the_watch_channel"],
           "повторний POST під час завершення", "200 або відмова з'єднання, без паніки",
           ["serve_admin_shutdown_still_returns_200_once_every_receiver_is_dropped"], who="PART")
get_route("admin-overrides", "/admin/overrides",
          "curl", "200 `{allowlist, blocklist, conflicts, persisted:true}`; на 0.7.0 `overrides.toml` відсутній -> порожні списки",
          ["serve_admin_overrides_returns_the_current_lists_and_conflicts"],
          "`Origin` чужого сайту", "200 без CORS")
post_route("admin-overrides-add", "/admin/overrides/add",
           "`{pattern:\"qa-block.test\", list:\"blocklist\"}`, потім DoH-запит на нього, потім remove",
           "200, `persisted:true`, домен -> `0.0.0.0`, рядок `BLOCKLIST` у лозі, кешований вердикт інвалідовано",
           ["serve_admin_overrides_add_appends_a_new_entry_and_it_is_visible_on_the_next_get",
            "serve_admin_overrides_add_invalidates_a_cached_verdict_for_the_newly_blocked_domain"],
           "pattern `*.`, `a..b`, 300-символьний домен, `list:\"OTHER\"`; " + PERSIST_EP,
           "400 на невалідний; " + PERSIST_EP_EXP,
           ["serve_admin_overrides_add_rejects_an_invalid_pattern"],
           mf_extra="той самий домен в allow і block -> `conflicts`",
           cr_steps="10 паралельних add різних доменів", cr_exp="жоден не загублено",
           cr_cov=["concurrent_admin_overrides_add_posts_lose_no_updates"])
post_route("admin-overrides-remove", "/admin/overrides/remove",
           "remove доданого в A-admin-overrides-add-HP", "200, домен зник, DoH знову резолвить",
           ["serve_admin_overrides_remove_removes_the_matching_entry"],
           "remove відсутнього; невірний `is_wildcard`", "200 no-op, `persisted` правдивий",
           ["serve_admin_overrides_remove_is_a_safe_no_op_for_an_absent_entry"])
get_route("admin-cache-config", "/admin/cache-config", "curl", "200, 5 полів + `persisted:true`, = `[cache]` файлу",
          ["serve_admin_cache_config_returns_the_default_live_settings"], "`Origin` чужого сайту", "200 без CORS")
post_route("admin-cache-config-apply", "/admin/cache-config/apply",
           "змінити `max_capacity` 10000->9999, перевірити, повернути",
           "200, `persisted:true`, кеш перебудовано порожнім (KNOWN-LIMITATIONS: cache.enc near-empty)",
           ["serve_admin_cache_config_apply_updates_the_live_settings",
            "serve_admin_cache_config_apply_persists_a_change_to_disk_when_a_config_path_is_set"],
           "`clamp_min_secs` > `clamp_max_secs`; " + PERSIST_EP, "400; " + PERSIST_EP_EXP,
           ["serve_admin_cache_config_apply_rejects_an_inverted_clamp_range",
            "serve_admin_cache_config_apply_reports_not_persisted_when_no_config_path_is_set"])
R("A-admin-cache-config-apply-SB2", "A", "POST /admin/cache-config/apply", "SB",
  "значення близькі до `u64::MAX` у `block_verdict_ttl_secs`/`clamp_max_secs`/`stale_grace_secs`; "
  "`max_capacity:0`. Перевіряти лише in-process тестом (Фаза 3), живий прогін -- тільки з "
  "відкатом конфігу і явним «так»",
  "відмова 400 або безпечне обрізання. ПІДОЗРА (CODE-ONLY): `CacheConfig::from_secs` перевіряє лише "
  "min>max, а `cache.rs:84` `Instant::now() + ttl` і `cache.rs:303` `ttl + stale_grace` панікують на "
  "переповненні; значення персиститься, тож паніка повторюватиметься після рестарту. `panic` не "
  "`abort` -> гине задача з'єднання, не процес", [], "CODE")
get_route("admin-geoip", "/admin/geoip", "curl",
          "200, `blocked_countries`, `database_loaded:true`, `database_source:USER_COUNTRY`, час збірки БД",
          ["serve_admin_geoip_returns_the_current_list", "serve_admin_geoip_reports_the_loaded_databases_build_time"],
          "`Origin` чужого сайту", "200 без CORS")
post_route("admin-geoip-add", "/admin/geoip/add",
           "`{country:\"kp\"}` -> GET -> remove", "200, нормалізовано в `KP`, `persisted:true`; повтор -- ідемпотентно",
           ["serve_admin_geoip_add_appends_a_new_country_and_it_is_visible_on_the_next_get",
            "serve_admin_geoip_add_normalizes_a_lowercase_code_to_uppercase",
            "serve_admin_geoip_add_is_idempotent_for_an_already_present_country"],
           "`country:\"XX1\"`, `\"\"`, `\"Ukraine\"`", "400",
           ["serve_admin_geoip_add_rejects_an_invalid_code"])
post_route("admin-geoip-remove", "/admin/geoip/remove",
           "remove `kp` (нижній регістр)", "200, видалено", ["serve_admin_geoip_remove_accepts_a_lowercase_code_matching_the_stored_uppercase_entry"],
           "невалідний код; відсутній валідний код", "400; 200 no-op",
           ["serve_admin_geoip_remove_rejects_an_invalid_code"])
R("A-admin-geoip-maxmind-GET-HP", "A", "GET /admin/geoip/maxmind", "HP", "curl",
  "200 `configured:false`, ключ ніколи не повертається", ["maxmind_get_reports_not_configured_on_a_fresh_state",
                                                          "maxmind_get_echoes_the_account_id_after_a_save_and_never_the_key"])
R("A-admin-geoip-maxmind-GET-EP", "A", "GET /admin/geoip/maxmind", "EP", "PUT/DELETE", "405", [TABLE_ALL])
post_route("admin-geoip-maxmind-POST", "/admin/geoip/maxmind",
           "фейкові креди `{account_id:\"999999\", license_key:\"fake_invalid_key\"}` (1 запит до MaxMind), "
           "потім clear",
           "200 `check:REJECTED`, `refresh_health:AUTH_REJECTED`, ключ у Credential Manager, не у файлі",
           ["maxmind_get_echoes_the_account_id_after_a_save_and_never_the_key"],
           "порожнє поле", "400 до будь-якого запиту в мережу",
           ["maxmind_post_with_a_blank_field_is_400_before_any_probe"])
post_route("admin-geoip-maxmind-clear", "/admin/geoip/maxmind/clear",
           "clear після A-admin-geoip-maxmind-POST-HP", "200 `configured:false`, запис Credential Manager видалено",
           ["maxmind_clear_removes_the_credentials_and_reports_not_configured"],
           "clear на чистому стані", "200, ідемпотентно",
           ["serve_admin_geoip_maxmind_clear_is_idempotent_on_a_fresh_state"])
post_route("admin-rating-filter", "/admin/rating-filter",
           "`{enabled:true, lists:[\"ua\"]}` -> дочекатись `active:true` -> DoH на домен поза зоною "
           "(`qa-out.test` не годиться -- потрібен резолвний; узяти `example.org`) -> вимкнути",
           "200, `persisted:true`, поза зоною -> BLOCK `RATING_FILTER`, не кешується; вимкнення повертає норму",
           ["serve_admin_rating_filter_enables_the_bubble_and_the_status_reflects_it",
            "serve_admin_rating_filter_clears_the_cache_when_it_turns_the_filter_on"],
           "`lists:[\"uka\"]`, `[\"fr\"]`", "400 (форма / немає датасету)",
           ["serve_admin_rating_filter_rejects_a_malformed_list_code",
            "serve_admin_rating_filter_rejects_a_code_with_no_dataset"],
           mf_extra="`enabled:true, lists:[]` -> inert, не помилка",
           mf_cov=["serve_admin_rating_filter_enabled_with_no_lists_is_inert_not_an_error"])
post_route("admin-blocklist-bundles", "/admin/blocklist-bundles",
           "`{enabled:true, sources:[\"hagezi-hoster\"]}` (найменше джерело, ~1.2k записів -- мережева ввічливість) -> "
           "status -> вимкнути",
           "200, `persisted:true`, `sources` не перетворюється з `null` на список при `null`",
           ["serve_admin_blocklist_bundles_enables_with_explicit_sources_and_status_reflects_it",
            "serve_admin_blocklist_bundles_none_sources_round_trips_without_freezing"],
           "`sources:[\"nope\"]`", "400", ["serve_admin_blocklist_bundles_rejects_an_unknown_source_id"],
           mf_extra="`enabled:true, sources:[]` -> KNOWN-LIMITATIONS: старий набір лишається чинним")
post_route("admin-cctld-block", "/admin/cctld-block",
           "`{blocked_codes:[\"su\"]}` -> DoH на `qa.su` -> повернути `[]`",
           "200, `persisted:true`, BLOCK `CCTLD_BLOCK` без мережі",
           ["serve_admin_cctld_block_replaces_the_list_and_status_reflects_it",
            "serve_admin_cctld_block_persists_a_change_to_disk_when_a_config_path_is_set"],
           "`[\"r\"]`, `[\"ru1\"]`, `[\"RU\",\"ru\"]`", "400 на невалідні; дубль у різному регістрі -- дедуп",
           ["serve_admin_cctld_block_rejects_a_malformed_code"])
get_route("admin-providers", "/admin/providers", "curl",
          "200: `active` (на 0.7.0 -- 4 рядки з `opendns-familyshield` disabled, залишок смоуку 13c), "
          "`available_presets`, `third_party_count`, `category_states`, `master_switch_targets`",
          ["serve_admin_providers_lists_the_default_three_and_every_preset",
           "serve_admin_providers_carries_the_category_folds_and_master_switch_targets"],
          "`Origin` чужого сайту", "200 без CORS")
post_route("admin-providers-add", "/admin/providers/add",
           "додати preset `cleanbrowsing-security` -> remove неможливий (built-in) -> set-enabled false",
           "200, `persisted:true`, кеш очищено", ["serve_admin_providers_add_a_preset_then_it_is_active_and_persisted"],
           "custom з `http://`, з `https://127.0.0.1/`, з `https://10.0.0.1/`, дубль id, id `A B`",
           "400 на кожен (SSRF literal-host; KNOWN-LIMITATIONS: DNS-rebinding hostname не ловиться)",
           ["serve_admin_providers_add_rejects_ssrf_and_duplicate_and_bad_id"])
post_route("admin-providers-remove", "/admin/providers/remove",
           "додати custom `qa-custom` (https на публічний DoH), remove", "200, зник",
           ["serve_admin_providers_remove_a_custom_entry_but_not_a_builtin"],
           "remove built-in `quad9`; remove неіснуючого", "400 обидва",
           ["serve_admin_providers_remove_a_custom_entry_but_not_a_builtin"])
post_route("admin-providers-set-enabled", "/admin/providers/set-enabled",
           "вимкнути `adguard` -> status -> увімкнути", "200, кеш очищено (bcc8275), status відображає",
           ["serve_admin_providers_set_enabled_toggles_and_status_reflects_it"],
           "невідомий id", "400", ["serve_admin_providers_set_enabled_rejects_an_unknown_id"],
           mf_extra="вимкнути всіх -> pass-through, `filtering_active:false`, hero `NO_PROVIDERS`",
           mf_cov=["disabling_every_provider_is_pass_through_not_fail_closed"])
post_route("admin-providers-set-category-enabled", "/admin/providers/set-category-enabled",
           "`{category:\"ADULT_CONTENT\", enabled:true}` -> перевірити -> false",
           "200, одна транзакція, кеш очищено", ["serve_admin_providers_set_category_enabled_disables_a_whole_category_in_one_write",
                                                 "serve_admin_providers_set_category_enabled_invalidates_the_whole_cache"],
           "невідома категорія", "400", ["serve_admin_providers_set_category_enabled_rejects_unknown_category_and_non_json"])
get_route("admin-log", "/admin/log", "curl `?limit=5`, `?decision=BLOCKED`, `?domain_contains=qa`",
          "200, фільтри працюють, `truncated` правдивий",
          ["serve_admin_log_filters_by_decision", "serve_admin_log_filters_by_domain_contains",
           "serve_admin_log_caps_the_response_at_the_requested_limit_and_reports_truncated"],
          "`?domain_contains=%FF`; `?limit=0`; `?limit=abc`; `?decision=x`; `?voter=`",
          "400 на кожен, ніколи не «без фільтра»; домен із запиту не потрапляє в service.log",
          ["parse_log_query_rejects_invalid_percent_encoding", "parse_log_query_rejects_a_zero_limit"],
          "`?limit=99999999`; невідомий ключ `?foo=1`", "обрізано до 1000; ключ ігнорується",
          ["parse_log_query_clamps_a_limit_above_the_hard_cap", "parse_log_query_ignores_an_unrecognized_key"])
post_route("admin-log-clear", "/admin/log/clear", "POST `{}`", "200, `/admin/log` порожній",
           ["serve_admin_log_clear_actually_empties_the_log"], "повтор на порожньому", "200")
post_route("admin-request-remove-all", "/admin/request-remove-all",
           "ДЕСТРУКТИВНО (правило 5): кнопка danger-zone при живому треї; у діалозі трею -- «Ні»",
           "200 `REQUESTED`, свіжий `remove-all.flag`, трей показує своє підтвердження поверх браузера",
           ["request_remove_all_with_a_live_tray_writes_a_fresh_flag"],
           "без трею (після «Сховати іконку»); без app-data; запис прапорця падає",
           "200 `TRAY_NOT_RUNNING` без прапорця; без app-data -- помилка; збій запису видимий",
           ["request_remove_all_rejects_non_post_methods", "request_remove_all_without_a_tray_writes_nothing",
            "request_remove_all_without_an_app_data_dir_is_unavailable",
            "request_remove_all_surfaces_a_failed_flag_write"], who="PART")
get_route("admin-events", "/admin/events",
          "`curl -N` з пінованим cert; змінити налаштування в іншій вкладці; почекати 10 с",
          "SSE: перший кадр `status`, кадр на змінену тему, `ping` кожні 10 с; потік закривається на /admin/shutdown",
          ["a_stream_starts_with_status_then_pushes_a_changed_topic",
           "an_unchanged_status_is_not_resent_and_an_idle_stream_pings", "shutdown_ends_an_open_stream"],
          "5 одночасних потоків", "п'ятий -> 503; закритий потік звільняє слот",
          ["the_fifth_stream_is_refused_and_a_closed_one_frees_its_slot"],
          "POST, відхилений з 400, при відкритому потоці", "потік нічого не надсилає",
          ["a_rejected_write_pushes_nothing"])
get_route("admin-cert-status", "/admin/cert-status", "curl", "200 `{trusted:TRUSTED}`, без запуску certutil",
          ["serve_admin_cert_status_reads_the_cached_trust_state"], "`Origin` чужого сайту", "200 без CORS",
          ["serve_admin_cert_status_rejects_non_get_methods"])
post_route("admin-install-cert", "/admin/install-cert",
           "ДЕСТРУКТИВНО (правило 5): з hero «Сертифікат не встановлено» -> кнопка",
           "200 `INSTALLED`/`ALREADY_INSTALLED`, cert-status -> TRUSTED синхронно",
           [], "сертифікат уже довірений", "200 `ALREADY_INSTALLED`, без UAC-діалогу",
           ["serve_admin_install_cert_rejects_non_post_methods"], who="USER")
for slug, path, test in (("admin-ui", "/admin/ui", "serve_html_returns_ok_with_a_strict_csp_header"),
                         ("admin-ui-js", "/admin/ui/main.js", "serve_js_has_no_csp_header_but_still_has_nosniff"),
                         ("admin-ui-css", "/admin/ui/style.css", "serve_css_rejects_non_get"),
                         ("admin-ui-favicon", "/admin/ui/favicon.png", "serve_favicon_is_a_png_and_the_page_links_it")):
    get_route(slug, path, "curl -I + тіло", "200, правильний `Content-Type`, `nosniff`; для HTML -- строгий CSP без `unsafe-inline`",
              [test], "`/admin/ui/` (слеш), `/admin/ui/../admin/status`, `/ADMIN/UI`", "404 (точний збіг рядка)",
              ["serve_returns_404_for_every_path_outside_the_documented_allowlist"])
R("A-i18n-HP", "A", "GET /admin/ui/i18n/<37 локалей>.json", "HP",
  "скрипт: curl кожного з 37 (ar bg cs da de el en es et fi fr he hi hr hu id it ja ko lt lv nb nl pl "
  "pt ro sk sl sr-Latn sv sw th tr uk ur vi zh)", "200 x37, валідний JSON, `application/json`",
  ["serve_i18n_json_has_expected_content_type_and_no_csp_for_every_locale",
   "i18n_routes_matches_the_documented_locale_allowlist"])
R("A-i18n-SB", "A", "GET /admin/ui/i18n/*", "SB",
  "`sr.json`, `UK.json`, `uk.json.bak`, `../uk.json`, `uk.JSON`", "404 на кожен",
  ["serve_i18n_404s_on_an_unregistered_locale"])
R("A-i18n-EP", "A", "GET /admin/ui/i18n/*", "EP", "POST на `/admin/ui/i18n/uk.json`", "405",
  ["serve_i18n_rejects_non_get_for_every_locale"])
R("A-unknown-path", "A", "невідомий шлях", "SB",
  "`/admin`, `/admin/`, `/admin/statuss`, `/`, `/favicon.ico`, `/.well-known/x`", "404 на кожен",
  ["serve_returns_404_for_every_path_outside_the_documented_allowlist"])
R("A-tls-SB", "A", "TLS-слухач", "SB",
  "`curl --tlsv1.0 --tls-max 1.1`; HTTP без TLS на 8443; 50 відкритих TCP без хендшейку 12 с",
  "відмова TLS<1.2; без TLS -- розрив; хендшейк-таймаут 10 с закриває (SPEC §1.1, T-169)",
  [], "AUTO")
R("A-routes-unused-by-ui", "A", "маршрути, яких UI не викликає", "HP",
  "звірка: `/admin/reset`, `/admin/shutdown` -- лише трей; `/admin/cert-status` -- трей/hero через status; "
  "`/health` -- watcher; `/dns-query` -- браузер", "кожен має свого споживача (R5) -- інакше мертвий маршрут",
  ["~R5 grep main.js"], "CODE")
R("A-dto-doc-drift", "A", "UI-SPEC.md vs admin.rs DTO", "HP",
  "звірити, що UI-SPEC описує `app_version`, `encrypted_persistence`, `refresh_health`, "
  "`UninstallLocalStateResponse` (5 полів); CLAUDE.md `local_state` каже «3 keyring entries/4 artifacts»",
  "документ = код. На 2026-10-03 grep: ці 4 імені в UI-SPEC відсутні -- кандидат doc-drift (перевірити правило 0)",
  [], "CODE")

# ---------------------------------------------------------------- E: CLI
for b in ("service", "tray", "watcher"):
    exe = f"dnsqb-{b}.exe"
    R(f"E-{b}-help-HP", "E", f"{exe} --help / -h / /?", "HP",
      f"запустити встановлений `{exe}` з кожним прапорцем з PowerShell (безпечно поза пакетом лише "
      f"тому, що `wants_help` виходить до guard/логів/cert -- лише ці три прапорці)",
      "друкує довідку з версією 0.8.0 мовою ОС, код 0, жодних побічних дій (лог, guard, порт)",
      ["wants_help_recognizes_every_documented_spelling", "help_text_names_the_right_binary_and_carries_the_version"])
    R(f"E-{b}-args-MF", "E", f"{exe} --version / --foo / кілька аргументів", "MF",
      f"ЛИШЕ всередині пакета: `Invoke-CommandInDesktopPackage -PackageFamilyName "
      f"dns-quorum-filter_8d78tvs37tgae -AppId App -Command <WindowsApps>\\{exe} -Args '--version'` "
      f"(також `--foo bar`, `--help --foo`). НІКОЛИ прямий запуск exe з PowerShell без `--help`: без "
      f"package identity процес бачить невіртуалізований порожній app-data, guard не спрацьовує, а "
      f"`orchestrate::run` генерує новий cert ДО bind порту і перезаписує TLS-ключ у тому самому записі "
      f"Credential Manager (хеш від логічного шляху)",
      "НЕ довідка для невідомих -> звичайний старт; при живому екземплярі -- single-instance guard / "
      "конфлікт порту, гучна помилка в лозі, без другого процесу. Зафіксувати фактичне",
      ["wants_help_is_false_for_no_args_or_unrelated_args"])
    R(f"E-{b}-console-EP", "E", f"{exe} без консолі", "EP",
      f"запуск через Explorer/ShellExecute (windows_subsystem) з `--help`",
      "жодного вікна консолі, без краху (T-235: println! безпечний)", [], "PART")
R("E-locale", "E", "локаль --help", "HP",
  "`--help` при en-US і uk-UA мові інтерфейсу (якщо доступно змінити -- інакше USER)",
  "текст відповідною мовою, fallback на en", ["help_text_is_never_empty_and_never_panics_for_any_binary"], "PART")

# ---------------------------------------------------------------- B: /admin/ui
UI_POLL = "2s-poll (`setInterval(refresh, 2000)`)"


def ui(id, point, cat, steps, expect, cov=(), who="AUTO", bug=""):
    R(f"B-{id}-{cat}", "B", point, cat, steps, expect, cov, who, bug)


ui("app-title", "#app-title", "HP", "відкрити /admin/ui", "заголовок «DNS Quorum Filter 0.8.0»",
   ["main_js_renders_the_app_title_from_status_app_version"])
ui("locale", "#locale-switcher / #locale-switcher-label / #locale-select", "HP",
   "перемкнути uk -> en -> ar (RTL) -> pl (плюрали) -> uk", "весь текст перекладено, 0 сирих ключів/токенів, "
   "`dir=rtl` для ar; вибір переживає reload", ["locale_switcher_options_name_themselves_not_the_admin_locale",
                                             "smoke.js:applyStatic"])
ui("locale", "#locale-select", "MF",
   "перемкнути локаль посеред вводу в полі override, з відкритою `?`-підказкою і відкритими «Розширені»",
   "введений текст, відкрита підказка і `#advanced-settings.open` не скидаються",
   ["custom_provider_form_is_retranslated_without_rebuilding_or_touching_value"])
ui("locale", "#locale-select", "SB", "підмінити `localStorage` локаль на `../x`/`<script>` і reload",
   "fallback на uk/en, без запиту за межі I18N_ROUTES, без ін'єкції", [])
ui("hero", "#protection-hero (8 HeroStateView + SERVICE_UNREACHABLE)", "HP",
   "спостерегти PROTECTED; викликати PAUSED (трей), NO_PROVIDERS (вимкнути всіх), OFFLINE (hosts, I), "
   "CERT_NOT_TRUSTED/CERT_UNKNOWN (G), WATCHDOG_RESTARTING/GAVE_UP (F), SERVICE_UNREACHABLE (сервіс зупинено)",
   "кожен стан має свій текст/колір, порядок пріоритетів = `compute_hero_state`",
   ["main_js_renders_the_hero_from_the_server_computed_state", "every_hero_presentation_key_has_state_and_detail_in_every_locale"], "PART")
ui("hero", "#protection-hero кнопка встановлення cert", "EP",
   "у CERT_NOT_TRUSTED натиснути дію hero", "POST /admin/install-cert, hero оновлюється без гонитви "
   "(смоук v0.5.0 2b: перший кадр після onboarding показував «не встановлено»)", [], "USER")
ui("hero-last-query", "#hero-last-query", "HP", "спостерегти сегмент hero «останній запит: N хв тому» 2+ хв",
   "відносний вік, оновлюється без перезавантаження (ARCH-04); без запитів -- сегмента немає",
   ["smoke.js:renderLastQuery", "last_query_unix_ms_is_the_newest_entry_time"], "PART")
ui("startup-task", "#startup-task-row", "HP", "спостерегти рядок автозапуску; вимкнути автозапуск у Параметрах Windows",
   "стан MSIX StartupTask (T-243): увімкнено / вимкнено користувачем / політикою",
   ["smoke.js:renderStartupTask", "startup_task_view_wire_strings"], "PART")
ui("rating-badge", "#rating-filter-badge", "HP", "увімкнути бульбашку з `ua`", "бейдж з'являється на 2s-poll, зникає при вимкненні",
   ["main_js_renders_the_rating_filter_badge_from_the_status_poll"])
ui("filter-controls", "#filter-controls-body (master + 3 категорії)", "HP",
   "клік master, клік кожної категорії, клавіатура (Space/Enter на toggle)",
   "виклик set-category-enabled, стан Off/Partial/On з сервера; master не вмикає порожню ADULT",
   ["main_js_master_switch_iterates_the_server_target_list", "main_js_wires_the_category_toggles_to_the_atomic_route"])
ui("filter-controls", "#filter-controls-body", "MF", "подвійний швидкий клік на toggle категорії",
   "фінальний стан = останній клік, без розсинхрону з сервером", [])
ui("filter-controls", "#filter-controls-body", "EP", "сервіс зупинено -> клік", "видима помилка, toggle повертається", [])
ui("browser-setup", "#browser-setup-body, #doh-url, #doh-url-copy, #browser-setup-toggle, #browser-setup-steps, "
   "#browser-detected, " + ", ".join(f"#browser-steps-{b}, #settings-url-{b}, #settings-copy-{b}"
                                     for b in ("chrome", "edge", "brave", "opera", "vivaldi", "firefox"))
   + ", #browser-steps-other, #browser-verify-chromium, #browser-verify-firefox, #browser-setup-result", "HP",
   "розгорнути, кожна кнопка копіювання -> буфер; Chrome і Firefox (UA)", "правильний блок кроків, DoH URL з реальним портом",
   ["browser_setup_card_has_a_static_step_block_per_browser",
    "browser_setup_card_carries_the_doh_url_field_and_the_verification_pointer"])
ui("browser-setup", "#doh-url-copy", "EP", "копіювання без дозволу clipboard", "видимий fallback/повідомлення, без винятку в консолі", [])
ui("overrides", "#overrides-body (поле, «Додати», remove, `?` fieldHelp.overrides)", "HP",
   "додати `qa-ui.test` у blocklist, у allowlist, видалити", "список оновлено, конфлікт показано, файл змінено",
   ["smoke.js:renderOverrides"])
ui("overrides", "#overrides-body", "MF",
   "порожній ввід + Enter; 300 символів; `<img src=x onerror=alert(1)>`; подвійний клік «Додати»",
   "400 показано текстом, HTML не інтерпретується (textContent, CSP), без дубля", [])
ui("overrides", "#overrides-body", "EP", "`persisted:false` (read-only файл)",
   "KNOWN-LIMITATIONS: картка не показує попередження -- already-filed", [], bug="already-filed (KNOWN-LIMITATIONS #overrides-body)")
ui("blocklist", "#blocklist-bundles-body (master, чекбокси джерел, details.bl-sources)", "HP",
   "увімкнути одне джерело, вимкнути", "POST /admin/blocklist-bundles, власний цикл fetch (не 2s-poll)",
   ["blocklist_bundles_card_has_its_own_fetch_render_cycle_off_the_2s_poll", "smoke.js:renderBlocklistBundles"])
ui("blocklist", "#blocklist-bundles-body", "MF", "зняти всі чекбокси при enabled", "явне попередження «лишається чинним» (KNOWN-LIMITATIONS)",
   ["smoke.js:renderBlocklistBundlesInactive"])
ui("log", "#log-body (пошук, decision, voter, Шукати, Оновити, Очистити, деталі рядка, `?` fieldHelp.logFilters)", "HP",
   "кожен фільтр, розгорнути деталі рядка, Очистити", "відповідні запити /admin/log, рендер voters/країни",
   ["smoke.js:buildLogFilterRow+renderLog"])
ui("log-autorefresh", "#log-body автооновлення", "HP", "відкрити сторінку, зробити DoH-запит, чекати 10 с без кліку",
   "T-242: лог НЕ оновлюється сам (очікування користувача -- оновлюється). Відтворити на 0.8.0, "
   "з'ясувати: регресія чи відсутня фіча", [], bug="T-242")
ui("log", "#log-body", "MF", "текст у пошуку + відкрита `?` + розгорнутий рядок під 2s-poll 10 с",
   "нічого не скидається", ["timeout_config_heading_is_never_rebuilt_by_the_2s_status_poll"])
ui("advanced", "#advanced-settings", "HP", "розгорнути/згорнути; reload", "згорнуто за замовчуванням",
   ["advanced_disclosure_is_collapsed_by_default"])
ui("timeout", "#timeout-config-body (3 radio, baseline checkbox, `?` fieldHelp.timeoutMode)", "HP",
   "кожен radio, checkbox, повернути fail_open", "POST /admin/config, файл змінено; `?` не закривається 2s-poll (2756c42)",
   ["timeout_config_heading_is_never_rebuilt_by_the_2s_status_poll", "smoke.js:renderTimeoutConfig"])
ui("providers", "#providers-body (чекбокси, remove custom, форма custom, додати preset, `?` fieldHelp.providers)", "HP",
   "toggle preset, додати/видалити custom `qa-custom`", "відповідні /admin/providers/*; fan-out-лічильник оновлюється",
   ["smoke.js:renderProviders", "main_js_keeps_the_fanout_and_passthrough_notices_in_the_basic_view"])
ui("providers", "форма custom-провайдера", "MF",
   "`http://`, `https://127.0.0.1`, порожні поля, XSS у назві; ввід переживає toggle іншого провайдера і зміну локалі",
   "400 видно; ввід не стирається; T-240 перекладається", ["custom_provider_form_is_retranslated_without_rebuilding_or_touching_value"])
ui("cache", "#cache-config-body (5 полів, Застосувати, `?` fieldHelp.cache)", "HP",
   "змінити max_capacity, Застосувати, повернути", "POST apply, `persisted` показано", ["smoke.js:renderCacheConfig"])
ui("cache", "#cache-config-body", "MF", "від'ємне, порожнє, 1e30, min>max", "400 показано текстом, поле не скинуто", [])
ui("cctld", "#cctld-block-body (combobox, меню, remove, Зберегти, Скасувати, Підтвердити)", "HP",
   "додати `su` через пошук/клавіатуру, Зберегти -> Підтвердити, видалити, Зберегти",
   "армування лише при додаванні коду; POST /admin/cctld-block",
   ["cctld_block_save_arms_only_when_the_picked_set_adds_a_code", "smoke.js:renderCctldBlock"])
ui("cctld", "#cctld-block-body", "MF", "Esc/blur у меню, неіснуючий код `zz`, швидкий подвійний «Підтвердити»",
   "меню закривається, невідомий код не губиться мовчки", ["cctld_block_never_silently_hides_a_code_outside_the_catalogue"])
ui("geoip", "#geoip-body (поле, Додати, remove, армування)", "HP", "додати `KP`, видалити", "POST add/remove, список",
   ["smoke.js:renderGeoip"])
ui("maxmind", "#geoip-maxmind-body (form, Зберегти, Очистити)", "HP", "фейкові креди -> REJECTED -> Очистити",
   "текст `maxmind.check.rejected`, ключ не відображається", ["smoke.js:renderMaxmind"])
ui("rating", "#rating-filter-body (switch, confirm, combobox, підказка регіону, Зберегти)", "HP",
   "прийняти підказку `ua`, увімкнути з підтвердженням, вимкнути",
   "армування на ввімкнення, підказка не автопік, лічильник доменів",
   ["main_js_rating_filter_card_arms_turn_on_and_drives_the_zone_picker_from_the_server",
    "main_js_rating_filter_suggestion_is_a_hint_not_an_auto_pick"])
ui("danger", "#danger-zone-body, #uninstall-local-state-btn, #uninstall-local-state-result", "HP",
   "ЛИШЕ в кінці G, з явним «так»", "двокрокове підтвердження, результат з 5 рядків",
   ["danger_zone_requests_the_tray_removal_and_names_every_consequence", "smoke.js:renderRemoveAllResult"], "USER")
ui("credits", "#credits", "HP", "перевірити посилання й атрибуції", "Apache-2.0, DB-IP/sapics атрибуції, робочі `href`",
   ["index_html_carries_the_required_geoip_data_attributions"])
ui("app-body", "#app-body / консоль / CSP", "SB", "після кожного екрана: консоль і мережа (chrome-devtools)",
   "0 помилок, 0 CSP-порушень, жодних зовнішніх запитів", [])
ui("app-body", "#app-body", "EP", "зупинити сервіс (через watcher-респавн вікно) з відкритою сторінкою",
   "hero SERVICE_UNREACHABLE, картки показують помилку, після відновлення -- самі повертаються", ["smoke.js:errors"])

# ---------------------------------------------------------------- C: tray menu
TRAY_RECIPE = "UI Automation: SetCursorPos на іконку -> Invoke -> Down x N -> Enter"


def tray(const, label, cat, steps, expect, cov=(), who="PART", bug=""):
    R(f"C-{const}-{cat}", "C", f"{const} «{label}»", cat, steps, expect, cov, who, bug)


tray("OPEN_SETTINGS_ID", "Відкрити налаштування", "HP", TRAY_RECIPE,
     "браузер за замовчуванням відкриває `https://127.0.0.1:8443/admin/ui`", ["menu_action_for_maps_each_built_menu_id_to_its_action"])
tray("RESTART_ID", "Скинути кеш і лог", "HP", TRAY_RECIPE + "; потім /admin/log",
     "POST /admin/reset, лог порожній (НЕ рестарт процесу -- ID історичний)")
tray("ABOUT_ID", "Про програму", "HP", TRAY_RECIPE, "діалог з версією 0.8.0 і URL з портом (f166cdd)",
     ["about_dialog_text_includes_the_actual_port"])
tray("SETUP_WIZARD_ID", "Майстер налаштування", "HP", TRAY_RECIPE + "; «Ні»", "діалог майстра, «Ні» нічого не змінює", [], "USER")
tray("INSTALL_CERT_ID", "Встановити сертифікат", "HP", "Так -> (сертифікат уже довірений)",
     "діалог «вже встановлено», без UAC", ["trust_store_outcome_text_never_leaks_the_raw_debug_label"], "USER")
tray("INSTALL_CERT_ID", "Встановити сертифікат", "EP", "Ні", "нічого не змінено", [], "USER")
tray("UNINSTALL_CERT_ID", "Видалити сертифікат", "HP", "ДЕСТРУКТИВНО (правило 5): Так -> перевстановити",
     "cert зник, іконка червона (cert-override), hero CERT_NOT_TRUSTED", [], "USER")
tray("ROTATE_CERT_ID", "Перевипустити сертифікат", "HP", "ДЕСТРУКТИВНО: Так -> рестарт сервісу за PID",
     "новий thumbprint обслуговується після рестарту, старий видалено з Root", [], "USER")
tray("REMOVE_ALL_ID", "Повністю видалити", "HP", "ДЕСТРУКТИВНО, останній крок проходу (T-238 відкладене): Так",
     "звіт з 5 рядків, процеси зупинені, app-data стерто, відкрито ms-settings:appsfeatures",
     ["uninstall_report_has_one_labelled_line_per_artifact", "wipe_script_waits_and_bails_before_it_deletes"], "USER",
     "T-238 (відкладене)")
tray("PAUSE_RESUME_ID", "Призупинити фільтрацію", "HP", TRAY_RECIPE + "; «Так» -- руками користувача (T-238)",
     "`stop.flag` створено, `/admin/status.paused:true`, сервіс живий, іконка сіра, DoH через baseline",
     [], "USER", "T-238 (відкладене)")
tray("PAUSE_RESUME_ID", "Призупинити фільтрацію", "EP", TRAY_RECIPE + "; «Ні»", "`stop.flag` не створено", [], "USER")
R("C-PAUSE_RESUME_ID-resume-HP", "C", "PAUSE_RESUME_ID «Відновити фільтрацію»", "HP", "у стані паузи -> пункт (вже без діалогу)",
     "`stop.flag` видалено, `paused:false`, лог трею `filtering resumed by the user`")
tray("PAUSE_RESUME_ID", "Призупинити фільтрацію", "MF", "пауза -> перезапуск застосунку з плитки",
     "watcher на старті чистить `stop.flag` -> пауза знята (задокументовано)", [], "USER")
tray("PAUSE_RESUME_ID", "Призупинити фільтрацію", "SB", "вдала пауза -> tray.log",
     "смоук v0.7.0 #11: вдала пауза не лишає INFO-рядка (асиметрія з resume) -- перевірити, завести, якщо досі так", [], "AUTO")
tray("RESTORE_SUPERVISION_ID", "Відновити нагляд", "HP", "вбити watcher за PID -> пункт",
     "новий watcher з новим PID", ["live_matching_sibling_is_already_running", "stale_or_recycled_pid_file_means_spawn"])
tray("RETRY_SERVICE_ID", "Спробувати ще раз", "HP", "з GAVE_UP (служба не стартувала) -> пункт",
     "`retry.flag`, watcher скидає бюджет і запускає службу; пункт видно лише коли служба лежить",
     ["menu_action_for_maps_each_built_menu_id_to_its_action",
      "recovery_actions_offer_retry_when_down_and_reset_only_for_a_bad_config"])
tray("RESET_CONFIG_ID", "Скинути налаштування", "HP",
     "лише на копії: старт з битим `resolver_config.toml` (ConfigInvalid) -> пункт -> «Так»",
     "конфіг відсунуто `.orphaned-*`, служба стартує з типовим; пункт видно лише для поганого конфігу",
     ["menu_action_for_maps_each_built_menu_id_to_its_action",
      "recovery_actions_offer_retry_when_down_and_reset_only_for_a_bad_config"])
tray("CLOSE_ID", "Сховати іконку", "HP", TRAY_RECIPE, "трей вийшов, сервіс і watcher живі; повернути -- плитка")
tray("QUIT_APP_ID", "Вийти з DNS Quorum Filter", "HP", "«Так» -- руками, перед G-деінсталяцією",
     "`stop.flag`+`quit.flag`, watcher зупиняє сервіс і виходить, 0 процесів", [], "USER")
tray("QUIT_APP_ID", "Вийти з DNS Quorum Filter", "EP", "«Ні»", "нічого не змінено", [], "USER")
R("C-menu-a11y", "C", "меню трею (#32768 owner-draw)", "SB",
  "UI Automation: перелік пунктів меню", "смоук v0.7.0 #11: пунктів не видно для UIA/Narrator -- знахідка доступності, "
  "перевірити правило 0 і завести", [], "AUTO")

# ---------------------------------------------------------------- D: tray beyond the menu
for st, colour, how in (("Filtering", "green", "звичайний стан"),
                        ("Filtering(degraded all)", "amber", "hosts-хайджек одного voter'а (I-degraded)"),
                        ("Filtering(cert untrusted)", "red", "G: видалити cert"),
                        ("ServiceRestarting", "amber", "F: вбити сервіс за PID"),
                        ("ServiceGaveUp", "red", "CODE-ONLY: 6 вбивств за 600 с -- не робити наживо"),
                        ("Offline", "amber", "I-offline через hosts"),
                        ("Paused", "grey", "C пауза"),
                        ("NoActiveProvider", "grey", "вимкнути всіх провайдерів"),
                        ("Unreachable", "red", "сервіс зупинено і watcher не встигає")):
    R(f"D-icon-{st.split('(')[0]}{'-' + st.split('(')[1].rstrip(')').replace(' ', '-') if '(' in st else ''}", "D",
      f"іконка/tooltip `{st}`", "HP", how, f"колір {colour}, tooltip відповідний (`status::icon_colour`)",
      ["every_tray_status_maps_to_a_colour_when_the_cert_is_trusted", "untrusted_cert_reddens_only_filtering",
       "filtering_icon_is_amber_only_when_every_recent_query_degraded"],
      "CODE" if "GaveUp" in st else "PART")
R("D-tooltip-suffixes", "D", "tooltip-суфікси degraded / рейтинг-фільтр / cert-warning", "HP",
  "UIA-читання tooltip у відповідних станах", "суфікси лише коли застосовні",
  ["tooltip_names_the_rating_filter_bubble_only_when_it_is_actually_gating",
   "compose_tooltip_appends_the_cert_warning_when_it_applies"], "PART")
R("D-onboarding", "D", "майстер першого запуску / `onboarding.seen`", "HP",
  "лише на свіжому інсталі (після «Повністю видалити» + повторний інстал)",
  "пропонується лише на підтверджено недовіреному cert; маркер переживає запуски",
  ["offers_the_wizard_when_the_cert_is_confirmed_untrusted_and_unseen"], "USER")
R("D-browser-nudge", "D", "`browser_nudge` / `nudge_popup` / `browser-nudge.seen`", "HP",
  "CODE-ONLY: 30 хв з 0 запитів на свіжому інсталі", "одноразовий попап; текст лише українською (Батч 5.7)",
  ["offers_the_nudge_once_the_threshold_has_passed_with_zero_queries"], "CODE")
R("D-single-instance", "D", "single-instance guard трею", "MF",
  "запустити `dnsqb-tray.exe` вдруге через `Invoke-CommandInDesktopPackage ... -AppId App` (не напряму -- див. E-*-args-MF)", "другий виходить, одна іконка", ["a_second_same_role_acquire_is_rejected_while_the_first_is_held"])
R("D-i18n", "D", "i18n трею (48 ключів, 37 локалей)", "HP",
  "меню/tooltip/діалоги при uk і en мові ОС", "відповідна мова, fallback на en",
  ["t_falls_back_to_en_then_to_the_bare_key_on_a_miss", "uninstall_report_translates_into_english"], "PART")

# ---------------------------------------------------------------- F: watcher
R("F-start-flags", "F", "старт чистить `stop.flag`/`quit.flag`", "HP",
  "створити `stop.flag` руками -> вийти -> запуск плитки", "обидва прапорці стерто, paused:false",
  ["quit_flag_round_trips_and_the_two_are_independent"], "PART")
R("F-launcher-order", "F", "ідемпотентний лаунчер трей -> сервіс", "HP",
  "`watcher.log` після старту", "`started tray` раніше за `started service`", ["absent_pid_file_means_spawn"])
R("F-second-instance", "F", "другий екземпляр watcher", "MF", "клік плитки при живому застосунку",
  "`a watcher is already running` -> показати трей -> exit(0), процесів не додалось", [])
R("F-channels", "F", "3 канали: pipe, `service.hb`/`watcher.hb`, `/health`", "HP",
  "спостерігати mtime `*.hb` і `watchdog-state.json` 30 с", "оновлюються кожні ~5 с; стан HEALTHY",
  ["observe_passes_the_other_three_channels_through_unchanged"])
R("F-respawn", "F", "респавн убитого сервісу", "CR", "Stop-Process сервісу за PID (з підтвердженням)",
  "стан проходить VERIFYING_PID -> HEALTHY, новий PID за ~30-40 с, `restart_attempts_in_window:1`",
  ["~watchdog::loop_driver::tests"])
R("F-gaveup", "F", "backoff і `GaveUp`", "EP", "CODE-ONLY (5/600 с бюджет)", "GaveUp термінальний, UI показує",
  ["~watchdog::budget::tests", "~watchdog::transition::tests"], "CODE")
for s in ("Healthy", "ChannelDegraded", "SuspectDead", "VerifyingPid", "Restarting", "BackoffWait", "GaveUp"):
    R(f"F-state-{s}", "F", f"WatchdogState::{s} (diagrams/watchdog-state.md)", "HP",
      "спостерігати під час F-respawn" if s not in ("GaveUp",) else "CODE-ONLY",
      "стан досяжний і відображається у `watchdog-state.json`", ["~watchdog::transition::tests"],
      "CODE" if s == "GaveUp" else "PART")
R("F-quit-flag", "F", "реакція на `quit.flag`", "HP", "разом із C-QUIT_APP_ID-HP", "сервіс зупинено, watcher exit(0)", [], "USER")
R("F-service-to-watcher", "F", "service -> watcher напрям", "CR", "вбити watcher за PID, чекати",
  "сервіс логує/діє, але стан не персистить (§7.1 #7, задокументовано)", [], "PART")

# ---------------------------------------------------------------- H: config & state files
CFG = [("port", "u16"), ("timeout_mode", "enum"), ("timeout_ms", "u32"),
       ("serve_baseline_when_filters_unreachable", "bool"), ("persist_query_log", "bool"),
       ("persist_cache", "bool"),
       ("providers.id", "str"), ("providers.enabled", "bool"), ("providers.url", "str"),
       ("providers.display_name", "str"), ("providers.category", "enum"), ("providers.block_signature", "enum"),
       ("cache.clamp_min_secs", "u64"), ("cache.clamp_max_secs", "u64"), ("cache.block_verdict_ttl_secs", "u64"),
       ("cache.stale_grace_secs", "u64"), ("cache.max_capacity", "u64"),
       ("geoip.blocked_countries", "list"), ("rating_filter.enabled", "bool"), ("rating_filter.lists", "list"),
       ("personal_zone.enabled", "bool"), ("personal_zone.frequency_window_days", "u32"),
       ("personal_zone.frequency_top_n", "u32"), ("personal_zone.regularity_window_days", "u32"),
       ("personal_zone.regularity_min_days", "u32"), ("blocklist_bundles.enabled", "bool"),
       ("blocklist_bundles.sources", "list"), ("cctld_block.blocked_codes", "list"),
       ("limits.max_concurrent_connections", "u32"), ("limits.handshake_timeout_ms", "u32"),
       ("limits.idle_timeout_ms", "u32"),
       ("maxmind.account_id", "secret"), ("maxmind.license_key", "secret"),
       ("overrides.allowlist", "list"), ("overrides.blocklist", "list")]
for name, kind in CFG:
    R(f"H-cfg-{name}", "H", f"`{name}` ({kind})", "EP",
      "на КОПІЇ конфігу (відкат прописано): невалідне значення -> ЛИШЕ `/admin/reset` (500, стан не змінено); рестарт сервісу -- лише з валідним граничним значенням (рестарт з невалідним = цикл респавну -> GaveUp, користувач без фільтра)",
      "валідне застосовано; невалідне -- гучна помилка (ConfigError у лозі / 500 на reset), НЕ тихий дефолт "
      "(CONFIGURATION.md)", ["~config::tests"], "CODE" if kind == "secret" else "PART")
R("H-cfg-unknown-key", "H", "невідомий ключ / застарілий `[providers]` формат", "MF",
  "додати `foo = 1` -> ЛИШЕ `/admin/reset`, не рестарт", "гучна помилка (`deny_unknown_fields`), стан не змінено",
  ["serve_admin_reset_returns_500_for_a_malformed_overrides_file_and_leaves_state_untouched"], "PART")
R("H-enc-persist", "H", "`query-log.enc`/`cache.enc`/`zone-removals.enc`/`personal-zone.enc`", "CR",
  "увімкнути persist_* -> рестарт -> лог на місці -> вимкнути", "відновлення працює; ключі в Credential Manager",
  ["~log_persist::tests", "~cache_persist::tests"], "PART")
R("H-logs-privacy", "H", "`logs\\<role>.log` без доменів", "SB",
  "grep трьох логів на тестові домени проходу (`qa-*.test`, `example.*`)", "0 збігів (SPEC «Наскрізні вимоги»)", [], "AUTO")
R("H-appdata-files", "H", "файли app-data (cert.pem, *.pid, *.lock, *.hb, watchdog-state.json, *.seen, "
  "first-seen.stamp, geoip.mmdb, topn/, blocklists/)", "EP",
  "CODE/частково: що буде при зіпсованому/відсутньому/заблокованому файлі", "задокументована поведінка SERVICES.md", [], "CODE")

# ---------------------------------------------------------------- I: end-to-end
R("I-browser-real", "I", "реальна фільтрація через браузер", "HP",
  "користувач вмикає secure DNS -> `https://127.0.0.1:8443/dns-query`; allow/blocklist/ccTLD/бульбашка",
  "`ERR_ADDRESS_INVALID` на заблокованих, рядки в /admin/log", [], "USER", "T-238 (відкладене)")
R("I-offline", "I", "офлайн fast-path (hosts, 9 імен)", "EP", "UAC, відкат прописаний до зміни (плани v0.4.0 сц.22)",
  "network OFFLINE ~10 с, SERVFAIL <50 мс, відновлення без рестарту", [], "USER", "T-238 (відкладене)")
R("I-degraded", "I", "деградація кворуму (hosts, 1 voter)", "EP", "UAC, відкат",
  "кворум відповідає, voter ERROR у лозі", [], "USER", "T-238 (відкладене)")
R("I-passthrough", "I", "pass-through при 0 провайдерів", "HP", "вимкнути всіх -> DoH -> увімкнути",
  "резолвиться через baseline, hero NO_PROVIDERS, не кешується", ["disabling_every_provider_is_pass_through_not_fail_closed"])
R("I-quad9-http-errors", "I", "фонові помилки `quad9 kind=\"http\"` у service.log", "EP",
  "проаналізувати частоту за добу на 0.7.0/0.8.0", "поодинокі -- норма; систематичні -- діагностувати (Lower-layer)", [])

# ---------------------------------------------------------------- G: package lifecycle
R("G-upgrade", "G", "апгрейд 0.7.0 -> 0.8.0 поверх", "HP",
  "Trust-TestCert.ps1 (UAC, через файл-обгортку -- однорядковий RunAs зависав), потім `Add-AppxPackage -Path <msix> -ForceTargetApplicationShutdown` (RUST-GOTCHAS: Windows сам не закриває Desktop Bridge-процеси, без прапорця 0x80073D02); НЕ `Remove-AppxPackage` -- стирає app-data",
  "app-data збережено = знімок P4, onboarding не повторюється, `app_version` 0.8.0", [], "USER")
R("G-startup-state", "G", "`DnsqbWatcherStartup` State одразу після інсталу", "HP",
  "читати реєстр до будь-якого запуску", "State=2 -- гіпотеза (1) T-243", [], "AUTO", "T-243")
R("G-autostart-reboot", "G", "автозапуск після ребуту (T-243)", "HP",
  "ребут, НІЧОГО не запускати руками, перевірити процеси/батька/час", "watcher стартує сам (батько sihost), "
  "потім трей і сервіс", [], "USER", "T-243")
R("G-first-run", "G", "перший запуск після чистого інсталу", "HP", "після REMOVE_ALL + інстал", "майстер онбордингу", [], "USER")
R("G-uninstall", "G", "деінсталяція пакета", "EP", "після REMOVE_ALL",
  "без zombie-процесів (смоук v0.5.0 8b), cert і секрети прибрано", [], "USER")
R("G-direct-remove", "G", "`Remove-AppxPackage` без трею", "MF", "CODE/доки: README застереження",
  "процеси лишаються zombie до ребуту -- задокументовано?", [], "CODE")

# ---------------------------------------------------------------- R13: KNOWN-LIMITATIONS.md, one row each
KL = [
    ("rating-d", "H", "рейтинг-фільтр: лічильник зон per-list, «—» для незавантаженого", "PART"),
    ("rating-e", "B", "немає кнопки очищення персональної зони", "CODE"),
    ("rating-f", "H", "зміна вікна `[personal_zone]` повністю діє лише після рестарту", "CODE"),
    ("enc-log", "H", "query-log.enc: best-effort scrub, <=60 с втрати, orphan `.orphaned-<ts>` накопичуються", "CODE"),
    ("enc-cache", "H", "cache.enc: персиститься лише Allow; apply cache-config -> near-empty cache.enc", "PART"),
    ("fail-closed-cache", "I", "fail_closed timeout-Block кешується в пам'яті на block_verdict_ttl", "CODE"),
    ("proxy-offline", "I", "HTTPS/SVCB/MX/TXT без offline fast-path (таймаут замість миттєвого SERVFAIL)", "USER"),
    ("baseline-geoip", "I", "BASELINE_FALLBACK ALLOW не GeoIP-фільтрується", "CODE"),
    ("markers-config", "H", "reachability-маркери / BASELINE_CHAIN не конфігуруються", "CODE"),
    ("serve-stale", "I", "`should_serve_stale` не підключено (RFC 8767)", "CODE"),
    ("geoip-voters-empty", "A", "GeoIP-блок свіжого ALLOW логує `voters: []`, звужує degraded-вікно", "CODE"),
    ("overrides-persisted", "B", "#overrides-body не показує `persisted:false`", "PART"),
    ("geoip-country-col", "B", "`geoip_country` без колонки в UI логу", "AUTO"),
    ("resolve-precondition", "I", "`quorum::resolve` неперевірена передумова (all-disabled)", "CODE"),
    ("ssrf-literal", "A", "SSRF-перевірка custom URL лише за літеральним хостом", "AUTO"),
    ("log-voter-removed", "A", "`/admin/log?voter=<видалений custom>` -> 400", "AUTO"),
    ("sinkhole-hardcoded", "I", "sinkhole-префікси захардкоджені (sinkhole_probe перед релізом)", "CODE"),
    ("t160-geoip-startup", "F", "T-160: синхронне читання geoip.mmdb на старті", "CODE"),
    ("t169-limits", "H", "T-169: `[limits]` лише після повного рестарту; без окремої стелі кворуму", "CODE"),
    ("maxmind-health-live", "B", "AUTH_REJECTED видно лише після reload/дії", "CODE"),
    ("tls-key-uninstall", "G", "«TLS-ключ не видаляється при деінсталяції» -- а `UninstallLocalStateResponse` вже має "
     "`tls_key`: перевірити, чи пункт застарів (doc-drift)", "CODE"),
    ("fuzz-scope", "A", "fuzz не покриває install-cert/uninstall-local-state і upstream-decode", "CODE"),
    ("status-indicator", "D", "T-56: детекція використання DoH браузером не збудована", "CODE"),
    ("user-country-url", "H", "user-country GeoIP URL без fallback", "CODE"),
    ("blocklist-stale", "A", "`[blocklist_bundles]` enabled + `sources:[]` лишає старий набір чинним", "AUTO"),
    ("blocklist-integrity", "H", "часткова перевірка цілісності 7 джерел (T-233/T-234)", "CODE"),
    ("i18n-machine", "B", "35/37 локалей машинні; RTL без дзеркалення layout", "PART"),
]
for slug, surf, text, who in KL:
    R(f"KL-{slug}", surf, f"KNOWN-LIMITATIONS: {text}", "EP",
      "перевірити, що поводиться як задокументовано (R13)",
      "поведінка = документ; якщо вже не відтворюється -- документ застарів (знахідка)", [], who,
      "already-filed (KNOWN-LIMITATIONS.md)")

# ---------------------------------------------------------------- R11: app-data files, one row each
APPDATA = [
    ("resolver_config.toml", "service (admin-маршрути під persist_lock)", "service (старт, /admin/reset), watcher (`load_port`)",
     "зіпсований -> старт: гучна помилка; reset: 500, стан не змінено; відсутній -> дефолти", "PART"),
    ("overrides.toml", "service (overrides add/remove)", "service (старт, reset)",
     "на 0.7.0 відсутній = порожні списки; зіпсований -> reset 500", "PART"),
    ("cert.pem", "service (`tls`, `cert_rotation`)", "service, tray (trust-watch, thumbprint), watcher (cert-pinned AdminClient)",
     "відсутній/невідповідний ключу -> перегенерація (`CertOrigin::Replaced`), cert-status NOT_TRUSTED до перевстановлення", "CODE"),
    ("geoip.mmdb", "service (`geoip_updater`, атомарна заміна після sha256)", "service",
     "зіпсований -> keep last-known-good / `database_loaded:false`", "CODE"),
    ("query-log.enc", "service (60 с, коли persist_query_log)", "service (старт)", "зіпсований/без ключа -> `.orphaned-<ts>`, порожній лог", "CODE"),
    ("cache.enc", "service (60 с, коли persist_cache)", "service (старт)", "як query-log.enc", "CODE"),
    ("zone-removals.enc", "service (коли rating_filter.enabled)", "service (старт)", "як query-log.enc", "CODE"),
    ("personal-zone.enc", "service (окремий `personal-zone-key`)", "service (старт)", "як query-log.enc", "CODE"),
    ("service.pid / watcher.pid / tray.pid", "кожен процес на старті", "launcher (`ensure_sibling_running`)",
     "застарілий/перевикористаний PID -> spawn (PID + exe identity)", "PART"),
    ("service.lock / watcher.lock / tray.lock", "кожен процес (`share_mode(0)` guard)", "—",
     "заблокований -> другий екземпляр виходить", "PART"),
    ("service.hb / watcher.hb", "service / watcher (кожен тік)", "протилежний процес (канал 2)", "застарілий -> канал мовчить", "AUTO"),
    ("watchdog-state.json", "лише watcher (§7.1 #7)", "tray (`watchdog_override`), service (`read_watchdog_view`)",
     "зіпсований/застарілий -> `None`, без хибної тривоги", "AUTO"),
    ("stop.flag", "tray (пауза)", "service (`pause_watch`, 1 с), watcher (чистить на старті)", "наявність = сигнал, вміст не читається", "PART"),
    ("quit.flag", "tray («Вийти»)", "watcher (кожен тік)", "наявність = сигнал", "USER"),
    ("onboarding.seen", "tray (майстер)", "tray", "наявність блокує лише автооффер", "CODE"),
    ("browser-nudge.seen / first-seen.stamp", "tray", "tray (`browser_nudge`)", "зіпсований stamp -> None, без паніки", "CODE"),
    ("topn/<list>.txt (+.sha256)", "service (`topn_updater`)", "service (старт)", "невідповідний sha256 -> last-known-good", "CODE"),
    ("blocklists/<id>.txt + <id>.count", "service (`blocklist_updater`, після T-233 гейтів)", "service",
     "відхилений цикл -> last-known-good", "CODE"),
    ("logs/<role>.log (+.log.old)", "кожен процес", "людина", "ротація на старті при 5 MiB; без доменів", "AUTO"),
    ("key.pem / geoip_maxmind.toml (legacy)", "—", "service (одноразова міграція в Credential Manager)",
     "key.pem стирається лише після успішного TLS-завантаження", "CODE"),
]
for name, writer, reader, broken, who in APPDATA:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    R(f"H-file-{slug}", "H", f"app-data `{name}`", "EP",
      f"пише: {writer}; читає: {reader}. Спостерегти наявність/оновлення; зіпсований/відсутній -- лише на "
      f"копії або CODE-ONLY (жива інсталяція не псується)",
      broken, [], who)

# ---------------------------------------------------------------- R14: diagram states, one row each
DIAG = [
    ("status-S1", "D", "ui-status-indicator S1: браузер не використовує локальний фільтр", "CODE",
     "не збудовано (T-56/T-134) -- рядок KL-status-indicator"),
    ("status-S2", "D", "ui-status-indicator S2: сервіс перезапускається/зупинено", "PART", "трей ServiceRestarting, hero WATCHDOG_RESTARTING"),
    ("status-S3", "D", "ui-status-indicator S3: немає інтернету", "USER", "трей Offline, hero OFFLINE (I-offline)"),
    ("status-S3a", "D", "ui-status-indicator S3a: призупинено", "USER", "трей Paused, hero PAUSED"),
    ("status-S4", "D", "ui-status-indicator S4: 0 активних провайдерів", "AUTO", "трей NoActiveProvider, hero NO_PROVIDERS"),
    ("status-S5", "D", "ui-status-indicator S5: деградовано", "USER", "amber лише коли деградували всі останні запити"),
    ("status-S6", "D", "ui-status-indicator S6: фільтрація активна", "AUTO", "зелений, PROTECTED"),
    ("onb-yes-ok", "D", "onboarding: «Так» -> install Ok -> mark seen -> /admin/ui", "USER", "cert TRUSTED, маркер, вкладка"),
    ("onb-yes-err", "D", "onboarding: «Так» -> помилка -> DlgErr", "CODE", "діалог помилки, маркер НЕ пишеться"),
    ("onb-no", "D", "onboarding: «Ні»", "USER", "маркер пишеться, повторно не пропонується"),
    ("onb-latch", "D", "onboarding: латч раз на процес / чекати підтвердженого стану", "CODE", "без повтору в межах процесу"),
    ("life-headless", "F", "process-lifecycle: watcher напряму (headless)", "CODE",
     "лише всередині пакета (див. E-*-args-MF) -- інакше небезпечно"),
    ("life-stray-tray", "F", "process-lifecycle: лише трей запущено -> safety-net watcher", "CODE",
     "трей піднімає watcher; поза пакетом не виконувати"),
    ("life-filtering", "F", "process-lifecycle: Filtering", "AUTO", "3 процеси живі"),
    ("life-paused", "F", "process-lifecycle: Paused", "USER", "сервіс живий, stop.flag"),
    ("life-exited", "F", "process-lifecycle: Exited (Вийти)", "USER", "0 процесів"),
    ("life-removed", "F", "process-lifecycle: Removed (Повністю видалити)", "USER", "app-data стерто"),
    ("life-crash", "F", "process-lifecycle: служба крашиться", "PART", "= F-respawn"),
    ("rf-out", "I", "rating-filter: поза зоною -> BLOCK, не кешується", "AUTO", "RATING_FILTER у лозі"),
    ("rf-inz-lists", "I", "rating-filter: у зоні (lists) -> далі конвеєром", "AUTO", "звичайний кворум"),
    ("rf-inz-personal", "I", "rating-filter: у зоні (personal)", "CODE", "потребує навченої зони"),
    ("rf-rm", "I", "rating-filter: exact у зоні + quorum Block -> record_zone_removal", "CODE", "домен прибирається з зони"),
    ("rf-noop", "I", "rating-filter: субдомен у зоні + quorum Block -> нічого", "CODE", "зона не змінюється"),
]
for slug, surf, text, who, expect in DIAG:
    R(f"DIAG-{slug}", surf, f"діаграма: {text}", "HP", "досягти стану (або CODE-ONLY) і звірити з діаграмою",
      expect, [], who)

# ---------------------------------------------------------------- category completion (QA-PROMPT: 4 per point)
# Per-surface scenarios for categories a point has no hand-written row for. Each is a real scenario
# to execute, or an explicit "N/A -- <reason>"; prefixed [шаблон] so it reads as surface-generic.
DEFAULTS = {
    "A": {
        "HP": ("звичайний запит з валідними даними", "200 і задокументоване тіло"),
        "SB": ("той самий запит з `Origin: https://evil.test` і без пінованого cert", "без CORS-заголовків; TLS лише з довіреним cert"),
        "MF": ("невідомі/повторні query-параметри, query 8 КБ", "200/400 детерміновано, параметри ігноруються, без паніки"),
        "EP": ("сервіс у вікні респавну (після F-respawn)", "відмова з'єднання, клієнт бачить помилку, не завис"),
    },
    "B": {
        "HP": ("звичайне використання контролу", "відображає стан сервера"),
        "SB": ("дані сервера з `<img src=x onerror=alert(1)>`/`<script>` (display_name custom-провайдера, домен у лозі) і RTL/емодзі",
               "рендер як текст, 0 CSP-порушень у консолі"),
        "MF": ("подвійний клік, швидке перемикання, порожній/наддовгий ввід, Tab/Enter/Esc", "без дублюючих POST, без зависання, ввід не губиться під 2s-poll"),
        "EP": ("маршрут повертає 400/500 або сервіс недоступний", "видима локалізована помилка, контрол повертається у стан сервера"),
    },
    "C": {
        "HP": ("пункт меню за рецептом трею", "задокументована дія"),
        "SB": ("спостерегти процеси, мережу і tray.log під час дії", "лише задокументована дія, жодних зайвих процесів/запитів"),
        "MF": ("подвійне швидке натискання; повторне відкриття меню під час відкритого діалогу", "одна дія, один діалог"),
        "EP": ("сервіс зупинено (вікно респавну) -> пункт", "зрозуміле повідомлення або тиха відмова, трей не падає"),
    },
    "D": {
        "HP": ("досягти стану", "задокументований колір/текст"),
        "SB": ("стан, коли фільтрація реально не працює", "індикатор НІКОЛИ не показує зелений/«захищено» (false-safe заборонено, Три Б)"),
        "MF": ("швидка зміна станів (пауза -> відновлення за <2 с)", "фінальний колір = фінальний стан, без застряглого кольору (T-191)"),
        "EP": ("`/admin/status` недоступний", "Unreachable/червоний, а не останній відомий зелений"),
    },
    "E": {
        "HP": ("звичайний запуск", "задокументована поведінка"),
        "SB": ("`--help` + аргумент 10 КБ / не-UTF-8 байти", "довідка або ігнор, без паніки"),
        "MF": ("`--HELP`, `-help`, `/h` -- лише всередині пакета (див. E-*-args-MF)", "НЕ довідка -> звичайний старт; зафіксувати"),
        "EP": ("`--help > out.txt`; `--help | Select -First 1` (закритий pipe)", "вивід у файл, без паніки на закритому stdout"),
    },
    "F": {
        "HP": ("спостерігати в нормальній роботі", "задокументована поведінка"),
        "SB": ("CODE-ONLY: підмінений pid-файл на чужий живий процес", "identity-перевірка exe відкидає, не вбиває/не вважає живим чужий"),
        "MF": ("CODE-ONLY: ручне редагування `watchdog-state.json` / видалення `*.hb`", "без паніки; стан самовідновлюється за тік"),
        "EP": ("CODE-ONLY: watcher не може записати state/hb", "warn у watcher.log, цикл триває"),
    },
    "G": {
        "HP": ("звичайний крок життєвого циклу", "задокументовано"),
        "SB": ("інстал без signing cert у `LocalMachine\\TrustedPeople`", "0x800B0109/0x800B010A, нічого не встановлено (T-178)"),
        "MF": ("двічі поспіль `Add-AppxPackage` / клік плитки під час інсталу", "ідемпотентно, без дубля процесів"),
        "EP": ("`Add-AppxPackage` без `-ForceTargetApplicationShutdown` при живих процесах", "0x80073D02, стара версія лишається робочою"),
    },
    "H": {
        "HP": ("валідне значення -> `/admin/reset`", "застосовано, `/admin/status` відображає"),
        "SB": ("граничні: 0, u32/u64 max, від'ємне, файл >64 КБ -> ЛИШЕ `/admin/reset`", "гучна помилка або задокументоване обмеження, без паніки"),
        "MF": ("невірний тип, регістр (`True`), дубль ключа -> ЛИШЕ `/admin/reset`", "500 на reset, стан не змінено"),
        "EP": ("див. рядок EP", ""),
    },
    "I": {
        "HP": ("наскрізний сценарій", "задокументовано"),
        "SB": ("браузер у режимі automatic secure DNS при недоступному локальному DoH", "зафіксувати: тихий fallback повз фільтр (SPEC відкрите питання 10) -- user-safety спостереження"),
        "MF": ("той самий домен у allowlist і blocklist; домен з великої літери/кінцевою крапкою", "allowlist виграє, нормалізація"),
        "EP": ("див. рядок EP / I-offline", ""),
    },
}
NA = {
    # point stem -> {category: reason}
    "B-app-title": {"SB": "N/A -- текст лише з `app_version` сервера, покрито B-app-body-SB",
                    "MF": "N/A -- статичний елемент без вводу", "EP": "N/A -- див. B-app-body-EP"},
    "B-credits": {"SB": "N/A -- статичні посилання, CSP перевіряє B-app-body-SB", "MF": "N/A -- без вводу",
                  "EP": "N/A -- статичний HTML, не залежить від сервера"},
    "B-advanced": {"SB": "N/A -- нативний `<details>` без даних", "EP": "N/A -- без мережі"},
    "C-menu-a11y": {"HP": "N/A -- рядок про доступність, не дію", "MF": "N/A", "EP": "N/A"},
    "C-ABOUT_ID": {"EP": "N/A -- діалог не залежить від сервісу (порт з конфігу)"},
    "C-CLOSE_ID": {"EP": "N/A -- лише вихід процесу трею"},
}
# Wave 12 (2026-10-05): the F template's SB/MF/EP cases do not vary by state, so one
# representative row per case carries the real tests (EXTRA_COV below) and the rest point to it.
_F_SB = "N/A -- pid-ідентичність перевіряється лише у VerifyingPid і лаунчері: див. F-state-VerifyingPid-SB, F-launcher-order-SB"
_F_MF = "N/A -- не залежить від стану: див. F-state-Healthy-MF"
_F_EP = "N/A -- не залежить від стану/точки: див. F-state-Healthy-EP"
for _s in ("Healthy", "ChannelDegraded", "SuspectDead", "VerifyingPid", "Restarting", "BackoffWait", "GaveUp"):
    _na = {}
    if _s != "VerifyingPid":
        _na["SB"] = _F_SB
    if _s != "Healthy":
        _na.update(MF=_F_MF, EP=_F_EP)
    NA[f"F-state-{_s}"] = _na
NA["F-start-flags"] = {"SB": _F_SB, "MF": _F_MF, "EP": _F_EP}
NA["F-launcher-order"] = {"EP": _F_EP}
NA["D-browser-nudge"] = {
    "SB": "N/A -- нудж не є індикатором стану (шаблон D про колір); false-safe -- рядки D-icon-*",
    "MF": "N/A -- одноразовий попап, не колір; латч і маркер -- D-browser-nudge-HP і H-file-browser-nudge-*",
    "EP": "N/A -- без /admin/status нудж не спрацьовує (немає total_queries): does_not_fire_without_total_queries_or_a_first_seen_stamp",
}
_stems = {}
for r in ROWS:
    if re.match(r"(KL-|DIAG-|H-file-|A-routes-unused|A-dto-|A-tls|A-unknown-path)", r["id"]):
        continue
    stem = re.sub(r"-(HP|SB|MF|EP|CR)\d*$", "", r["id"])
    _stems.setdefault(stem, {"cats": set(), "row": r})["cats"].add(r["cat"])
for stem, info in _stems.items():
    base = info["row"]
    for cat in ("HP", "SB", "MF", "EP"):
        if cat in info["cats"]:
            continue
        na = NA.get(stem, {}).get(cat)
        if na:
            R(f"{stem}-{cat}", base["surf"], base["point"], cat, na, "—", [], "CODE")
            continue
        steps, expect = DEFAULTS[base["surf"]][cat]
        if not expect:
            steps, expect = "N/A -- точка сама є error-path сценарієм", "—"
        who = base["who"] if base["who"] != "AUTO" or cat != "SB" or base["surf"] != "F" else "CODE"
        if steps.startswith("CODE-ONLY"):
            who = "CODE"
        R(f"{stem}-{cat}", base["surf"], base["point"], cat, f"[шаблон {base['surf']}] {steps}", expect, [], who)

# Firefox pass (2026-10-04): MCP-launched Firefox with a throwaway geckodriver profile; DoH via
# network.trr.* prefs at runtime. No template rows -- each Firefox row states its own category.
FF = "Firefox (MCP, тимчасовий профіль)"
R("I-firefox-cert", "I", f"{FF}: довіра до leaf-сертифіката", "HP",
  "свіжий профіль, без ручного імпорту -> https://127.0.0.1:<port>/admin/ui",
  "сторінка без попередження (security.enterprise_roots.enabled бере CurrentUser Root)")
R("I-firefox-mode3", "I", f"{FF}: TRR mode 3 («Максимальний захист»)", "HP",
  "trr.mode=3 + uri локального DoH; домен у blocklist і дозволений домен",
  "заблокований -> сторінка помилки, лог BLOCKED; дозволений -> відкривається, лог ALLOWED")
R("I-firefox-mode2-block", "I", f"{FF}: TRR mode 2 («Посилений захист») на блокуванні", "SB",
  "trr.mode=2, служба жива, домен у blocklist",
  "домен лишається заблокованим (передумова SPEC §3.2: на 0.0.0.0 клієнт не ретраїться)")
R("I-firefox-dead-doh", "I", f"{FF}: недоступний локальний DoH", "EP",
  "trr.uri на закритий порт; mode 3 і mode 2",
  "mode 3 -> жорстка відмова; mode 2 -> зафіксувати тихий fallback (SPEC відкрите питання 10)")
R("I-firefox-https-rr", "I", f"{FF}: HTTPS/SVCB pass-through і ECH", "HP",
  "mode 3; HTTPS RR для домену з ECH; сторінка /cdn-cgi/trace того ж домену",
  "HTTPS RR з ech-параметром приходить через локальний DoH; sni=encrypted")
ui("firefox-render", "/admin/ui у Firefox", "HP",
   "відкрити /admin/ui; усі *-body картки; перемкнути мову uk / ar / en",
   "усі картки з контролами без помилок; lang/dir міняються (ar -> rtl)")
ui("browser-setup-firefox", "#browser-setup-body у Firefox", "MF",
   "прочитати інструкцію й крок перевірки для Firefox (UA-детекція, T-189)",
   "кроки ведуть до режиму 3; очікувана ознака блокування відповідає Firefox")

# Other-browser pass (user request 2026-10-04): Edge/Brave/Opera/Vivaldi (Chromium, own settings UI
# and UA) and LibreWolf (hardened Firefox fork -- may not read the Windows Root store, so the cert
# row can legitimately differ from Firefox). Brave and Vivaldi report a plain Chrome UA; Brave is
# still told apart by navigator.brave.
for _key, _name, _url, _ua in (
    ("edge", "Microsoft Edge", "edge://settings/privacy", "edge"),
    ("brave", "Brave", "brave://settings/security", "brave (navigator.brave.isBrave(), main.js)"),
    ("opera", "Opera", "opera://settings", "opera (гілка OPR/)"),
    ("vivaldi", "Vivaldi", "vivaldi://settings/privacy", "chrome (Vivaldi не видає себе в UA)"),
    ("librewolf", "LibreWolf", "about:preferences#privacy", "firefox"),
):
    _B = f"{_name} (справжній профіль користувача)"
    R(f"I-{_key}-cert", "I", f"{_B}: довіра до leaf-сертифіката", "HP",
      "без ручного імпорту -> https://127.0.0.1:<port>/admin/ui",
      "сторінка без попередження (CurrentUser Root; для LibreWolf зафіксувати, чи бере його взагалі)")
    R(f"I-{_key}-secure-dns", "I", f"{_B}: Secure DNS з власним провайдером", "HP",
      f"{_url} -> власний провайдер = локальний DoH; домен у blocklist і дозволений домен",
      "заблокований -> сторінка помилки, лог BLOCKED; дозволений -> відкривається, лог ALLOWED")
    R(f"I-{_key}-block-holds", "I", f"{_B}: блокування не обходиться fallback-ом", "SB",
      "домен у blocklist; перевірити, що браузер не дістає справжню адресу іншим шляхом (аналог T-257)",
      "домен лишається заблокованим, лог BLOCKED для A/AAAA/HTTPS")
    R(f"I-{_key}-dead-doh", "I", f"{_B}: недоступний локальний DoH", "EP",
      "власний провайдер на закритий порт (службу не чіпати)",
      "зафіксувати: жорстка відмова чи тихий fallback (SPEC відкрите питання 10)")
    ui(f"{_key}-render", f"/admin/ui у {_name}", "HP",
       "відкрити /admin/ui; усі *-body картки; перемкнути мову uk / ar / en",
       "усі картки з контролами без помилок; lang/dir міняються (ar -> rtl)")
    ui(f"browser-setup-{_key}", f"#browser-setup-body у {_name}", "MF",
       "прочитати інструкцію й крок перевірки (UA-детекція, T-189)",
       f"детекція = {_ua}; адреса налаштувань відкривається в цьому браузері; ознака блокування відповідає цьому браузеру")

_FF_NA = "N/A -- точка Firefox-проходу перевіряє одну поведінку браузера; інші категорії покривають рядки I-browser-real-*, B-* (Chrome) і A-*"
_ff_done = {}
for _r in list(ROWS):
    if _r["id"].startswith(("I-firefox-", "B-firefox-", "B-browser-setup-firefox",
                            "I-edge-", "B-edge-", "B-browser-setup-edge",
                            "I-brave-", "B-brave-", "B-browser-setup-brave",
                            "I-opera-", "B-opera-", "B-browser-setup-opera",
                            "I-vivaldi-", "B-vivaldi-", "B-browser-setup-vivaldi",
                            "I-librewolf-", "B-librewolf-", "B-browser-setup-librewolf")):
        _ff_done.setdefault(re.sub(r"-(HP|SB|MF|EP)$", "", _r["id"]), (_r, set()))[1].add(_r["cat"])
for _stem, (_r, _cats) in _ff_done.items():
    for _cat in ("HP", "SB", "MF", "EP"):
        if _cat not in _cats:
            R(f"{_stem}-{_cat}", _r["surf"], _r["point"], _cat, _FF_NA, "—", [], "CODE")

# Phase 3a (QA pass): coverage added for behaviour already observed as PASS.
# Selection rule: a test covers only behaviour observed live as PASS and
# reproducible without the installed app, OS dialogs or network. B-overrides-SB
# stays FAIL (T-249, accessible names); the XSS test covers only its PASS half.
# Left uncovered on purpose: FAIL/CODE-ONLY rows (they belong to the fix
# waves in QA-FIX-PLAN.md, regression test first), tray/watcher/browser rows
# (need a desktop session), and config fields outside QA_FIELDS -- provider
# url/display_name/category/block_signature, blocklist_bundles.sources (each
# already has its own validator tests), maxmind.* and overrides.* (other files).
QUERY_ALL = "get_routes_ignore_unknown_repeated_and_oversized_query_strings"
CFG_ALL = "every_config_field_rejects_wrong_type_bad_case_negative_and_duplicate_key"
HELP_LONG = "wants_help_is_unaffected_by_a_10_kb_argument"
XSS_ALL = "~`ui/smoke.js` XSS-прогін (рядки сервера з HTML-ін'єкцією не доходять до HTML-синків)"
CFG_TESTED = {"port", "timeout_mode", "timeout_ms", "serve_baseline_when_filters_unreachable",
              "persist_query_log", "persist_cache", "providers.id", "providers.enabled",
              "cache.clamp_min_secs", "cache.clamp_max_secs", "cache.block_verdict_ttl_secs",
              "cache.stale_grace_secs", "cache.max_capacity", "geoip.blocked_countries",
              "rating_filter.enabled", "rating_filter.lists", "personal_zone.enabled",
              "personal_zone.frequency_window_days", "personal_zone.frequency_top_n",
              "personal_zone.regularity_window_days", "personal_zone.regularity_min_days",
              "blocklist_bundles.enabled", "cctld_block.blocked_codes",
              "limits.max_concurrent_connections", "limits.handshake_timeout_ms",
              "limits.idle_timeout_ms"}
CFG_UNSIGNED = {"port", "timeout_ms", "cache.clamp_min_secs", "cache.clamp_max_secs",
                "cache.block_verdict_ttl_secs", "cache.stale_grace_secs", "cache.max_capacity",
                "personal_zone.frequency_window_days", "personal_zone.frequency_top_n",
                "personal_zone.regularity_window_days", "personal_zone.regularity_min_days",
                "limits.max_concurrent_connections", "limits.handshake_timeout_ms",
                "limits.idle_timeout_ms"}
EXTRA_COV = {f"A-{s}-MF": [QUERY_ALL] for s in (
    "health", "admin-overrides", "admin-cache-config", "admin-geoip", "admin-geoip-maxmind-GET",
    "admin-providers", "admin-cert-status", "admin-ui", "admin-ui-js", "admin-ui-css", "i18n")}
EXTRA_COV.update({f"H-cfg-{f}-MF": [CFG_ALL] for f in CFG_TESTED})
EXTRA_COV.update({f"H-cfg-{f}-SB": [CFG_ALL] for f in CFG_UNSIGNED})
EXTRA_COV.update({f"E-{b}-help-SB": [HELP_LONG] for b in ("service", "tray", "watcher")})
EXTRA_COV.update({f"B-{s}-SB": [XSS_ALL] for s in (
    "overrides", "providers", "log", "maxmind", "geoip", "rating", "blocklist", "timeout")})
# Wave 12 (2026-10-05): CODE-ONLY rows wired to the tests that assert their expectation.
EXTRA_COV.update({
    "F-state-VerifyingPid-SB": ["verifying_pid_routes_on_the_check_result", "live_pid_with_a_foreign_exe_is_a_mismatch"],
    "F-launcher-order-SB": ["stale_or_recycled_pid_file_means_spawn", "live_pid_with_a_foreign_exe_is_a_mismatch"],
    "F-state-Healthy-MF": ["a_corrupt_file_is_invalid_data", "all_channels_signalling_stays_healthy_and_writes_every_tick",
                           "one_silent_channel_degrades_but_never_restarts"],
    "F-launcher-order-MF": ["pid_file_errors_are_returned_not_panicked", "pid_check_that_did_not_run_means_spawn"],
    "F-state-Healthy-EP": ["write_errors_and_leaves_no_temp_file"],
    "H-file-cert-pem": ["cert_origin_is_replaced_when_files_existed_but_load_failed",
                        "server_config_rejects_a_mismatched_cert_and_key_pair",
                        "load_server_config_from_dir_fails_on_corrupt_cert_pem_content"],
    "H-file-geoip-mmdb": ["checksum_matches_sha256_rejects_a_wrong_digest",
                          "persist_atomically_replaces_an_existing_file_and_the_old_reader_stays_usable"],
    "H-file-onboarding-seen": ["a_written_marker_suppresses_the_automatic_offer_and_round_trips"],
    "H-file-browser-nudge-seen-first-seen-stamp": ["first_seen_reads_back_none_for_a_corrupt_stamp_file",
                                                   "browser_nudge_seen_marker_round_trips"],
    "H-file-blocklists-id-txt-id-count": ["write_and_hash_blocking_does_not_poison_an_existing_last_known_good_file",
                                          "write_and_hash_blocking_rejects_a_suspicious_growth_and_never_updates_either_file"],
    "H-file-key-pem-geoip-maxmind-toml-legacy": ["migration_action_moves_only_when_store_empty_and_legacy_present",
                                                 "migration_moves_a_legacy_file_into_the_store_and_erases_it",
                                                 "migration_rejects_an_oversized_legacy_file_and_leaves_it_in_place"],
    "DIAG-rf-inz-personal": ["personal_zone_domain_is_reached_when_topn_zone_misses"],
    "DIAG-rf-rm": ["lazy_hygiene_surfaces_zone_removal_only_for_an_exact_registrable_block",
                   "lazy_hygiene_evicts_a_personal_zone_domain_on_a_fresh_quorum_block"],
    "DIAG-rf-noop": ["lazy_hygiene_surfaces_zone_removal_only_for_an_exact_registrable_block"],
})
EXTRA_COV.update({f"H-file-{f}": ["a_file_without_its_key_is_moved_aside_and_never_overwritten",
                                  "an_undecryptable_file_is_moved_aside_and_never_overwritten"]
                  for f in ("query-log-enc", "cache-enc", "zone-removals-enc", "personal-zone-enc")})
_by_id = {r["id"]: r for r in ROWS}
for _rid, _extra in EXTRA_COV.items():
    _by_id[_rid]["cov"].extend(c for c in _extra if c not in _by_id[_rid]["cov"])

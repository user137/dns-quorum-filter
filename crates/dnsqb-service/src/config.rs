//! Persisted resolver config: port, timeout mode/duration, whether quorum
//! voters are enabled at all (T-144). Mirrors `overrides.rs`'s own load
//! pattern closely (`ResolverConfigFile`/`ConfigError`/`load`).
//!
//! On-disk format is TOML (T-145, superseding T-144's JSON) — chosen over
//! JSON specifically for comment support, closer to the `ssh_config`/`my.cnf`
//! hand-editable style than JSON allows. `ConfigError::Toml` wraps
//! `toml::de::Error` directly (unlike `overrides.rs`'s deliberately
//! payload-less parse-error variant) — `resolver_config.toml` never contains
//! a domain name, so `toml`'s parse errors (which render an annotated
//! snippet of the offending input line, confirmed empirically via a scratch
//! probe) are a genuine UX win here with no privacy cost.
//!
//! Per-provider toggling (T-148) reuses `quorum::EnabledProviders` directly
//! as this struct's `providers` field, rather than a parallel config-only
//! copy — a second type here could drift from what `quorum::resolve`
//! actually honors, the exact footgun T-41's own `Voters` design note
//! originally flagged (a config subset nothing downstream reads). Category
//! toggling (UI-SPEC.md §3.4, beyond the two Phase-1 providers) stays a
//! later-phase gap — this module only persists what `resolve()` can act on
//! today.
//!
//! `save()` (T-52) is this file's first writer — `admin.rs`'s
//! `POST /admin/config` handler calls it to persist a live-applied change.
//! `overrides.toml` (T-37) still has none — no writer and no watcher there
//! yet (T-46/T-47), so *that* sibling file keeps the "load once at startup,
//! no live-reload" precedent this module used to share with it in full.
//!
//! `[geoip]` (T-76, SPEC.md §3.5) is the `GeoIP` blocked-country list —
//! validated (uppercase, two ASCII letters) at load, same "hand-edited file,
//! loud error not a silent no-op" discipline every other field here already
//! has (see [`ConfigError::InvalidCountryCode`]). It's the one field this
//! module persists with no admin-route *editor* yet (T-77) — `dispatch.rs`'s
//! two existing config-writing routes still have to read and echo its
//! current value back on every save, or an unrelated `providers`/`timeout`/
//! cache-config change would silently wipe a hand-edited country list, same
//! cross-field-read requirement `AppState::persist_lock`'s own doc comment
//! already documents for `providers`/`timeout_mode`/`cache`.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::cache::CacheConfig;
use crate::quorum::EnabledProviders;
use crate::timeout::TimeoutMode;

/// Errors loading the resolver config.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to read or write the file (anything other than "file does not
    /// exist" on read — a missing file is `Ok`, see [`ResolverConfig::load`]).
    #[error("failed to read or write resolver config file: {0}")]
    Io(#[source] io::Error),
    /// The file's contents are not valid TOML in the expected shape.
    #[error("failed to parse resolver config TOML: {0}")]
    Toml(#[source] toml::de::Error),
    /// [`ResolverConfig::save`] failed to serialize the config to TOML. Not
    /// expected to ever actually happen for this struct's field types (no
    /// non-representable floats, no map keys), but `toml::to_string` returns
    /// a real `Result`, so this variant exists rather than an `unwrap`
    /// (forbidden, `#![deny(clippy::unwrap_used)]`).
    #[error("failed to serialize resolver config to TOML: {0}")]
    TomlSerialize(#[source] toml::ser::Error),
    /// `port` was `0` — `bind_listener(0)` would bind an OS-chosen ephemeral
    /// port, exactly the silent dynamic-port behavior SPEC.md §1 forbids for
    /// the real listener (Three safety legs, user safety: a browser
    /// re-pointed at a fixed port would silently stop working on the next
    /// restart, with no obvious cause).
    #[error("port must not be 0 - a dynamic port would break manual browser configuration")]
    ZeroPort,
    /// `timeout_ms` was `0` — every voter would time out instantly, so every
    /// query SERVFAILs and filtering silently degrades to "the internet
    /// looks down" with no indication why (Three safety legs, user safety).
    #[error("timeout_ms must not be 0 - every query would time out instantly")]
    ZeroTimeout,
    /// The file exceeds [`MAX_CONFIG_FILE_SIZE`] — rejected before being read
    /// into memory (SPEC.md §8.1: "ліміт розміру, не необмежена алокація"),
    /// not after.
    #[error("resolver config file exceeds the {MAX_CONFIG_FILE_SIZE}-byte size limit")]
    TooLarge,
    /// The `[cache]` table's `clamp_min_secs` exceeds `clamp_max_secs`
    /// (T-153) — rejected at load, same as `ZeroPort`/`ZeroTimeout` above,
    /// rather than constructing a `CacheConfig` that would later make
    /// `cache::clamp_ttl`'s own `Ord`-based clamp panic on every query. See
    /// `cache::CacheConfig::from_secs`, the single validated path this and
    /// the admin-channel write handler both go through.
    #[error("cache config clamp_min_secs must not exceed clamp_max_secs")]
    CacheClampMinExceedsMax,
    /// The `[geoip]` table's `blocked_countries` contains an entry that
    /// isn't exactly two ASCII letters (T-76) — rejected at load rather than
    /// silently stored and matching nothing: `"RUS"` or `"Ukraine"` would
    /// never equal any `GeoipReader::country` result (SPEC.md §3.5's country
    /// codes are ISO 3166-1 alpha-2), leaving the operator believing
    /// filtering is active for a country it can never actually match — the
    /// same "hand-edited file, loud error not a silent no-op" discipline
    /// `ZeroPort`/`ZeroTimeout` already apply. The code itself, not a
    /// domain name, so a payload here carries no "no domain names in
    /// service logs" risk (same reasoning `ConfigError::Toml`'s own doc
    /// comment already states for this file).
    #[error("blocked country code {0:?} is not a valid two-letter ISO 3166-1 alpha-2 code")]
    InvalidCountryCode(String),
}

/// Upper bound on `resolver_config.toml`'s on-disk size, checked in
/// [`ResolverConfig::load`] before any of it is read into memory — reachable
/// live via `POST /admin/reset` (T-149), not just at startup. A separate,
/// much smaller constant than `overrides::MAX_OVERRIDES_FILE_SIZE`
/// deliberately, not a shared one — this file holds a handful of scalar
/// fields plus two small nested tables (`[providers]`, T-148; `[cache]`,
/// T-153), not an open-ended domain list, so 64 KiB (the same order of
/// magnitude as `dispatch::MAX_MESSAGE_SIZE`) is already generous for even a
/// heavily hand-commented file.
pub(crate) const MAX_CONFIG_FILE_SIZE: u64 = 64 * 1024;

/// The `[geoip]` table's live-relevant contents (T-76 — SPEC.md §3.5):
/// which countries a resolved IP must never match. `Vec<String>`, not
/// `Copy` (unlike `EnabledProviders`/`CacheConfig`) — that's why
/// [`ResolverConfig`] itself lost its own `Copy` derive at this task; see
/// that type's own doc comment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeoipConfig {
    /// Already-validated, uppercased two-letter ISO 3166-1 alpha-2 codes
    /// (see [`ConfigError::InvalidCountryCode`]) — empty by default, SPEC.md
    /// §3.5's own stated default: an opt-in list, not a default policy.
    pub blocked_countries: Vec<String>,
}

/// Resolver config, loaded once at startup (T-144). No longer `Copy` as of
/// T-76 — `geoip.blocked_countries` is a `Vec<String>`, so this type is
/// `Clone` only now (every other field stays individually `Copy`, so a
/// caller that only reads e.g. `.port`/`.providers` is unaffected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverConfig {
    /// The local `DoH` listener's port (SPEC.md §1: fixed-by-default,
    /// configurable, never a silent fallback on conflict). `0` is rejected
    /// ([`ConfigError::ZeroPort`]), but a privileged port (1-1023) is
    /// deliberately **not** rejected here — on Windows, binding one without
    /// elevation fails loudly via `BindError::Other` (not silently), which
    /// satisfies SPEC.md §1's "explicit error" requirement even though the
    /// error message itself won't say "this port needs admin." Fine for a
    /// hand-edited file; revisit when T-53 exposes `set_doh_port(port)` from
    /// the UI, where a bare bind failure is a worse user-facing message than
    /// catching the privileged-port case explicitly here.
    pub port: u16,
    /// How an unresponsive voter is interpreted (SPEC.md §3.3).
    pub timeout_mode: TimeoutMode,
    /// Per-query timeout, in milliseconds.
    pub timeout_ms: u32,
    /// Which quorum providers are enabled (T-148) — [`EnabledProviders::
    /// any_enabled`] being `false` is SPEC.md §3/§8.1's explicit
    /// pass-through case, not fail-closed and not a silent no-op.
    pub providers: EnabledProviders,
    /// Cache TTL clamps/capacity (T-153) — reuses `cache::CacheConfig`
    /// directly rather than a parallel config-only copy, same reasoning
    /// already established for `providers` above: a second type here could
    /// drift from what `cache::clamp_ttl`/`Cache::new` actually honor.
    pub cache: CacheConfig,
    /// `GeoIP` blocked-country list (T-76, SPEC.md §3.5).
    pub geoip: GeoipConfig,
}

impl Default for ResolverConfig {
    /// The MVP defaults `main.rs` hardcoded before T-144.
    fn default() -> Self {
        Self {
            port: 8443,
            timeout_mode: TimeoutMode::FailOpen,
            timeout_ms: 2000,
            providers: EnabledProviders::default(),
            cache: CacheConfig::default(),
            geoip: GeoipConfig::default(),
        }
    }
}

impl ResolverConfig {
    /// Loads the resolver config from `path`. A missing file is `Ok` with
    /// [`ResolverConfig::default`] — same "no file yet" tolerance
    /// `overrides::OverrideLists::load` already has. A present-but-malformed
    /// file is always `Err`, never a silent fallback to defaults: an
    /// operator who hand-edited the file and made a mistake should see an
    /// error, not have their edit silently discarded. A field absent from
    /// otherwise-valid TOML defaults to the MVP value for just that field
    /// (`ResolverConfigFile`'s own `#[serde(default)]`); an unknown key is
    /// rejected outright (`#[serde(deny_unknown_fields)]`), the same
    /// "graceful partial, loud typo" split `overrides.rs` already
    /// established.
    ///
    /// This does blocking file I/O — call at startup, not from a per-query
    /// hot path.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] for a read failure other than "file not
    /// found", [`ConfigError::TooLarge`] if the file exceeds
    /// [`MAX_CONFIG_FILE_SIZE`], [`ConfigError::Toml`] if the file's TOML
    /// doesn't match the expected shape, [`ConfigError::ZeroPort`] if `port`
    /// is `0`, or [`ConfigError::ZeroTimeout`] if `timeout_ms` is `0`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let mut handle = match File::open(path) {
            Ok(handle) => handle,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => return Err(ConfigError::Io(err)),
        };
        // Bounded read, not metadata-then-read - see overrides::OverrideLists
        // ::load's own comment for why a size check has to be enforced by
        // the call that actually allocates, not measured by a separate one.
        let mut raw = String::new();
        let read = handle
            .by_ref()
            .take(MAX_CONFIG_FILE_SIZE + 1)
            .read_to_string(&mut raw)
            .map_err(ConfigError::Io)?;
        if u64::try_from(read).unwrap_or(u64::MAX) > MAX_CONFIG_FILE_SIZE {
            return Err(ConfigError::TooLarge);
        }
        let file: ResolverConfigFile = toml::from_str(&raw).map_err(ConfigError::Toml)?;

        if file.port == 0 {
            return Err(ConfigError::ZeroPort);
        }
        if file.timeout_ms == 0 {
            return Err(ConfigError::ZeroTimeout);
        }
        let cache = match CacheConfig::from_secs(
            file.cache.clamp_min_secs,
            file.cache.clamp_max_secs,
            file.cache.block_verdict_ttl_secs,
            file.cache.stale_grace_secs,
            file.cache.max_capacity,
        ) {
            Ok(cache) => cache,
            Err(crate::cache::CacheConfigError::ClampMinExceedsMax) => {
                return Err(ConfigError::CacheClampMinExceedsMax)
            }
        };
        let mut blocked_countries = Vec::with_capacity(file.geoip.blocked_countries.len());
        for raw in &file.geoip.blocked_countries {
            blocked_countries.push(validate_country_code(raw)?);
        }

        Ok(Self {
            port: file.port,
            timeout_mode: file.timeout_mode,
            timeout_ms: file.timeout_ms,
            providers: file.providers,
            cache,
            geoip: GeoipConfig { blocked_countries },
        })
    }

    /// Persists this config to `path` as TOML (T-52 — the admin channel's
    /// `POST /admin/config` is the first writer this file has ever had).
    ///
    /// **Overwrites the whole file from struct fields** — any hand-written
    /// comments or formatting the operator added are lost. T-145 chose TOML
    /// specifically for comment support (DECISIONS.md); a format-preserving
    /// edit would avoid this, but is over-engineering for two booleans and
    /// an enum at this project's current scope. `CONFIGURATION.md` carries
    /// an explicit warning about this — a stated tradeoff, not a silent one.
    ///
    /// This does blocking file I/O — call from a place that's already
    /// accepted that cost (T-52's admin handler), not a per-query hot path.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::TomlSerialize`] if serialization fails (not
    /// expected for this struct's field types) or [`ConfigError::Io`] if the
    /// write itself fails.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let cache_secs = self.cache.to_secs();
        let file = ResolverConfigFile {
            port: self.port,
            timeout_mode: self.timeout_mode,
            timeout_ms: self.timeout_ms,
            providers: self.providers,
            cache: CacheConfigFile {
                clamp_min_secs: cache_secs.clamp_min_secs,
                clamp_max_secs: cache_secs.clamp_max_secs,
                block_verdict_ttl_secs: cache_secs.block_verdict_ttl_secs,
                stale_grace_secs: cache_secs.stale_grace_secs,
                max_capacity: cache_secs.max_capacity,
            },
            geoip: GeoipConfigFile {
                blocked_countries: self.geoip.blocked_countries.clone(),
            },
        };
        let toml = toml::to_string(&file).map_err(ConfigError::TomlSerialize)?;
        fs::write(path, toml).map_err(ConfigError::Io)
    }
}

/// Validates and uppercases one `[geoip] blocked_countries` entry (T-76) —
/// see [`ConfigError::InvalidCountryCode`]'s own doc comment for why this is
/// a load-time rejection, not a silent pass-through.
fn validate_country_code(raw: &str) -> Result<String, ConfigError> {
    if raw.len() == 2 && raw.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        Ok(raw.to_ascii_uppercase())
    } else {
        Err(ConfigError::InvalidCountryCode(raw.to_string()))
    }
}

/// On-disk shape — a plain, hand-editable TOML table (same spirit as
/// `overrides.rs`'s own `OverrideListsFile`). Struct-level `#[serde(default)]`
/// (backed by `impl Default` below, mirroring [`ResolverConfig::default`])
/// fills any field absent from a partial file; `deny_unknown_fields` still
/// rejects a typo'd key (`"potr"`, `"timeoutMs"`, ...) loudly rather than
/// silently ignoring it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ResolverConfigFile {
    port: u16,
    timeout_mode: TimeoutMode,
    timeout_ms: u32,
    providers: EnabledProviders,
    cache: CacheConfigFile,
    geoip: GeoipConfigFile,
}

impl Default for ResolverConfigFile {
    fn default() -> Self {
        let defaults = ResolverConfig::default();
        let cache_secs = defaults.cache.to_secs();
        Self {
            port: defaults.port,
            timeout_mode: defaults.timeout_mode,
            timeout_ms: defaults.timeout_ms,
            providers: defaults.providers,
            cache: CacheConfigFile {
                clamp_min_secs: cache_secs.clamp_min_secs,
                clamp_max_secs: cache_secs.clamp_max_secs,
                block_verdict_ttl_secs: cache_secs.block_verdict_ttl_secs,
                stale_grace_secs: cache_secs.stale_grace_secs,
                max_capacity: cache_secs.max_capacity,
            },
            geoip: GeoipConfigFile {
                blocked_countries: defaults.geoip.blocked_countries,
            },
        }
    }
}

/// TOML-facing shape for [`GeoipConfig`] (T-76) — a plain, hand-editable
/// `[geoip]` table, same "graceful partial, loud typo" split every other
/// nested table in this file already established. Country-code validation
/// itself happens in [`ResolverConfig::load`] (via [`validate_country_code`]),
/// not here — this struct only has to round-trip the raw strings; the load
/// path is the one place `serde`'s own error type is already the wrong shape
/// to carry a per-entry validation failure cleanly.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
struct GeoipConfigFile {
    blocked_countries: Vec<String>,
}

/// TOML-facing shape for `cache::CacheConfig` (T-153) — seconds as `u64`,
/// mirroring how `ResolverConfigFile.timeout_ms` is a plain integer while the
/// live `TimeoutConfig` holds a real `Duration`. `CacheConfig` itself stays
/// serde-free; [`CacheConfig::from_secs`]/[`CacheConfig::to_secs`] are the
/// only conversion between the two.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
struct CacheConfigFile {
    clamp_min_secs: u64,
    clamp_max_secs: u64,
    block_verdict_ttl_secs: u64,
    stale_grace_secs: u64,
    max_capacity: u64,
}

impl Default for CacheConfigFile {
    fn default() -> Self {
        let secs = CacheConfig::default().to_secs();
        Self {
            clamp_min_secs: secs.clamp_min_secs,
            clamp_max_secs: secs.clamp_max_secs,
            block_verdict_ttl_secs: secs.block_verdict_ttl_secs,
            stale_grace_secs: secs.stale_grace_secs,
            max_capacity: secs.max_capacity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CacheConfig, ConfigError, GeoipConfig, ResolverConfig};
    use crate::quorum::EnabledProviders;
    use crate::timeout::TimeoutMode;
    use std::fs;

    fn temp_config_path() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        };
        let path = dir.path().join("resolver_config.toml");
        (dir, path)
    }

    #[test]
    fn load_of_missing_file_returns_defaults_not_an_error() {
        let (_dir, path) = temp_config_path();
        let config = match ResolverConfig::load(&path) {
            Ok(config) => config,
            Err(err) => panic!("a missing file must not be an error: {err}"),
        };
        assert_eq!(config, ResolverConfig::default());
    }

    #[test]
    fn load_of_a_fully_specified_file_returns_exactly_those_values() {
        let (_dir, path) = temp_config_path();
        let toml = "port = 9000\ntimeout_mode = \"fail_closed\"\ntimeout_ms = 5000\n\n[providers]\nquad9 = false\nadguard = false\n";
        if let Err(err) = fs::write(&path, toml) {
            panic!("must be able to write the fixture file: {err}");
        }
        let config = match ResolverConfig::load(&path) {
            Ok(config) => config,
            Err(err) => panic!("a valid file must load: {err}"),
        };
        assert_eq!(
            config,
            ResolverConfig {
                port: 9000,
                timeout_mode: TimeoutMode::FailClosed,
                timeout_ms: 5000,
                providers: EnabledProviders {
                    quad9: false,
                    adguard: false,
                },
                cache: CacheConfig::default(),
                geoip: GeoipConfig::default(),
            }
        );
    }

    // T-148: EnabledProviders is a nested TOML table, not a flat field -
    // confirmed empirically (not assumed) that struct-level
    // #[serde(default, deny_unknown_fields)] composes the same way one level
    // deep inside a [providers] table as it does at the top level of the
    // file (CLAUDE.md's own T-144 gotcha only verified the top-level case).

    #[test]
    fn load_of_a_partial_providers_table_fills_the_other_provider_from_default() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(&path, "[providers]\nquad9 = false\n") {
            panic!("must be able to write the fixture file: {err}");
        }
        let config = match ResolverConfig::load(&path) {
            Ok(config) => config,
            Err(err) => panic!("a partial [providers] table must still load: {err}"),
        };
        assert_eq!(
            config.providers,
            EnabledProviders {
                quad9: false,
                adguard: true,
            }
        );
    }

    #[test]
    fn load_rejects_a_misspelled_key_inside_the_providers_table() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(&path, "[providers]\nadgaurd = false\n") {
            panic!("must be able to write the fixture file: {err}");
        }
        assert!(matches!(
            ResolverConfig::load(&path),
            Err(ConfigError::Toml(_))
        ));
    }

    // T-148: hard cutover, no dual-field migration shim - an old file still
    // using the pre-T-148 flat `voters_enabled` key is now a loud parse
    // error, not silently accepted (same "malformed file is fatal" rule
    // this file already applies to every other unknown key).
    #[test]
    fn load_rejects_the_old_flat_voters_enabled_key_as_unknown() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(&path, "voters_enabled = false\n") {
            panic!("must be able to write the fixture file: {err}");
        }
        assert!(matches!(
            ResolverConfig::load(&path),
            Err(ConfigError::Toml(_))
        ));
    }

    #[test]
    fn load_of_a_partial_file_fills_the_rest_from_defaults() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(&path, "port = 9000\n") {
            panic!("must be able to write the fixture file: {err}");
        }
        let config = match ResolverConfig::load(&path) {
            Ok(config) => config,
            Err(err) => panic!("a partial file must still load: {err}"),
        };
        assert_eq!(
            config,
            ResolverConfig {
                port: 9000,
                ..ResolverConfig::default()
            }
        );
    }

    #[test]
    fn load_rejects_a_misspelled_key_instead_of_silently_ignoring_it() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(&path, "potr = 9000\n") {
            panic!("must be able to write the fixture file: {err}");
        }
        assert!(matches!(
            ResolverConfig::load(&path),
            Err(ConfigError::Toml(_))
        ));
    }

    #[test]
    fn load_rejects_structurally_invalid_toml() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(&path, "not valid toml ===") {
            panic!("must be able to write the fixture file: {err}");
        }
        assert!(matches!(
            ResolverConfig::load(&path),
            Err(ConfigError::Toml(_))
        ));
    }

    #[test]
    fn load_rejects_a_file_one_byte_over_the_size_limit() {
        let (_dir, path) = temp_config_path();
        let oversized =
            "#".repeat(usize::try_from(super::MAX_CONFIG_FILE_SIZE + 1).unwrap_or(usize::MAX));
        if let Err(err) = fs::write(&path, oversized) {
            panic!("must be able to write the fixture file: {err}");
        }
        assert!(matches!(
            ResolverConfig::load(&path),
            Err(ConfigError::TooLarge)
        ));
    }

    #[test]
    fn load_accepts_a_file_exactly_at_the_size_limit() {
        let (_dir, path) = temp_config_path();
        let body = "port = 9000\n";
        let padding = "#".repeat(
            usize::try_from(super::MAX_CONFIG_FILE_SIZE).unwrap_or(usize::MAX) - body.len(),
        );
        if let Err(err) = fs::write(&path, format!("{body}{padding}")) {
            panic!("must be able to write the fixture file: {err}");
        }
        match ResolverConfig::load(&path) {
            Ok(config) => assert_eq!(config.port, 9000),
            Err(err) => panic!("a file exactly at the size limit must still load: {err}"),
        }
    }

    #[test]
    fn load_rejects_a_zero_port() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(&path, "port = 0\n") {
            panic!("must be able to write the fixture file: {err}");
        }
        assert!(matches!(
            ResolverConfig::load(&path),
            Err(ConfigError::ZeroPort)
        ));
    }

    #[test]
    fn save_then_load_round_trips_a_non_default_config() {
        let (_dir, path) = temp_config_path();
        let cache = match CacheConfig::from_secs(60, 7200, 7200, 172_800, 20_000) {
            Ok(cache) => cache,
            Err(err) => panic!("valid input must not be rejected: {err}"),
        };
        let config = ResolverConfig {
            port: 9443,
            timeout_mode: TimeoutMode::FailClosed,
            timeout_ms: 3500,
            providers: EnabledProviders {
                quad9: false,
                adguard: true,
            },
            cache,
            geoip: GeoipConfig {
                blocked_countries: vec!["SE".to_string(), "DE".to_string()],
            },
        };
        if let Err(err) = config.save(&path) {
            panic!("must be able to save: {err}");
        }
        let loaded = match ResolverConfig::load(&path) {
            Ok(loaded) => loaded,
            Err(err) => panic!("must be able to load what was just saved: {err}"),
        };
        assert_eq!(loaded, config);
    }

    #[test]
    fn save_overwrites_a_preexisting_file_entirely() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(
            &path,
            "port = 1\ntimeout_mode = \"fail_open\"\ntimeout_ms = 1\n",
        ) {
            panic!("must be able to write the fixture file: {err}");
        }
        let config = ResolverConfig::default();
        if let Err(err) = config.save(&path) {
            panic!("must be able to save: {err}");
        }
        let loaded = match ResolverConfig::load(&path) {
            Ok(loaded) => loaded,
            Err(err) => panic!("must be able to load what was just saved: {err}"),
        };
        assert_eq!(loaded, config);
    }

    #[test]
    fn load_rejects_a_zero_timeout() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(&path, "timeout_ms = 0\n") {
            panic!("must be able to write the fixture file: {err}");
        }
        assert!(matches!(
            ResolverConfig::load(&path),
            Err(ConfigError::ZeroTimeout)
        ));
    }

    // T-76: [geoip] - default empty (SPEC.md §3.5's own stated default: an
    // opt-in list, not a default policy), entries normalized to uppercase,
    // a malformed code is a loud load-time error, not silently stored to
    // match nothing.

    #[test]
    fn load_of_a_missing_geoip_table_defaults_to_an_empty_blocked_list() {
        let (_dir, path) = temp_config_path();
        let config = match ResolverConfig::load(&path) {
            Ok(config) => config,
            Err(err) => panic!("a missing file must still load: {err}"),
        };
        assert_eq!(config.geoip, GeoipConfig::default());
        assert!(config.geoip.blocked_countries.is_empty());
    }

    #[test]
    fn load_of_a_geoip_table_normalizes_country_codes_to_uppercase() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(&path, "[geoip]\nblocked_countries = [\"se\", \"De\"]\n") {
            panic!("must be able to write the fixture file: {err}");
        }
        let config = match ResolverConfig::load(&path) {
            Ok(config) => config,
            Err(err) => panic!("a valid [geoip] table must load: {err}"),
        };
        assert_eq!(
            config.geoip.blocked_countries,
            vec!["SE".to_string(), "DE".to_string()]
        );
    }

    #[test]
    fn load_rejects_a_three_letter_country_code() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(&path, "[geoip]\nblocked_countries = [\"RUS\"]\n") {
            panic!("must be able to write the fixture file: {err}");
        }
        assert!(matches!(
            ResolverConfig::load(&path),
            Err(ConfigError::InvalidCountryCode(code)) if code == "RUS"
        ));
    }

    #[test]
    fn load_rejects_a_non_alphabetic_country_code() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(&path, "[geoip]\nblocked_countries = [\"1U\"]\n") {
            panic!("must be able to write the fixture file: {err}");
        }
        assert!(matches!(
            ResolverConfig::load(&path),
            Err(ConfigError::InvalidCountryCode(_))
        ));
    }

    #[test]
    fn load_rejects_a_misspelled_key_inside_the_geoip_table() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(&path, "[geoip]\nblcoked_countries = [\"SE\"]\n") {
            panic!("must be able to write the fixture file: {err}");
        }
        assert!(matches!(
            ResolverConfig::load(&path),
            Err(ConfigError::Toml(_))
        ));
    }

    // T-153: [cache] follows the same nested-table conventions [providers]
    // already established (T-148) - partial table fills the rest from
    // default, typo'd key is a loud error, not silently ignored.

    #[test]
    fn load_of_a_partial_cache_table_fills_the_rest_from_default() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(&path, "[cache]\nmax_capacity = 500\n") {
            panic!("must be able to write the fixture file: {err}");
        }
        let config = match ResolverConfig::load(&path) {
            Ok(config) => config,
            Err(err) => panic!("a partial [cache] table must still load: {err}"),
        };
        let defaults = CacheConfig::default().to_secs();
        let secs = config.cache.to_secs();
        assert_eq!(secs.max_capacity, 500);
        assert_eq!(secs.clamp_min_secs, defaults.clamp_min_secs);
        assert_eq!(secs.clamp_max_secs, defaults.clamp_max_secs);
    }

    #[test]
    fn load_rejects_a_misspelled_key_inside_the_cache_table() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(&path, "[cache]\nclmap_min_secs = 60\n") {
            panic!("must be able to write the fixture file: {err}");
        }
        assert!(matches!(
            ResolverConfig::load(&path),
            Err(ConfigError::Toml(_))
        ));
    }

    #[test]
    fn load_rejects_a_cache_clamp_min_exceeding_clamp_max() {
        let (_dir, path) = temp_config_path();
        if let Err(err) = fs::write(
            &path,
            "[cache]\nclamp_min_secs = 100\nclamp_max_secs = 10\n",
        ) {
            panic!("must be able to write the fixture file: {err}");
        }
        assert!(matches!(
            ResolverConfig::load(&path),
            Err(ConfigError::CacheClampMinExceedsMax)
        ));
    }

    #[test]
    fn save_then_load_round_trips_a_non_default_cache_config() {
        let (_dir, path) = temp_config_path();
        let cache = match CacheConfig::from_secs(45, 1800, 1800, 43_200, 2_500) {
            Ok(cache) => cache,
            Err(err) => panic!("valid input must not be rejected: {err}"),
        };
        let config = ResolverConfig {
            cache,
            ..ResolverConfig::default()
        };
        if let Err(err) = config.save(&path) {
            panic!("must be able to save: {err}");
        }
        let loaded = match ResolverConfig::load(&path) {
            Ok(loaded) => loaded,
            Err(err) => panic!("must be able to load what was just saved: {err}"),
        };
        assert_eq!(loaded, config);
    }
}

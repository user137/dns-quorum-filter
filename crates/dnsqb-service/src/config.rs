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

use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

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
}

/// Resolver config, loaded once at startup (T-144). `Copy` — small and
/// value-like, same as [`crate::CacheConfig`]/[`crate::TimeoutConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

impl Default for ResolverConfig {
    /// The MVP defaults `main.rs` hardcoded before T-144.
    fn default() -> Self {
        Self {
            port: 8443,
            timeout_mode: TimeoutMode::FailOpen,
            timeout_ms: 2000,
            providers: EnabledProviders::default(),
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
    /// found", [`ConfigError::Toml`] if the file's TOML doesn't match the
    /// expected shape, [`ConfigError::ZeroPort`] if `port` is `0`, or
    /// [`ConfigError::ZeroTimeout`] if `timeout_ms` is `0`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = match fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => return Err(ConfigError::Io(err)),
        };
        let file: ResolverConfigFile = toml::from_str(&raw).map_err(ConfigError::Toml)?;

        if file.port == 0 {
            return Err(ConfigError::ZeroPort);
        }
        if file.timeout_ms == 0 {
            return Err(ConfigError::ZeroTimeout);
        }

        Ok(Self {
            port: file.port,
            timeout_mode: file.timeout_mode,
            timeout_ms: file.timeout_ms,
            providers: file.providers,
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
        let file = ResolverConfigFile {
            port: self.port,
            timeout_mode: self.timeout_mode,
            timeout_ms: self.timeout_ms,
            providers: self.providers,
        };
        let toml = toml::to_string(&file).map_err(ConfigError::TomlSerialize)?;
        fs::write(path, toml).map_err(ConfigError::Io)
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
}

impl Default for ResolverConfigFile {
    fn default() -> Self {
        let defaults = ResolverConfig::default();
        Self {
            port: defaults.port,
            timeout_mode: defaults.timeout_mode,
            timeout_ms: defaults.timeout_ms,
            providers: defaults.providers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigError, ResolverConfig};
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
        let config = ResolverConfig {
            port: 9443,
            timeout_mode: TimeoutMode::FailClosed,
            timeout_ms: 3500,
            providers: EnabledProviders {
                quad9: false,
                adguard: true,
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
}

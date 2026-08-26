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
//! Deliberately **not** a per-provider/category config — `quorum::resolve`
//! hardcodes querying both `Provider::Quad9` and `Provider::AdGuard`
//! unconditionally, with no parameter anywhere for "which providers to
//! query." Persisting a per-provider toggle the resolver can't yet act on
//! would be the same footgun T-41's own `Voters` design note already
//! flagged (a config subset that isn't honored downstream) — so this module
//! persists only the one toggle already wired end to end since T-41,
//! `voters_enabled`. Per-provider/category toggling (UI-SPEC.md §3.4) stays
//! an open gap for whoever scopes T-52's config surface for real.
//!
//! No `save()` either — same "no file-write path yet" precedent as
//! `overrides.rs` before T-46/T-47's UI writer existed. No live-reload:
//! `overrides.json` (T-37) already only loads once at `main.rs` startup with
//! no writer and no watcher, and this file follows the same precedent, not a
//! stronger guarantee than its sibling config file already has.

use std::fs;
use std::io;
use std::path::Path;

use serde::Deserialize;

use crate::timeout::TimeoutMode;

/// Errors loading the resolver config.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to read the file (anything other than "file does not exist" —
    /// a missing file is `Ok`, see [`ResolverConfig::load`]).
    #[error("failed to read resolver config file: {0}")]
    Io(#[source] io::Error),
    /// The file's contents are not valid TOML in the expected shape.
    #[error("failed to parse resolver config TOML: {0}")]
    Toml(#[source] toml::de::Error),
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
    /// Whether quorum voters are enabled at all — `false` is SPEC.md §3/
    /// §8.1's explicit pass-through case ([`crate::Voters::Disabled`]), not
    /// fail-closed and not a silent no-op.
    pub voters_enabled: bool,
}

impl Default for ResolverConfig {
    /// The MVP defaults `main.rs` hardcoded before T-144.
    fn default() -> Self {
        Self {
            port: 8443,
            timeout_mode: TimeoutMode::FailOpen,
            timeout_ms: 2000,
            voters_enabled: true,
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
            voters_enabled: file.voters_enabled,
        })
    }
}

/// On-disk shape — a plain, hand-editable TOML table (same spirit as
/// `overrides.rs`'s own `OverrideListsFile`). Struct-level `#[serde(default)]`
/// (backed by `impl Default` below, mirroring [`ResolverConfig::default`])
/// fills any field absent from a partial file; `deny_unknown_fields` still
/// rejects a typo'd key (`"potr"`, `"timeoutMs"`, ...) loudly rather than
/// silently ignoring it.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ResolverConfigFile {
    port: u16,
    timeout_mode: TimeoutMode,
    timeout_ms: u32,
    voters_enabled: bool,
}

impl Default for ResolverConfigFile {
    fn default() -> Self {
        let defaults = ResolverConfig::default();
        Self {
            port: defaults.port,
            timeout_mode: defaults.timeout_mode,
            timeout_ms: defaults.timeout_ms,
            voters_enabled: defaults.voters_enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigError, ResolverConfig};
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
        let toml = "port = 9000\ntimeout_mode = \"fail_closed\"\ntimeout_ms = 5000\nvoters_enabled = false\n";
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
                voters_enabled: false,
            }
        );
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

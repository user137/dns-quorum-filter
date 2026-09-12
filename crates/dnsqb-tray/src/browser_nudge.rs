//! T-229 (detection half only, 2026-09-13) — whether it's worth mentioning,
//! once, that no browser appears to have queried the local `DoH` endpoint yet.
//!
//! **This module deliberately decides only *when*, never *how*.** The user's
//! own ask ("небільшe спливаюче біля трею, не на весь екран, не по центру")
//! rules out `rfd`'s centered native dialogs (already used by `onboarding`),
//! and the two real rendering options each carry a cost bigger than this
//! module: a Windows balloon tip needs either a new direct dependency or a
//! hand-rolled `unsafe` `Shell_NotifyIcon` registration (this project is
//! `#![forbid(unsafe_code)]` everywhere, and `tray-icon` 0.21's cross-platform
//! `TrayIcon` exposes `window_handle()` but not the private `uID` it
//! registered its own icon under, so a balloon can't just reuse the existing
//! icon's `NOTIFYICONDATA` entry — it would need a second, separate
//! registration); a custom `tao` popup window needs a rendering dependency
//! this crate doesn't otherwise have (rendering text, not just showing a
//! native dialog). Both are real architectural additions to a
//! `#![forbid(unsafe_code)]` crate and belong in front of the user, not
//! picked silently — see TASKS-DONE.md's T-229 entry.
//!
//! What *is* built here, mirroring `onboarding.rs`'s exact shape: a pure
//! decision (`should_offer_browser_nudge`) plus the on-disk state it reads —
//! a `first-seen.stamp` (written once, ever, the earliest launch this app
//! has been observed at) and a `browser-nudge.seen` latch (T-229's own
//! one-time marker, distinct from `onboarding.seen` — the two nudges fire
//! independently). `main.rs` wires this to the poll loop and, for now, logs
//! rather than rendering — swapping in a real notification later only means
//! replacing that one call, not touching the decision logic above it.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// File name of the "browser nudge shown" marker under the app-data
/// directory — T-229's own one-shot latch, independent of `onboarding.seen`.
pub const BROWSER_NUDGE_SEEN_NAME: &str = "browser-nudge.seen";

/// File name of the "first ever observed launch" stamp under the app-data
/// directory. Content is the Unix-epoch millisecond timestamp as decimal
/// text — plain and human-inspectable, unlike relying on the file's own
/// filesystem metadata (which a copy/restore could reset).
const FIRST_SEEN_NAME: &str = "first-seen.stamp";

/// How long after the first-ever launch to wait before a sustained "zero
/// queries" reading is worth mentioning once. Not derived from SPEC.md — a
/// judgment call, long enough that a user still mid-install isn't nudged
/// while reading the setup instructions, short enough the nudge still lands
/// in the same sitting.
const NUDGE_AFTER: Duration = Duration::from_mins(30);

fn seen_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join(BROWSER_NUDGE_SEEN_NAME)
}

fn first_seen_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join(FIRST_SEEN_NAME)
}

/// Whether the one-time browser nudge has already been shown.
#[must_use]
pub fn browser_nudge_seen(app_data_dir: &Path) -> bool {
    seen_path(app_data_dir).exists()
}

/// Record that the nudge has actually been shown. Best-effort, matching
/// `onboarding::mark_onboarding_seen`: a failed write just means the check
/// re-evaluates true next tick, which is self-correcting, not a crash.
///
/// **Not called anywhere yet** — `main.rs`'s wiring deliberately calls only
/// the in-process `offered` latch, never this, because nothing is actually
/// shown to the user until a renderer is chosen (see the module doc); this
/// is the seam that renderer will call once it exists. Exercised only by
/// this module's own round-trip test in the meantime.
#[cfg_attr(not(test), allow(dead_code))]
pub fn mark_browser_nudge_seen(app_data_dir: &Path) {
    if let Err(err) = std::fs::write(seen_path(app_data_dir), []) {
        tracing::warn!("could not write {BROWSER_NUDGE_SEEN_NAME}: {err}");
    }
}

/// Record the first time this app has ever been observed running, if it
/// hasn't been already. Idempotent by construction (checks existence first),
/// so the stamp always holds the *earliest* launch, never a later one.
pub fn mark_first_seen_if_absent(app_data_dir: &Path, now: SystemTime) {
    let path = first_seen_path(app_data_dir);
    if path.exists() {
        return;
    }
    let millis = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    if let Err(err) = std::fs::write(&path, millis.to_string()) {
        tracing::warn!("could not write {FIRST_SEEN_NAME}: {err}");
    }
}

/// Read back the recorded first-seen time. Absent or unparsable (e.g.
/// hand-edited) both read as `None` — never a fabricated instant.
#[must_use]
pub fn first_seen(app_data_dir: &Path) -> Option<SystemTime> {
    let text = std::fs::read_to_string(first_seen_path(app_data_dir)).ok()?;
    let millis: u64 = text.trim().parse().ok()?;
    Some(SystemTime::UNIX_EPOCH + Duration::from_millis(millis))
}

/// Whether to offer the one-time "point your browser at this" nudge now.
///
/// `total_queries` — `AdminStats::total` from the most recent poll, but only
/// once the service is actually in the `Filtering` state; the caller passes
/// `None` for every other `TrayStatus` (offline/paused/no-active-provider/
/// watchdog), so those states never count as "zero queries" evidence one way
/// or the other. `first_seen` — `None` means not yet recorded, and the nudge
/// never fires without it (so a single instantaneous reading right after the
/// very first launch can't trigger it). `seen` — the one-time marker.
#[must_use]
pub fn should_offer_browser_nudge(
    now: SystemTime,
    first_seen: Option<SystemTime>,
    total_queries: Option<u64>,
    seen: bool,
) -> bool {
    if seen || total_queries != Some(0) {
        return false;
    }
    let Some(first_seen) = first_seen else {
        return false;
    };
    match now.duration_since(first_seen) {
        Ok(elapsed) => elapsed >= NUDGE_AFTER,
        // Clock went backwards relative to the stamp -- not yet due, never
        // treated as overdue from a negative/nonsensical elapsed time.
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        browser_nudge_seen, first_seen, mark_browser_nudge_seen, mark_first_seen_if_absent,
        should_offer_browser_nudge, NUDGE_AFTER,
    };
    use std::time::{Duration, SystemTime};

    fn tempdir() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("tempdir: {err}"),
        }
    }

    // Happy path: zero queries, well past the threshold, never shown before.
    #[test]
    fn offers_the_nudge_once_the_threshold_has_passed_with_zero_queries() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let now = start + NUDGE_AFTER;
        assert!(should_offer_browser_nudge(now, Some(start), Some(0), false));
    }

    // Security/boundary: one second short of the threshold must not fire;
    // exactly at it must.
    #[test]
    fn the_threshold_is_a_hard_boundary() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let just_short = start + NUDGE_AFTER - Duration::from_secs(1);
        assert!(!should_offer_browser_nudge(
            just_short,
            Some(start),
            Some(0),
            false
        ));
        let exactly = start + NUDGE_AFTER;
        assert!(should_offer_browser_nudge(
            exactly,
            Some(start),
            Some(0),
            false
        ));
    }

    // Misuse/fool: no evidence yet (service never reached `Filtering`, or
    // never recorded a first launch) must never fire, whatever the clock
    // says -- absence is not zero.
    #[test]
    fn does_not_fire_without_total_queries_or_a_first_seen_stamp() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let now = start + NUDGE_AFTER;
        assert!(!should_offer_browser_nudge(now, None, Some(0), false));
        assert!(!should_offer_browser_nudge(now, Some(start), None, false));
    }

    // Misuse/fool: any nonzero query count must never fire, regardless of
    // elapsed time.
    #[test]
    fn does_not_fire_once_any_query_has_been_seen() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let now = start + NUDGE_AFTER * 10;
        assert!(!should_offer_browser_nudge(
            now,
            Some(start),
            Some(1),
            false
        ));
    }

    // Error path: a first-seen stamp somehow in the future (clock skew, a
    // restored backup) must read as "not yet due", not panic or overflow.
    #[test]
    fn a_first_seen_stamp_in_the_future_is_not_yet_due_not_a_panic() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let future_stamp = now + Duration::from_secs(60);
        assert!(!should_offer_browser_nudge(
            now,
            Some(future_stamp),
            Some(0),
            false
        ));
    }

    // Idempotency/error: once the marker exists the nudge is never re-offered
    // automatically.
    #[test]
    fn a_seen_marker_suppresses_the_offer_regardless_of_everything_else() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let now = start + NUDGE_AFTER * 10;
        assert!(!should_offer_browser_nudge(now, Some(start), Some(0), true));
    }

    #[test]
    fn browser_nudge_seen_marker_round_trips() {
        let dir = tempdir();
        assert!(!browser_nudge_seen(dir.path()));
        mark_browser_nudge_seen(dir.path());
        assert!(browser_nudge_seen(dir.path()));
        mark_browser_nudge_seen(dir.path()); // a second write must not panic
        assert!(browser_nudge_seen(dir.path()));
    }

    #[test]
    fn first_seen_stamp_round_trips_and_keeps_the_earliest_value() {
        let dir = tempdir();
        assert_eq!(first_seen(dir.path()), None);

        let earliest = SystemTime::UNIX_EPOCH + Duration::from_secs(500);
        mark_first_seen_if_absent(dir.path(), earliest);
        assert_eq!(first_seen(dir.path()), Some(earliest));

        // A later call (e.g. a subsequent launch) must not overwrite it.
        let later = earliest + Duration::from_secs(999);
        mark_first_seen_if_absent(dir.path(), later);
        assert_eq!(first_seen(dir.path()), Some(earliest));
    }

    #[test]
    fn first_seen_reads_back_none_for_a_corrupt_stamp_file() {
        let dir = tempdir();
        let path = dir.path().join(super::FIRST_SEEN_NAME);
        match std::fs::write(&path, "not-a-number") {
            Ok(()) => {}
            Err(err) => panic!("write: {err}"),
        }
        assert_eq!(first_seen(dir.path()), None);
    }
}

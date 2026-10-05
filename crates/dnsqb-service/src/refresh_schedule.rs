//! ARCH-10 (wave 15): when a background updater's *first* cycle is due.
//! Every updater used to refresh the moment the service started, so each
//! restart re-downloaded files fetched minutes earlier. A file's mtime is
//! already its "last success" timestamp (`paths::write_atomic` only runs after
//! a verified fetch), so the first cycle waits out whatever is left of the
//! interval instead.

use std::path::Path;
use std::time::{Duration, SystemTime};

/// How long to wait before the first refresh. Zero — refresh now — when there
/// is no last success, when it lies in the future (the clock moved back, so
/// its age is unknown), or when it is at least `interval` old.
pub(crate) fn first_cycle_delay(
    now: SystemTime,
    last_success: Option<SystemTime>,
    interval: Duration,
) -> Duration {
    match last_success.map(|last| now.duration_since(last)) {
        Some(Ok(age)) if age < interval => interval.saturating_sub(age),
        _ => Duration::ZERO,
    }
}

/// The oldest mtime across `paths` — the set is only as fresh as its stalest
/// member. `None` when any file is missing or unreadable, or the set is empty.
pub(crate) fn oldest_mtime<P: AsRef<Path>>(
    paths: impl IntoIterator<Item = P>,
) -> Option<SystemTime> {
    let mut oldest: Option<SystemTime> = None;
    for path in paths {
        let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok()?;
        oldest = Some(oldest.map_or(modified, |o| o.min(modified)));
    }
    oldest
}

#[cfg(test)]
mod tests {
    use super::{first_cycle_delay, oldest_mtime};
    use std::time::{Duration, SystemTime};

    const DAY: Duration = Duration::from_hours(24);

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn no_last_success_refreshes_now() {
        assert_eq!(first_cycle_delay(at(1_000_000), None, DAY), Duration::ZERO);
    }

    #[test]
    fn a_fresh_file_waits_out_the_rest_of_the_interval() {
        let now = at(1_000_000);
        let last = now - Duration::from_hours(1);
        assert_eq!(
            first_cycle_delay(now, Some(last), DAY),
            Duration::from_hours(23)
        );
    }

    #[test]
    fn a_file_exactly_one_interval_old_or_older_refreshes_now() {
        let now = at(1_000_000);
        assert_eq!(first_cycle_delay(now, Some(now - DAY), DAY), Duration::ZERO);
        assert_eq!(
            first_cycle_delay(now, Some(now - DAY - Duration::from_secs(1)), DAY),
            Duration::ZERO
        );
    }

    #[test]
    fn a_file_written_just_now_waits_the_full_interval() {
        let now = at(1_000_000);
        assert_eq!(first_cycle_delay(now, Some(now), DAY), DAY);
    }

    #[test]
    fn an_mtime_in_the_future_refreshes_now() {
        let now = at(1_000_000);
        assert_eq!(
            first_cycle_delay(now, Some(now + Duration::from_secs(60)), DAY),
            Duration::ZERO,
            "a clock that moved back leaves the file's age unknown"
        );
    }

    #[test]
    fn oldest_mtime_is_none_when_any_file_is_missing_or_the_set_is_empty() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir");
        };
        let present = dir.path().join("a.txt");
        if let Err(err) = std::fs::write(&present, "x") {
            panic!("write: {err}");
        }
        assert!(oldest_mtime([&present]).is_some());
        assert!(oldest_mtime([present.clone(), dir.path().join("missing.txt")]).is_none());
        assert!(oldest_mtime(Vec::<std::path::PathBuf>::new()).is_none());
    }

    #[test]
    fn oldest_mtime_picks_the_stalest_file() {
        let Ok(dir) = tempfile::tempdir() else {
            panic!("tempdir");
        };
        let old = dir.path().join("old.txt");
        let new = dir.path().join("new.txt");
        for path in [&old, &new] {
            if let Err(err) = std::fs::write(path, "x") {
                panic!("write: {err}");
            }
        }
        let stale = SystemTime::now() - Duration::from_hours(30);
        let Ok(file) = std::fs::File::options().write(true).open(&old) else {
            panic!("open");
        };
        if let Err(err) = file.set_modified(stale) {
            panic!("set_modified: {err}");
        }
        drop(file);
        let Some(oldest) = oldest_mtime([&new, &old]) else {
            panic!("both files exist");
        };
        let Ok(age) = SystemTime::now().duration_since(oldest) else {
            panic!("oldest is in the past");
        };
        assert!(age >= Duration::from_hours(29), "got {age:?}");
    }
}

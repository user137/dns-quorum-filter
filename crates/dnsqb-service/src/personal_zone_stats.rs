//! T-138 (Батч 4.5, SPEC.md §5.1.1) — the pure aggregation core behind the
//! personal learned rating-filter zone. This module never talks to the
//! network or disk; [`crate::personal_zone_persist`] is the impure shell
//! that seals/restores a [`PersistedPersonalZone`] and [`crate::dispatch`]
//! is the hot-path caller of [`PersonalZoneStats::record_visit`].
//!
//! **Signal, not identity: a queried hostname, not a registrable** — this
//! crate has no PSL (see `rating_filter`'s module doc), so `www.`/`api.`/
//! `cdn.` of one site are tracked as separate entries. Narrower and safe for
//! `zone_match`'s suffix walk, but it splits the frequency signal and eats
//! into [`MAX_TRACKED_DOMAINS`] faster than a registrable-level count would.
//!
//! **Aggregated counters, not a raw timestamp log** (SPEC.md §5.1.1's own
//! wording): each tracked domain holds a fixed-length ring of per-day visit
//! counts, one day evicted and one added on every [`PersonalZoneStats::rotate_day`]
//! call — never a growing list of events.
//!
//! **Two inclusion criteria, union not intersection** (SPEC.md §5.1.1): a
//! domain qualifies for the bubble if it is in the personal frequency top-N
//! over its window **or** it was visited on enough distinct days over its
//! own (possibly different) window — see [`PersonalZoneStats::derive_qualifying_domains`].

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::SystemTime;

use crate::config::PersonalZoneConfig;

/// Hard, provable cap on how many distinct hostnames this store tracks at
/// once — a bound on memory and on `derive_qualifying_domains`'s per-cycle
/// cost, not just a nice-to-have (the same discipline as
/// `admission::ConnectionGate` / the query-log ring buffer's 1000/24h bound).
/// Checked with `>=`, not an equality that only holds by construction.
pub(crate) const MAX_TRACKED_DOMAINS: usize = 2000;

/// A day counter, not a calendar date — days since the Unix epoch,
/// saturating on both directions rather than panicking on a clock jump
/// (NTP correction, timezone change, or a multi-month-old restored
/// snapshot). Comparable/orderable so rollover logic never needs a
/// caller-proven invariant to stay in bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DayIndex(u32);

impl DayIndex {
    /// The day `now` falls on. A `SystemTime` before the Unix epoch (an
    /// unreasonable clock, not a real case this crate needs to handle
    /// precisely) saturates to day 0 rather than panicking.
    #[must_use]
    pub(crate) fn from_system_time(now: SystemTime) -> Self {
        let secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let days = secs / 86_400;
        Self(u32::try_from(days).unwrap_or(u32::MAX))
    }
}

/// One tracked domain's rolling window: exactly `window_len` daily counts,
/// oldest-first, `back()` is always today.
#[derive(Debug, Clone)]
struct DomainStats {
    counts: VecDeque<u16>,
    /// The most recent day this domain was actually visited (a nonzero
    /// count) — used only to pick an eviction victim under
    /// [`MAX_TRACKED_DOMAINS`], not for any inclusion decision.
    last_visited: DayIndex,
}

/// The whole personal-zone aggregate: today's day index, the fixed window
/// length every domain's ring is kept at, and the tracked domains
/// themselves.
#[derive(Debug, Clone)]
pub(crate) struct PersonalZoneStats {
    today: DayIndex,
    window_len: usize,
    domains: HashMap<String, DomainStats>,
}

/// `max(frequency_window_days, regularity_window_days)`, at least 1 — the
/// ring length every domain's [`DomainStats::counts`] is kept at, so both
/// criteria in [`PersonalZoneStats::derive_qualifying_domains`] can always
/// read their own window out of the same buffer.
#[must_use]
pub(crate) fn window_len_from_config(cfg: &PersonalZoneConfig) -> usize {
    let freq = usize::try_from(cfg.frequency_window_days).unwrap_or(usize::MAX);
    let reg = usize::try_from(cfg.regularity_window_days).unwrap_or(usize::MAX);
    freq.max(reg).max(1)
}

fn resize_counts(v: Vec<u16>, window_len: usize) -> VecDeque<u16> {
    let mut d: VecDeque<u16> = v.into();
    while d.len() > window_len {
        d.pop_front();
    }
    while d.len() < window_len {
        d.push_front(0);
    }
    d
}

/// Reconstructs a plausible `last_visited` for a domain restored from disk
/// (the persisted DTO doesn't carry it) — the day of the most recent
/// nonzero bucket, scanning back from `today`. Only feeds
/// [`MAX_TRACKED_DOMAINS`] eviction ordering, not any inclusion decision, so
/// an approximation here is fine.
fn last_visited_from_counts(counts: &VecDeque<u16>, today: DayIndex) -> DayIndex {
    for (i, &c) in counts.iter().rev().enumerate() {
        if c != 0 {
            let offset = u32::try_from(i).unwrap_or(u32::MAX);
            return DayIndex(today.0.saturating_sub(offset));
        }
    }
    today
}

fn sum_last(counts: &VecDeque<u16>, n: usize) -> u32 {
    counts
        .iter()
        .rev()
        .take(n)
        .fold(0u32, |acc, &c| acc.saturating_add(u32::from(c)))
}

fn count_nonzero_last(counts: &VecDeque<u16>, n: usize) -> usize {
    counts.iter().rev().take(n).filter(|&&c| c != 0).count()
}

/// The compact on-disk shape [`crate::personal_zone_persist`] seals —
/// `today` lets a restart-after-downtime correctly roll the buffer forward
/// before anything is trusted, `domains` is sorted for a deterministic file.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct PersistedPersonalZone {
    today: u32,
    domains: Vec<(String, Vec<u16>)>,
}

impl PersonalZoneStats {
    /// A fresh, empty store — the first-enable / no-persisted-file case.
    #[must_use]
    pub(crate) fn new(window_len: usize, today: DayIndex) -> Self {
        Self {
            today,
            window_len: window_len.max(1),
            domains: HashMap::new(),
        }
    }

    /// Rebuilds from a persisted snapshot, resizing every domain's ring to
    /// `window_len` (the *current* config's window, which may differ from
    /// whatever the snapshot was written under) and rolling forward to
    /// `current_today` in the same step a restart-after-downtime would need
    /// anyway.
    #[must_use]
    pub(crate) fn from_persisted(
        persisted: PersistedPersonalZone,
        current_today: DayIndex,
        window_len: usize,
    ) -> Self {
        let window_len = window_len.max(1);
        let old_today = DayIndex(persisted.today);
        let mut domains = HashMap::with_capacity(persisted.domains.len());
        for (name, counts_vec) in persisted.domains {
            let counts = resize_counts(counts_vec, window_len);
            let last_visited = last_visited_from_counts(&counts, old_today);
            domains.insert(
                name,
                DomainStats {
                    counts,
                    last_visited,
                },
            );
        }
        let mut stats = Self {
            today: old_today,
            window_len,
            domains,
        };
        stats.rotate_day(current_today);
        stats
    }

    /// Serializes the current state for [`crate::personal_zone_persist::persist_snapshot`].
    #[must_use]
    pub(crate) fn to_persisted(&self) -> PersistedPersonalZone {
        let mut domains: Vec<(String, Vec<u16>)> = self
            .domains
            .iter()
            .map(|(d, s)| (d.clone(), s.counts.iter().copied().collect()))
            .collect();
        domains.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        PersistedPersonalZone {
            today: self.today.0,
            domains,
        }
    }

    /// Today's day index, as this store currently understands it. Test-only
    /// — nothing in production code needs to read it back (the day is only
    /// ever fed *in*, via [`Self::rotate_day`]/[`Self::record_visit`]).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn today(&self) -> DayIndex {
        self.today
    }

    /// How many distinct hostnames are currently tracked (never above
    /// [`MAX_TRACKED_DOMAINS`]) — diagnostic only, not part of any bubble
    /// decision.
    #[must_use]
    pub(crate) fn tracked_domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Rolls every domain's ring forward to `new_today`. A no-op if
    /// `new_today` is not strictly after the currently-tracked day (covers
    /// a backward clock jump — NTP correction, timezone change — without
    /// ever shifting data the wrong way). Domains whose ring goes
    /// all-zero after the shift are dropped, so dead history does not grow
    /// without bound.
    pub(crate) fn rotate_day(&mut self, new_today: DayIndex) {
        if new_today <= self.today {
            return;
        }
        let days_forward = new_today.0 - self.today.0;
        let shift = usize::try_from(days_forward)
            .unwrap_or(usize::MAX)
            .min(self.window_len);
        for stats in self.domains.values_mut() {
            for _ in 0..shift {
                stats.counts.pop_front();
                stats.counts.push_back(0);
            }
        }
        self.today = new_today;
        self.domains.retain(|_, s| s.counts.iter().any(|&c| c != 0));
    }

    /// Records one already-ALLOW-and-Quorum-passed resolution of `host` on
    /// `today` — the sole hot-path entry point (called from `dispatch.rs`
    /// after the pipeline's own decision is final, never as part of making
    /// it). Rolls the day forward first if needed, so this alone keeps the
    /// store correct even if the periodic rollover task hasn't ticked yet
    /// since midnight.
    ///
    /// Never allocates on an already-tracked domain (`saturating_add`, no
    /// clone) — only a genuinely new hostname clones `host` into an owned
    /// key.
    pub(crate) fn record_visit(&mut self, host: &str, today: DayIndex) {
        self.rotate_day(today);
        if let Some(entry) = self.domains.get_mut(host) {
            entry.last_visited = today;
            if let Some(last) = entry.counts.back_mut() {
                *last = last.saturating_add(1);
            }
            return;
        }
        if self.domains.len() >= MAX_TRACKED_DOMAINS {
            self.evict_oldest();
        }
        let mut counts = VecDeque::with_capacity(self.window_len);
        for _ in 1..self.window_len {
            counts.push_back(0);
        }
        counts.push_back(1);
        self.domains.insert(
            host.to_string(),
            DomainStats {
                counts,
                last_visited: today,
            },
        );
    }

    /// Evicts the domain least recently visited — the
    /// [`MAX_TRACKED_DOMAINS`] backstop, run only on the rare call that
    /// would otherwise grow past the cap.
    fn evict_oldest(&mut self) {
        let oldest = self
            .domains
            .iter()
            .min_by_key(|(_, s)| s.last_visited)
            .map(|(d, _)| d.clone());
        if let Some(oldest) = oldest {
            self.domains.remove(&oldest);
        }
    }

    /// The union of the two SPEC.md §5.1.1 inclusion criteria: personal
    /// frequency top-N over `cfg.frequency_window_days`, **or** visited on
    /// at least `cfg.regularity_min_days` distinct days over
    /// `cfg.regularity_window_days`. Both windows are capped at this
    /// store's own `window_len` (always true by construction — see
    /// [`window_len_from_config`] — but capped again here rather than
    /// trusting that invariant across a call boundary).
    #[must_use]
    pub(crate) fn derive_qualifying_domains(&self, cfg: &PersonalZoneConfig) -> HashSet<String> {
        let freq_n = usize::try_from(cfg.frequency_window_days)
            .unwrap_or(usize::MAX)
            .min(self.window_len);
        let reg_n = usize::try_from(cfg.regularity_window_days)
            .unwrap_or(usize::MAX)
            .min(self.window_len);

        let mut by_frequency: Vec<(&str, u32)> = self
            .domains
            .iter()
            .map(|(d, s)| (d.as_str(), sum_last(&s.counts, freq_n)))
            .filter(|(_, sum)| *sum > 0)
            .collect();
        by_frequency.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        let top_n = usize::try_from(cfg.frequency_top_n).unwrap_or(usize::MAX);
        let mut qualifying: HashSet<String> = by_frequency
            .into_iter()
            .take(top_n)
            .map(|(d, _)| d.to_string())
            .collect();

        for (domain, stats) in &self.domains {
            let nonzero_days = count_nonzero_last(&stats.counts, reg_n);
            if u32::try_from(nonzero_days).unwrap_or(0) >= cfg.regularity_min_days {
                qualifying.insert(domain.clone());
            }
        }
        qualifying
    }
}

#[cfg(test)]
mod tests {
    use super::{DayIndex, PersonalZoneStats, MAX_TRACKED_DOMAINS};
    use crate::config::PersonalZoneConfig;

    fn day(n: u32) -> DayIndex {
        DayIndex(n)
    }

    fn cfg(freq_window: u32, top_n: u32, reg_window: u32, reg_min: u32) -> PersonalZoneConfig {
        PersonalZoneConfig {
            enabled: true,
            frequency_window_days: freq_window,
            frequency_top_n: top_n,
            regularity_window_days: reg_window,
            regularity_min_days: reg_min,
        }
    }

    // ---- Happy path ----

    #[test]
    fn a_domain_visited_daily_qualifies_by_regularity() {
        let mut stats = PersonalZoneStats::new(14, day(0));
        for d in 0..10 {
            stats.record_visit("daily.example", day(d));
        }
        let qualifying = stats.derive_qualifying_domains(&cfg(30, 1, 14, 5));
        assert!(qualifying.contains("daily.example"));
    }

    #[test]
    fn a_domain_with_one_big_session_qualifies_by_frequency_not_regularity() {
        let mut stats = PersonalZoneStats::new(30, day(0));
        for _ in 0..50 {
            stats.record_visit("one-session.example", day(0));
        }
        // Never visited on a second day, so regularity can't be why it's in.
        let qualifying = stats.derive_qualifying_domains(&cfg(30, 5, 14, 3));
        assert!(qualifying.contains("one-session.example"));
    }

    #[test]
    fn the_two_criteria_are_a_union_not_an_intersection() {
        let mut stats = PersonalZoneStats::new(30, day(0));
        // Frequent but not regular: one huge day.
        for _ in 0..100 {
            stats.record_visit("frequent-only.example", day(0));
        }
        // Regular but not frequent: one visit each of 5 different days.
        for d in 0..5 {
            stats.record_visit("regular-only.example", day(d));
        }
        // Neither.
        stats.record_visit("neither.example", day(0));

        let qualifying = stats.derive_qualifying_domains(&cfg(30, 1, 14, 5));
        assert!(qualifying.contains("frequent-only.example"));
        assert!(qualifying.contains("regular-only.example"));
        assert!(!qualifying.contains("neither.example"));
    }

    // ---- Security / boundary ----

    #[test]
    fn the_tracked_domain_count_never_exceeds_the_hard_cap() {
        let mut stats = PersonalZoneStats::new(7, day(0));
        for i in 0..(MAX_TRACKED_DOMAINS + 50) {
            stats.record_visit(&format!("host-{i}.example"), day(0));
        }
        assert!(stats.tracked_domain_count() <= MAX_TRACKED_DOMAINS);
    }

    #[test]
    fn a_daily_counter_saturates_instead_of_overflowing() {
        let mut stats = PersonalZoneStats::new(1, day(0));
        for _ in 0..(u32::from(u16::MAX) + 10) {
            stats.record_visit("hot.example", day(0));
        }
        // No panic reaching here is the actual assertion; also check the
        // qualifying set still comes out sane.
        let qualifying = stats.derive_qualifying_domains(&cfg(1, 1, 1, 1));
        assert!(qualifying.contains("hot.example"));
    }

    // ---- Misuse / fool ----

    #[test]
    fn rotating_forward_by_more_than_the_window_clears_everything() {
        let mut stats = PersonalZoneStats::new(7, day(0));
        stats.record_visit("stale.example", day(0));
        // Simulate a restart after a long downtime.
        stats.rotate_day(day(1000));
        assert_eq!(stats.tracked_domain_count(), 0);
    }

    #[test]
    fn rotating_backward_is_a_no_op() {
        let mut stats = PersonalZoneStats::new(7, day(10));
        stats.record_visit("present.example", day(10));
        stats.rotate_day(day(3)); // clock jumped backward
        assert_eq!(stats.today(), day(10), "backward jump must not move today");
        let qualifying = stats.derive_qualifying_domains(&cfg(7, 10, 7, 1));
        assert!(
            qualifying.contains("present.example"),
            "backward jump must not lose data"
        );
    }

    #[test]
    fn a_persisted_snapshot_survives_a_window_length_change() {
        let mut stats = PersonalZoneStats::new(7, day(0));
        stats.record_visit("grown.example", day(0));
        let persisted = stats.to_persisted();
        // Restart with a larger configured window.
        let restored = PersonalZoneStats::from_persisted(persisted, day(0), 30);
        let qualifying = restored.derive_qualifying_domains(&cfg(30, 5, 30, 1));
        assert!(qualifying.contains("grown.example"));
    }

    // Closing-advisor (Батч 4.5): `from_persisted` calls `resize_counts`
    // *then* `rotate_day` - each individually tested above/elsewhere, but
    // their composition (a restart after a long downtime *and* a shrunk
    // window in the same edit) is where a pad-front/drop-front ordering bug
    // would actually live. A day gap smaller than the new window: the visit
    // must still land at the correct offset from `current_today`, not be
    // lost or misplaced by the resize.
    #[test]
    fn a_restart_after_a_shrunk_window_and_a_partial_gap_keeps_the_right_offset() {
        let mut stats = PersonalZoneStats::new(30, day(0));
        for d in 0..30 {
            stats.record_visit("everyday.example", day(d));
        }
        let persisted = stats.to_persisted();
        // Restart 5 days later, window shrunk 30 -> 7 in the same edit.
        let restored = PersonalZoneStats::from_persisted(persisted, day(34), 7);
        // Visits ran through day 29; day 34 is now "today", so the last
        // real visit (day 29) is 5 days back - inside a 7-day window.
        let qualifying = restored.derive_qualifying_domains(&cfg(7, 1, 7, 1));
        assert!(
            qualifying.contains("everyday.example"),
            "a visit still inside the shrunk window must survive the restart"
        );
    }

    // Same composition, but the gap now exceeds the shrunk window entirely -
    // every count must land outside the window and the domain must not
    // qualify (nor panic/underflow while getting there).
    #[test]
    fn a_restart_after_a_shrunk_window_and_a_gap_longer_than_it_drops_stale_data() {
        let mut stats = PersonalZoneStats::new(30, day(0));
        stats.record_visit("stale.example", day(0));
        let persisted = stats.to_persisted();
        // Restart 40 days later, window shrunk 30 -> 7.
        let restored = PersonalZoneStats::from_persisted(persisted, day(40), 7);
        let qualifying = restored.derive_qualifying_domains(&cfg(7, 1, 7, 1));
        assert!(
            !qualifying.contains("stale.example"),
            "a visit older than the shrunk window must not survive the restart"
        );
    }

    // ---- Error path ----

    #[test]
    fn an_empty_store_derives_an_empty_set() {
        let stats = PersonalZoneStats::new(30, day(0));
        assert!(stats
            .derive_qualifying_domains(&cfg(30, 200, 14, 5))
            .is_empty());
    }
}

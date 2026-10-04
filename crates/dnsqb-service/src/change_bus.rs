//! T-277 — "something in topic X changed" signals for the `/admin/ui` push
//! stream (`GET /admin/events`). One [`tokio::sync::watch`] version counter
//! per [`Topic`]: a writer calls [`ChangeBus::bump`] after a live change, a
//! subscriber wakes and re-fetches that topic's data through the ordinary
//! `GET` route. `watch` keeps only the latest value, so a burst of changes
//! reaches a slow subscriber as one wake-up, never a backlog.
//!
//! Privacy: a topic is a closed enum and the payload is a bare counter — no
//! domain name or request field can ever travel through this bus.

use tokio::sync::watch;

/// One `/admin/ui` card (or card group) whose data can change behind the
/// page's back. Much of `Status` (counters, watchdog state, cert trust,
/// reachability) changes without a writer in this process, so the event
/// stream samples it; a bump of `Status` (every accepted write route, see
/// `dispatch::serve`) only makes that sample happen at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Topic {
    Status,
    Overrides,
    Providers,
    CacheConfig,
    Geoip,
    Maxmind,
    Cctld,
    RatingFilter,
    BlocklistBundles,
    Log,
}

impl Topic {
    /// Every topic, in a fixed order — `ChangeBus` indexes its senders by
    /// position in this list.
    pub(crate) const ALL: [Topic; 10] = [
        Topic::Status,
        Topic::Overrides,
        Topic::Providers,
        Topic::CacheConfig,
        Topic::Geoip,
        Topic::Maxmind,
        Topic::Cctld,
        Topic::RatingFilter,
        Topic::BlocklistBundles,
        Topic::Log,
    ];

    /// The SSE `event:` name the client routes on.
    pub(crate) fn event_name(self) -> &'static str {
        match self {
            Topic::Status => "status",
            Topic::Overrides => "overrides",
            Topic::Providers => "providers",
            Topic::CacheConfig => "cache-config",
            Topic::Geoip => "geoip",
            Topic::Maxmind => "maxmind",
            Topic::Cctld => "cctld",
            Topic::RatingFilter => "rating-filter",
            Topic::BlocklistBundles => "blocklist-bundles",
            Topic::Log => "log",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// The per-topic version counters. Lives on `AppState`.
pub(crate) struct ChangeBus {
    senders: [watch::Sender<u64>; Topic::ALL.len()],
}

impl Default for ChangeBus {
    fn default() -> Self {
        Self {
            senders: std::array::from_fn(|_| watch::Sender::new(0)),
        }
    }
}

impl ChangeBus {
    /// Marks `topic` changed. `send_modify` stores the new version even with
    /// no subscriber (plain `send` would drop it), so a page that connects
    /// later still starts from the current version.
    pub(crate) fn bump(&self, topic: Topic) {
        self.senders[topic.index()].send_modify(|version| *version = version.wrapping_add(1));
    }

    /// A receiver that wakes on the next `bump` of `topic` after this call.
    pub(crate) fn subscribe(&self, topic: Topic) -> watch::Receiver<u64> {
        self.senders[topic.index()].subscribe()
    }

    /// The current version of `topic`.
    #[cfg(test)]
    pub(crate) fn version(&self, topic: Topic) -> u64 {
        *self.senders[topic.index()].borrow()
    }
}

#[cfg(test)]
mod tests {
    use super::{ChangeBus, Topic};

    #[test]
    fn all_lists_every_topic_once_in_index_order() {
        for (position, topic) in Topic::ALL.iter().enumerate() {
            assert_eq!(topic.index(), position);
        }
        let mut names: Vec<_> = Topic::ALL.iter().map(|t| t.event_name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Topic::ALL.len(), "event names must be unique");
    }

    #[test]
    fn bump_without_subscribers_still_advances_the_version() {
        let bus = ChangeBus::default();
        bus.bump(Topic::Overrides);
        assert_eq!(bus.version(Topic::Overrides), 1);
    }

    #[tokio::test]
    async fn bump_wakes_a_subscriber_of_that_topic() {
        let bus = ChangeBus::default();
        let mut rx = bus.subscribe(Topic::Providers);
        bus.bump(Topic::Providers);
        assert!(rx.changed().await.is_ok());
        assert_eq!(*rx.borrow_and_update(), 1);
    }

    #[test]
    fn a_burst_of_bumps_reaches_a_subscriber_as_one_change() {
        let bus = ChangeBus::default();
        let mut rx = bus.subscribe(Topic::Log);
        for _ in 0..100 {
            bus.bump(Topic::Log);
        }
        assert!(rx.has_changed().unwrap_or(false));
        assert_eq!(*rx.borrow_and_update(), 100);
        assert!(!rx.has_changed().unwrap_or(true), "one wake-up, no backlog");
    }

    #[test]
    fn bumping_one_topic_does_not_wake_another() {
        let bus = ChangeBus::default();
        let rx = bus.subscribe(Topic::Geoip);
        bus.bump(Topic::Maxmind);
        assert!(!rx.has_changed().unwrap_or(true));
        assert_eq!(bus.version(Topic::Geoip), 0);
    }

    #[test]
    fn the_version_counter_wraps_instead_of_overflowing() {
        let bus = ChangeBus::default();
        bus.senders[Topic::Cctld.index()].send_replace(u64::MAX);
        bus.bump(Topic::Cctld);
        assert_eq!(bus.version(Topic::Cctld), 0);
    }
}

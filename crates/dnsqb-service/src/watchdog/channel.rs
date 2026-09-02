//! T-84 / T-93 — per-channel signal status (SPEC.md §7 / §7.1 #8). Shared by
//! all three heartbeat channels. Pure: a channel counts its own consecutive
//! misses and reports a [`ChannelStatus`]; it never concludes "the peer is
//! dead" — that verdict belongs to the voting layer (Батч 3.2), and this type
//! deliberately has no variant for it.

/// Consecutive missed heartbeats on one channel before it reports
/// [`ChannelStatus::NoSignal`] (SPEC.md §7.1 #8).
pub const MISS_THRESHOLD: u32 = 3;

/// What one channel can say about its peer — never more than these two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelStatus {
    /// A heartbeat arrived within the last [`MISS_THRESHOLD`] intervals.
    Signal,
    /// [`MISS_THRESHOLD`] or more consecutive intervals with no heartbeat.
    /// Not a death verdict — deciding that needs the other channels' votes.
    NoSignal,
}

/// Map a channel's consecutive-miss count to its [`ChannelStatus`].
#[must_use]
pub fn channel_status(consecutive_misses: u32) -> ChannelStatus {
    if consecutive_misses >= MISS_THRESHOLD {
        ChannelStatus::NoSignal
    } else {
        ChannelStatus::Signal
    }
}

#[cfg(test)]
mod tests {
    use super::{channel_status, ChannelStatus, MISS_THRESHOLD};

    // Happy path: below the threshold is always Signal.
    #[test]
    fn below_threshold_is_signal() {
        for misses in 0..MISS_THRESHOLD {
            assert_eq!(
                channel_status(misses),
                ChannelStatus::Signal,
                "{misses} misses"
            );
        }
    }

    // Boundary: exactly at the threshold, and the saturated count.
    #[test]
    fn at_and_above_threshold_is_no_signal() {
        assert_eq!(channel_status(MISS_THRESHOLD), ChannelStatus::NoSignal);
        assert_eq!(channel_status(u32::MAX), ChannelStatus::NoSignal);
    }

    // T-93 (per-channel half): a silent channel says "no signal", it does not
    // conclude the peer is dead — structurally, `ChannelStatus` has no such
    // variant. The death verdict is the voting layer's (Батч 3.2).
    #[test]
    fn no_signal_is_the_strongest_a_single_channel_can_say() {
        let all: &[ChannelStatus] = &[ChannelStatus::Signal, ChannelStatus::NoSignal];
        assert_eq!(all.len(), 2, "a channel reports exactly Signal or NoSignal");
        assert_eq!(channel_status(MISS_THRESHOLD + 10), ChannelStatus::NoSignal);
    }
}

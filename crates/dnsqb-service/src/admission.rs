//! Connection admission (T-169, SPEC.md §1.1) — a bounded-concurrency gate
//! with **immediate reject**, the resource-exhaustion backstop the load test
//! (PERFORMANCE.md) showed the accept loop needs against pathological
//! accumulation of held connections. It sits in front of `main.rs`'s
//! per-connection `tokio::spawn`: a connection that cannot get a permit is
//! closed at the TCP layer *before* TLS, never queued — the DNS-resolver
//! industry pattern (Unbound's jostle list, dnsdist rate-limiting): shed load
//! fast, do not build a deep queue.
//!
//! Zero-overhead by construction (SPEC.md §1.1 — "типи без оверхеду"): one
//! [`tokio::sync::Semaphore`] for lock-free permit accounting plus one
//! [`AtomicU64`] for the cumulative reject count. No `Mutex`, no `Arc<Mutex>`
//! cascade — the same shape as `dispatch::InFlightGuard`'s `&AtomicU64` RAII
//! idiom and `AppState::reachability`'s "a `Copy` value does not need a lock"
//! note.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// A bounded-concurrency admission gate for inbound connections (T-169).
///
/// [`try_admit`](Self::try_admit) hands out an [`OwnedSemaphorePermit`] while
/// the gate is below its ceiling and `None` once it is full. The permit is
/// `'static` (owned, not borrowed) specifically so it can be moved into the
/// per-connection `tokio::spawn`ed task and released on `Drop` when that task
/// returns — including when the TLS handshake times out — with no manual
/// bookkeeping, the same RAII shape as `dispatch::InFlightGuard` and
/// `hyper_util`'s `graceful.watcher()`.
///
/// # Examples
///
/// ```
/// use dnsqb_service::ConnectionGate;
///
/// let gate = ConnectionGate::new(1);
/// let permit = gate.try_admit();
/// assert!(permit.is_some());
/// assert!(gate.try_admit().is_none(), "at the ceiling");
/// assert_eq!(gate.rejected_count(), 1);
/// drop(permit);
/// assert!(gate.try_admit().is_some(), "a freed permit re-opens the slot");
/// ```
#[derive(Debug)]
pub struct ConnectionGate {
    /// Lock-free permit accounting. Wrapped in `Arc` because
    /// `Semaphore::try_acquire_owned` consumes an `Arc<Semaphore>` to mint a
    /// `'static` permit.
    permits: Arc<Semaphore>,
    /// Cumulative count of connections turned away at the ceiling — the same
    /// `AtomicU64` + `Relaxed` shape as `AppState::in_flight`.
    rejected: AtomicU64,
    /// The configured ceiling, kept for [`active`](Self::active) — `Semaphore`
    /// exposes only `available_permits`, not its original size.
    max: u32,
}

impl ConnectionGate {
    /// Builds a gate that admits at most `max_connections` concurrent
    /// connections.
    ///
    /// `max_connections` is a `u32` that
    /// [`ResolverConfig::load`](crate::ResolverConfig::load) has already
    /// checked is non-zero and no greater than `1_000_000`. Widening
    /// `u32` → `usize` is lossless and the result is far below
    /// `Semaphore::MAX_PERMITS` (`usize::MAX >> 3`), so `Semaphore::new`
    /// cannot panic here — provable from this line without tracing the caller.
    #[must_use]
    pub fn new(max_connections: u32) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max_connections as usize)),
            rejected: AtomicU64::new(0),
            max: max_connections,
        }
    }

    /// Tries to admit one connection. `Some(permit)` while the gate is below
    /// its ceiling — hold the permit for the connection's lifetime and drop
    /// it (RAII) to free the slot. `None` at the ceiling, and the cumulative
    /// reject counter is incremented.
    #[must_use]
    pub fn try_admit(&self) -> Option<OwnedSemaphorePermit> {
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        Some(permit)
    }

    /// Cumulative number of connections rejected at the ceiling since startup
    /// (never resets). Surfaced through `AdminStats`.
    #[must_use]
    pub fn rejected_count(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    /// Connections currently admitted — permits handed out and not yet
    /// dropped, i.e. `max - available`. `saturating_sub` keeps the
    /// subtraction safe from the line itself: the gate only ever returns
    /// permits it first took and never calls `add_permits`, so
    /// `available_permits()` can never exceed `max`.
    #[must_use]
    pub fn active(&self) -> u32 {
        let available = u32::try_from(self.permits.available_permits()).unwrap_or(u32::MAX);
        self.max.saturating_sub(available)
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectionGate;
    use std::sync::Arc;

    // --- Happy path -------------------------------------------------------

    #[test]
    fn admits_up_to_the_ceiling_and_tracks_active_count() {
        let gate = ConnectionGate::new(3);
        assert_eq!(gate.active(), 0);

        let p1 = gate.try_admit();
        assert!(p1.is_some());
        assert_eq!(gate.active(), 1);

        let p2 = gate.try_admit();
        assert!(p2.is_some());
        assert_eq!(gate.active(), 2);

        let p3 = gate.try_admit();
        assert!(p3.is_some());
        assert_eq!(gate.active(), 3);

        assert_eq!(
            gate.rejected_count(),
            0,
            "nothing was rejected below the ceiling"
        );
    }

    // --- Security & Boundary --------------------------------------------

    #[test]
    fn rejects_exactly_at_the_ceiling_then_reopens_a_slot_on_drop() {
        let gate = ConnectionGate::new(2);
        let p1 = gate.try_admit();
        let p2 = gate.try_admit();
        assert!(p1.is_some() && p2.is_some());

        // Exactly one past the ceiling: rejected, counter +1, no permit.
        assert!(gate.try_admit().is_none());
        assert_eq!(gate.rejected_count(), 1);
        assert_eq!(gate.active(), 2);

        // RAII release: dropping a held permit frees its slot.
        drop(p1);
        assert_eq!(gate.active(), 1);
        let p3 = gate.try_admit();
        assert!(p3.is_some(), "a freed permit must re-open a slot");

        // The reject count is cumulative — a later success does not undo it.
        assert_eq!(gate.rejected_count(), 1);
        drop((p2, p3));
        assert_eq!(gate.active(), 0);
    }

    #[test]
    fn a_ceiling_of_one_admits_exactly_one() {
        let gate = ConnectionGate::new(1);
        let held = gate.try_admit();
        assert!(held.is_some());
        assert!(gate.try_admit().is_none());
        assert_eq!(gate.rejected_count(), 1);
    }

    // --- Misuse & Fool -------------------------------------------------

    #[test]
    fn rejected_count_only_counts_true_rejections_and_never_decrements() {
        let gate = ConnectionGate::new(2);

        // Repeated admit/drop cycles below the ceiling never touch the counter.
        for _ in 0..50 {
            let permit = gate.try_admit();
            assert!(permit.is_some());
            drop(permit);
        }
        assert_eq!(gate.rejected_count(), 0);

        // Fill the gate, then hammer it while full: every extra attempt counts.
        let first = gate.try_admit();
        let _second = gate.try_admit();
        for _ in 0..10 {
            assert!(gate.try_admit().is_none());
        }
        assert_eq!(gate.rejected_count(), 10);

        // Freeing a slot does not roll the cumulative counter back.
        drop(first);
        assert!(gate.try_admit().is_some());
        assert_eq!(gate.rejected_count(), 10);
    }

    // --- Concurrency --------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parallel_admits_never_exceed_the_ceiling_and_the_reject_count_is_exact() {
        use tokio::sync::Barrier;

        const CEILING: u32 = 8;
        const EXTRA: u32 = 40;
        let total = (CEILING + EXTRA) as usize;

        let gate = Arc::new(ConnectionGate::new(CEILING));
        // Every task takes its shot, then waits at the barrier before
        // returning — so a task that got a permit holds it while every other
        // task is still trying. Peak concurrency is `total`, not 1.
        let barrier = Arc::new(Barrier::new(total));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..total {
            let gate = Arc::clone(&gate);
            let barrier = Arc::clone(&barrier);
            set.spawn(async move {
                let permit = gate.try_admit();
                let admitted = permit.is_some();
                barrier.wait().await;
                drop(permit);
                admitted
            });
        }

        let mut admitted = 0u32;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(true) => admitted += 1,
                Ok(false) => {}
                Err(err) => panic!("an admission task panicked: {err}"),
            }
        }

        assert_eq!(admitted, CEILING, "never more permits than the ceiling");
        assert_eq!(
            gate.rejected_count(),
            u64::from(EXTRA),
            "every over-ceiling attempt counted exactly once (no lost atomic update)"
        );
        assert_eq!(gate.active(), 0, "all permits released after the barrier");
    }
}

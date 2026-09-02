//! `dnsqb-watcher` liveness primitives + decision core (SPEC.md §7 / §7.1).
//! Батч 3.1 built the primitives (`instance`, `frame`, `channel`, `pipe`,
//! `heartbeat_file`); Батч 3.2 added the decision core — `vote`, `backoff`,
//! `budget`, `pid_check`, `spawn`, `state`, and the pure `transition` that
//! composes them into the `diagrams/watchdog-state.md` automaton. Батч 3.3 adds
//! `loop_driver` (one direction's running loop as a pure, time-injected state
//! owner) and `launcher` (the idempotent "bring up a missing sibling" decision),
//! consumed by the two `main.rs` I/O shells.

pub mod backoff;
pub mod budget;
pub mod channel;
pub mod frame;
pub mod heartbeat_file;
pub mod instance;
pub mod loop_driver;
pub mod pid_check;
#[cfg(windows)]
pub mod pipe;
pub mod spawn;
pub mod state;
pub mod transition;
pub mod vote;

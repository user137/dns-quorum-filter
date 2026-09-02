//! `dnsqb-watcher` liveness primitives + decision core (SPEC.md §7 / §7.1).
//! Батч 3.1 built the primitives (`instance`, `frame`, `channel`, `pipe`,
//! `heartbeat_file`); Батч 3.2 added the decision core — `vote`, `backoff`,
//! `budget`, `pid_check`, `spawn`, `state`, and the pure `transition` that
//! composes them into the `diagrams/watchdog-state.md` automaton. The running
//! loops that tick this on both binaries land in Батч 3.3 (`main.rs` wiring +
//! `dnsqb-watcher`'s entry point).

pub mod backoff;
pub mod budget;
pub mod channel;
pub mod frame;
pub mod heartbeat_file;
pub mod instance;
pub mod pid_check;
#[cfg(windows)]
pub mod pipe;
pub mod spawn;
pub mod state;
pub mod transition;
pub mod vote;

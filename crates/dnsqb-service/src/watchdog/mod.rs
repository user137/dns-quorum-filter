//! `dnsqb-watcher` liveness primitives (SPEC.md §7 / §7.1). Батч 3.1 builds
//! these as tested library pieces; the running loops that drive them land in
//! Батч 3.3 (`main.rs` wiring) and the decision core (voting / backoff /
//! restart budget / PID verification) in Батч 3.2.

pub mod channel;
pub mod frame;
pub mod heartbeat_file;
pub mod instance;
#[cfg(windows)]
pub mod pipe;
pub mod vote;

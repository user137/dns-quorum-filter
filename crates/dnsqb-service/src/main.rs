// Release/MSIX: no console window (T-181). Debug keeps the console so a
// `cargo run` still shows `tracing` on stdout — same split as `dnsqb-tray`.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

//! `dnsqb-service` binary entry point. All orchestration lives in
//! `dnsqb_service::run` (T-210, DECISIONS.md 2026-09-11) — this file used to
//! carry that logic directly, but `main.rs` is a separate crate that links
//! the lib externally, so keeping it here forced ~20 internal helpers
//! (persistence/updater loop entry points, `serve`, `AppState`, …) to stay
//! `pub` at the crate root for no reason other than this one file needing
//! them. See `dnsqb_service::orchestrate`'s module doc for the moved code
//! and its own doc comments (unchanged by the move).

#[tokio::main]
async fn main() {
    dnsqb_service::run().await;
}

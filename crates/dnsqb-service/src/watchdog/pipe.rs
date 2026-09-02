//! T-84 — watchdog channel 1 transport: a single duplex named pipe carrying
//! ping/pong frames both directions (SPEC.md §7.1 #1). `dnsqb-service` is the
//! server (longer-lived, always present); `dnsqb-watcher` is the client. Thin
//! I/O only — the frame codec is [`super::frame`]. `#[cfg(windows)]`; the Unix
//! domain-socket half is Фаза 6.

use std::io;
use std::path::Path;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};

use super::frame::{self, Frame, FrameKind, FRAME_LEN};

/// The heartbeat pipe name for the install rooted at `app_data_dir` —
/// `\\.\pipe\dns-quorum-filter\heartbeat-<h>`, `<h>` the shared app-data-dir
/// hash (SPEC.md §7.1 #1), so a scratch instance never shares a pipe with a
/// real one.
pub(crate) fn pipe_name(app_data_dir: &Path) -> String {
    format!(
        r"\\.\pipe\dns-quorum-filter\heartbeat-{}",
        crate::paths::app_data_dir_hash(app_data_dir)
    )
}

/// The server half of the heartbeat pipe (owned by `dnsqb-service`).
pub struct HeartbeatPipeServer {
    name: String,
    pipe: NamedPipeServer,
}

impl HeartbeatPipeServer {
    /// Create the pipe and return a server ready to [`accept`](Self::accept)
    /// its first client.
    ///
    /// # Errors
    ///
    /// Propagates the OS error if the pipe name can't be created — e.g.
    /// another server already owns it.
    pub fn bind(app_data_dir: &Path) -> io::Result<Self> {
        let name = pipe_name(app_data_dir);
        let pipe = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)?;
        Ok(Self { name, pipe })
    }

    /// Wait for a client to connect to the current pipe instance.
    ///
    /// # Errors
    ///
    /// Propagates a connect error.
    pub async fn accept(&mut self) -> io::Result<()> {
        self.pipe.connect().await
    }

    /// Read one frame; if it is a [`FrameKind::Ping`], reply with the matching
    /// [`FrameKind::Pong`]. Returns the frame that was read.
    ///
    /// # Errors
    ///
    /// An I/O error, or [`io::ErrorKind::InvalidData`] if the bytes don't
    /// decode as a frame.
    pub async fn respond_once(&mut self, now_millis: u64) -> io::Result<Frame> {
        let incoming = read_frame(&mut self.pipe).await?;
        if incoming.kind == FrameKind::Ping {
            write_frame(&mut self.pipe, &incoming.pong(now_millis)).await?;
        }
        Ok(incoming)
    }

    /// Drop the current client and open the next pipe instance to wait again.
    /// Every instance after the first must be created with
    /// `first_pipe_instance(false)` or the recreate fails (SPEC.md §7.1 #1) —
    /// this is the path the Батч 3.3 accept loop takes.
    ///
    /// # Errors
    ///
    /// Propagates the OS error if the next instance can't be created.
    pub fn recreate(&mut self) -> io::Result<()> {
        self.pipe = ServerOptions::new()
            .first_pipe_instance(false)
            .create(&self.name)?;
        Ok(())
    }
}

/// The client half of the heartbeat pipe (owned by `dnsqb-watcher`).
pub struct HeartbeatPipeClient {
    pipe: NamedPipeClient,
}

impl HeartbeatPipeClient {
    /// Connect to the heartbeat pipe for the install rooted at `app_data_dir`.
    ///
    /// # Errors
    ///
    /// Propagates the OS error if no server pipe is listening.
    pub fn connect(app_data_dir: &Path) -> io::Result<Self> {
        let pipe = ClientOptions::new().open(pipe_name(app_data_dir))?;
        Ok(Self { pipe })
    }

    /// Send a ping with `seq` / `now_millis` and wait for the pong.
    ///
    /// # Errors
    ///
    /// An I/O error, or [`io::ErrorKind::InvalidData`] if the reply doesn't
    /// decode as a frame.
    pub async fn ping(&mut self, seq: u64, now_millis: u64) -> io::Result<Frame> {
        write_frame(&mut self.pipe, &Frame::ping(seq, now_millis)).await?;
        read_frame(&mut self.pipe).await
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> io::Result<()> {
    w.write_all(&frame::encode(frame)).await?;
    w.flush().await
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Frame> {
    let mut buf = [0u8; FRAME_LEN];
    r.read_exact(&mut buf).await?;
    frame::parse(&buf).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[cfg(test)]
mod tests {
    use super::{pipe_name, HeartbeatPipeClient, HeartbeatPipeServer};
    use crate::watchdog::frame::FrameKind;

    fn temp_dir() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("must be able to create a temp dir: {err}"),
        }
    }

    // Boundary / isolation (§7.1 #1): two app-data directories yield two
    // different pipe names, so a scratch instance never shares a real one's.
    #[test]
    fn pipe_name_is_per_install() {
        let a = temp_dir();
        let b = temp_dir();
        assert_ne!(pipe_name(a.path()), pipe_name(b.path()));
        assert!(pipe_name(a.path()).starts_with(r"\\.\pipe\dns-quorum-filter\heartbeat-"));
    }

    // Happy path + Concurrency: a real server/client ping→pong over the pipe,
    // seq echoed. Recovery: after the first client drops, the server recreates
    // the next instance (the Батч 3.3 loop's path) and a second client works.
    #[tokio::test]
    async fn ping_pong_round_trip_and_recreate_for_the_next_client() {
        let dir = temp_dir();
        let dir_path = dir.path().to_path_buf();
        let mut server = match HeartbeatPipeServer::bind(&dir_path) {
            Ok(server) => server,
            Err(err) => panic!("bind must succeed: {err}"),
        };

        for expected_seq in [1_u64, 2_u64] {
            let client_path = dir_path.clone();
            let client = tokio::spawn(async move {
                let mut client = match HeartbeatPipeClient::connect(&client_path) {
                    Ok(client) => client,
                    Err(err) => panic!("connect must succeed: {err}"),
                };
                match client.ping(expected_seq, 100).await {
                    Ok(pong) => pong,
                    Err(err) => panic!("ping must get a pong: {err}"),
                }
            });

            if let Err(err) = server.accept().await {
                panic!("accept must succeed: {err}");
            }
            let seen = match server.respond_once(200).await {
                Ok(frame) => frame,
                Err(err) => panic!("respond_once must succeed: {err}"),
            };
            assert_eq!(seen.kind, FrameKind::Ping);
            assert_eq!(seen.seq, expected_seq);

            let pong = match client.await {
                Ok(pong) => pong,
                Err(err) => panic!("client task must not panic: {err}"),
            };
            assert_eq!(pong.kind, FrameKind::Pong);
            assert_eq!(pong.seq, expected_seq, "pong echoes the ping seq");

            if expected_seq == 1 {
                if let Err(err) = server.recreate() {
                    panic!("recreate must succeed: {err}");
                }
            }
        }
    }
}

//! `DoH` listener bind (T-21). Real HTTP/TLS serving (the `hyper` listener +
//! the self-signed leaf certificate) is a later batch, gated on T-48 —
//! this is just the "fixed port, explicit conflict error" contract SPEC.md
//! §1 requires.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::net::TcpListener;

/// Errors binding the `DoH` listener.
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    /// `port` is already bound by another process — never silently retried
    /// on a different port (SPEC.md §1).
    #[error("port {0} is already in use")]
    AddrInUse(u16),
    /// Any other OS-level bind failure.
    #[error("failed to bind 127.0.0.1:{port}: {source}")]
    Other {
        /// The port that failed to bind.
        port: u16,
        /// The underlying OS error.
        #[source]
        source: io::Error,
    },
}

/// SPEC.md §1 (T-21): bind the `DoH` listener on `127.0.0.1:<port>` —
/// **never** `0.0.0.0` (hardcoded, not a parameter — an arbitrary bind
/// address is syntactically impossible to request through this function).
/// A port already in use is an explicit error, never a silent fallback to a
/// different port.
///
/// # Errors
///
/// Returns [`BindError::AddrInUse`] if `port` is already bound, or
/// [`BindError::Other`] for any other OS-level bind failure.
pub async fn bind_listener(port: u16) -> Result<TcpListener, BindError> {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    TcpListener::bind(addr).await.map_err(|source| {
        if source.kind() == io::ErrorKind::AddrInUse {
            BindError::AddrInUse(port)
        } else {
            BindError::Other { port, source }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{bind_listener, BindError};

    #[tokio::test]
    async fn binding_an_already_bound_port_is_an_explicit_error_not_a_silent_fallback() {
        // Port 0: ask the OS for a free ephemeral port rather than racing a
        // fixed one.
        let first = match bind_listener(0).await {
            Ok(listener) => listener,
            Err(err) => panic!("first bind on an OS-chosen port must succeed: {err}"),
        };
        let port = match first.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => panic!("bound listener must expose its local address: {err}"),
        };

        // `first` stays alive (holding the port) across this second bind.
        let second = bind_listener(port).await;
        assert!(matches!(second, Err(BindError::AddrInUse(p)) if p == port));
    }
}

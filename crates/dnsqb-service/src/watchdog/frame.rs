//! T-84 — watchdog channel 1 (named-pipe IPC) heartbeat wire format
//! (SPEC.md §7.1 #4). A small fixed frame, not JSON: the watcher is
//! deliberately minimal. Pure — `encode`/`parse` only; the socket I/O that
//! carries these bytes is [`super::pipe`].

/// The frame protocol version this build writes, and the only version it
/// accepts on read.
pub const FRAME_VERSION: u8 = 1;

/// Bytes after the 2-byte `len` field in a v1 frame: `ver(1) + kind(1) +
/// seq(8) + millis(8)`. The `len` field is carried even though every v1 frame
/// is exactly this long so a future v2 with a variable tail can be
/// length-delimited on the same stream without a flag day.
pub const FRAME_BODY_LEN: u16 = 18;

/// Total bytes of an encoded v1 frame, the `len` field included.
pub const FRAME_LEN: usize = 2 + FRAME_BODY_LEN as usize;

/// Ping or pong — the only two message kinds on the heartbeat pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// A liveness probe; the receiver answers with [`FrameKind::Pong`] echoing
    /// the same `seq`.
    Ping,
    /// The answer to a [`FrameKind::Ping`].
    Pong,
}

impl FrameKind {
    const PING: u8 = 1;
    const PONG: u8 = 2;

    fn byte(self) -> u8 {
        match self {
            FrameKind::Ping => Self::PING,
            FrameKind::Pong => Self::PONG,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            Self::PING => Some(FrameKind::Ping),
            Self::PONG => Some(FrameKind::Pong),
            _ => None,
        }
    }
}

/// A decoded heartbeat frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    /// Protocol version — always [`FRAME_VERSION`] for a frame this build
    /// produced or accepted.
    pub version: u8,
    /// Ping or pong.
    pub kind: FrameKind,
    /// Monotonic sequence number chosen by the sender; a pong echoes its
    /// ping's value.
    pub seq: u64,
    /// Sender's wall clock at send time, milliseconds since the Unix epoch.
    pub unix_millis: u64,
}

impl Frame {
    /// A fresh ping with the given sequence number and timestamp.
    #[must_use]
    pub fn ping(seq: u64, unix_millis: u64) -> Self {
        Self {
            version: FRAME_VERSION,
            kind: FrameKind::Ping,
            seq,
            unix_millis,
        }
    }

    /// The pong answering `self` — same `seq`, a new timestamp.
    #[must_use]
    pub fn pong(&self, unix_millis: u64) -> Self {
        Self {
            version: FRAME_VERSION,
            kind: FrameKind::Pong,
            seq: self.seq,
            unix_millis,
        }
    }
}

/// Why [`parse`] rejected a byte slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// Fewer bytes than one whole frame.
    #[error("frame is shorter than the fixed frame length")]
    TooShort,
    /// The `len` field is not [`FRAME_BODY_LEN`], or bytes remain after one
    /// frame.
    #[error("frame length does not match the fixed body length")]
    LengthMismatch,
    /// The version byte is not [`FRAME_VERSION`].
    #[error("unsupported frame version")]
    BadVersion,
    /// The kind byte is neither ping nor pong.
    #[error("unknown frame kind")]
    BadKind,
}

/// Encode `frame` to its [`FRAME_LEN`]-byte wire form.
#[must_use]
pub fn encode(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_LEN);
    out.extend_from_slice(&FRAME_BODY_LEN.to_le_bytes());
    out.push(FRAME_VERSION);
    out.push(frame.kind.byte());
    out.extend_from_slice(&frame.seq.to_le_bytes());
    out.extend_from_slice(&frame.unix_millis.to_le_bytes());
    out
}

/// Parse exactly one frame from `bytes`, which must be exactly [`FRAME_LEN`]
/// bytes.
///
/// # Errors
///
/// See [`FrameError`].
pub fn parse(bytes: &[u8]) -> Result<Frame, FrameError> {
    if bytes.len() < FRAME_LEN {
        return Err(FrameError::TooShort);
    }
    if bytes.len() > FRAME_LEN {
        return Err(FrameError::LengthMismatch);
    }
    // `bytes.len() == FRAME_LEN` is proven by the two guards above, so this
    // conversion never takes its `Err` branch — it stays a `Result` only
    // because `TryInto<[u8; N]>` has no infallible form for a slice.
    let frame: [u8; FRAME_LEN] = bytes.try_into().map_err(|_| FrameError::TooShort)?;

    if u16::from_le_bytes([frame[0], frame[1]]) != FRAME_BODY_LEN {
        return Err(FrameError::LengthMismatch);
    }
    if frame[2] != FRAME_VERSION {
        return Err(FrameError::BadVersion);
    }
    let kind = FrameKind::from_byte(frame[3]).ok_or(FrameError::BadKind)?;
    let seq = u64::from_le_bytes([
        frame[4], frame[5], frame[6], frame[7], frame[8], frame[9], frame[10], frame[11],
    ]);
    let unix_millis = u64::from_le_bytes([
        frame[12], frame[13], frame[14], frame[15], frame[16], frame[17], frame[18], frame[19],
    ]);
    Ok(Frame {
        version: FRAME_VERSION,
        kind,
        seq,
        unix_millis,
    })
}

#[cfg(test)]
mod tests {
    use super::{encode, parse, Frame, FrameError, FrameKind, FRAME_BODY_LEN, FRAME_LEN};

    // Happy path: every frame round-trips, both kinds.
    #[test]
    fn round_trips_ping_and_pong() {
        for frame in [
            Frame::ping(7, 1_700_000_000_123),
            Frame::ping(0, 0).pong(42),
        ] {
            match parse(&encode(&frame)) {
                Ok(decoded) => assert_eq!(decoded, frame),
                Err(err) => panic!("{frame:?} must round-trip, got {err}"),
            }
        }
    }

    // Boundary: extreme field values survive, and an encoded frame is exactly
    // FRAME_LEN with a body-length field of FRAME_BODY_LEN.
    #[test]
    fn boundary_values_and_encoded_length() {
        let frame = Frame::ping(u64::MAX, u64::MAX);
        let bytes = encode(&frame);
        assert_eq!(bytes.len(), FRAME_LEN);
        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), FRAME_BODY_LEN);
        match parse(&bytes) {
            Ok(decoded) => assert_eq!(decoded, frame),
            Err(err) => panic!("max-value frame must round-trip, got {err}"),
        }
    }

    // Misuse & fool: truncation, trailing bytes, bad version, unknown kind.
    #[test]
    fn rejects_truncated_trailing_bad_version_and_unknown_kind() {
        let good = encode(&Frame::ping(1, 1));

        assert_eq!(parse(&good[..FRAME_LEN - 1]), Err(FrameError::TooShort));

        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(parse(&trailing), Err(FrameError::LengthMismatch));

        let mut bad_version = good.clone();
        bad_version[2] = 2;
        assert_eq!(parse(&bad_version), Err(FrameError::BadVersion));

        let mut bad_kind = good.clone();
        bad_kind[3] = 9;
        assert_eq!(parse(&bad_kind), Err(FrameError::BadKind));

        let mut bad_len = good;
        bad_len[0] = bad_len[0].wrapping_add(1);
        assert_eq!(parse(&bad_len), Err(FrameError::LengthMismatch));
    }

    // Error path: an empty slice.
    #[test]
    fn empty_slice_is_too_short() {
        assert_eq!(parse(&[]), Err(FrameError::TooShort));
    }

    // A pong keeps its ping's seq — the property the responder relies on.
    #[test]
    fn pong_echoes_ping_seq() {
        let ping = Frame::ping(123_456, 99);
        assert_eq!(ping.pong(100).seq, ping.seq);
        assert_eq!(ping.pong(100).kind, FrameKind::Pong);
    }
}

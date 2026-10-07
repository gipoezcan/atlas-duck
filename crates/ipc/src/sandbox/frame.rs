//! `u32` big-endian length-delimited frames (spec §3.3).
//!
//! The sync functions serve the single-threaded sandbox worker (§9.3: no other
//! threads, blocking I/O loop). [`codec`] (feature `async`) is the same wire
//! format as a `tokio_util` codec for hosts.

use std::fmt;
use std::io::{self, Read, Write};

use super::MAX_FRAME_BYTES;

/// Length of the frame header: one big-endian `u32`.
const HEADER_LEN: usize = 4;

/// Why [`read_frame`] failed.
#[derive(Debug)]
pub enum FrameError {
    /// The header announces more payload bytes than the caller's limit
    /// (never more than [`MAX_FRAME_BYTES`]). The body was not read.
    TooLarge { len: u64 },
    /// EOF after 1-3 header bytes, or before the announced body was complete.
    Truncated,
    /// Any other I/O error from the reader.
    Io(io::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooLarge { len } => write!(f, "frame of {len} bytes exceeds the limit"),
            FrameError::Truncated => f.write_str("frame truncated by EOF"),
            FrameError::Io(e) => write!(f, "frame I/O error: {e}"),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FrameError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        FrameError::Io(e)
    }
}

/// Writes one frame (4-byte big-endian length, then `payload`) and flushes `w`.
///
/// The flush matters: the worker writes to a buffered stdout, and a frame left
/// in the buffer never reaches the host. A payload above [`MAX_FRAME_BYTES`]
/// is refused with `InvalidInput` before anything is written, because every
/// reader would reject it.
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame payload exceeds MAX_FRAME_BYTES",
        ));
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame payload exceeds u32"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// Reads one frame whose payload is at most `max` bytes (capped at
/// [`MAX_FRAME_BYTES`] whatever the caller passes).
///
/// - `Ok(None)`: clean EOF before the first header byte (the peer closed).
/// - `Err(TooLarge)`: the header announces more than the limit; returned
///   before any body byte is read or any body buffer is allocated.
/// - `Err(Truncated)`: EOF inside the header or the body.
pub fn read_frame<R: Read>(r: &mut R, max: usize) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0u8; HEADER_LEN];
    let mut filled = 0;
    while filled < HEADER_LEN {
        match r.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(FrameError::Io(e)),
        }
    }
    let len = u64::from(u32::from_be_bytes(header));
    let limit = max.min(MAX_FRAME_BYTES) as u64;
    if len > limit {
        return Err(FrameError::TooLarge { len });
    }
    // `len <= MAX_FRAME_BYTES`, so the cast cannot truncate.
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::Truncated
        } else {
            FrameError::Io(e)
        }
    })?;
    Ok(Some(body))
}

/// The same wire format as a `tokio_util` codec: big-endian `u32` length
/// field, no offset or adjustment, payload limit [`MAX_FRAME_BYTES`] (the
/// tokio-util default is 8 MB, so the limit is set explicitly).
#[cfg(feature = "async")]
pub fn codec() -> tokio_util::codec::LengthDelimitedCodec {
    tokio_util::codec::LengthDelimitedCodec::builder()
        .big_endian()
        .length_field_type::<u32>()
        .length_field_offset(0)
        .length_adjustment(0)
        .num_skip(HEADER_LEN)
        .max_frame_length(MAX_FRAME_BYTES)
        .new_codec()
}

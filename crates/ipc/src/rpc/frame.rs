//! Async counterparts of [`crate::sandbox::frame::read_frame`] / `write_frame` over `tokio::io`.
//! The wire format is the M1 one (`u32` big-endian length, then the payload); a test pins the
//! bytes against the sync writer.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::sandbox::MAX_FRAME_BYTES;
pub use crate::sandbox::frame::FrameError;

const HEADER_LEN: usize = 4;

/// Reads one frame whose payload is at most `max` bytes (capped at [`MAX_FRAME_BYTES`]).
///
/// `Ok(None)`: clean EOF before the first header byte. `TooLarge` is returned right after the
/// 4-byte header, before any body byte is read or any body buffer is allocated. `Truncated`:
/// EOF inside the header or the body.
pub async fn read_frame_async<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0u8; HEADER_LEN];
    let mut filled = 0;
    while filled < HEADER_LEN {
        match r.read(&mut header[filled..]).await {
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
    r.read_exact(&mut body).await.map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::Truncated
        } else {
            FrameError::Io(e)
        }
    })?;
    Ok(Some(body))
}

/// Writes one frame and flushes. A payload above [`MAX_FRAME_BYTES`] is refused with
/// `InvalidInput` before anything is written.
pub async fn write_frame_async<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame payload exceeds MAX_FRAME_BYTES",
        ));
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame payload exceeds u32"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await
}

//! §3.3 framing: u32 big-endian length prefix, max frame 24 MiB; §3.4 worker->host 1 MiB.

use std::io::{self, Cursor, Read, Write};

use atlas_duck_ipc::sandbox::frame::{FrameError, read_frame, write_frame};
use atlas_duck_ipc::sandbox::{MAX_FRAME_BYTES, WORKER_FRAME_MAX_BYTES};

fn framed(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_frame(&mut out, payload).unwrap();
    out
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// A reader that serves `data` and counts how many bytes were handed out.
struct CountingReader {
    inner: Cursor<Vec<u8>>,
    served: usize,
}

impl Read for CountingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.served += n;
        Ok(n)
    }
}

/// A writer that records whether `flush` was called after the last write.
#[derive(Default)]
struct FlushTracker {
    bytes: Vec<u8>,
    flushed_after_last_write: bool,
}

impl Write for FlushTracker {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buf);
        self.flushed_after_last_write = false;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushed_after_last_write = true;
        Ok(())
    }
}

#[test]
fn constants_are_the_spec_values() {
    assert_eq!(MAX_FRAME_BYTES, 24 * 1024 * 1024);
    assert_eq!(WORKER_FRAME_MAX_BYTES, 1024 * 1024);
}

#[test]
fn round_trip_0_1_and_70000_bytes() {
    for len in [0usize, 1, 70_000] {
        let payload = pattern(len);
        let bytes = framed(&payload);
        assert_eq!(bytes.len(), 4 + len);
        let mut r = Cursor::new(bytes);
        let got = read_frame(&mut r, MAX_FRAME_BYTES).unwrap();
        assert_eq!(got, Some(payload));
        assert_eq!(read_frame(&mut r, MAX_FRAME_BYTES).unwrap(), None);
    }
}

#[test]
fn header_is_four_bytes_big_endian() {
    assert_eq!(&framed(&pattern(70_000))[..4], &[0x00, 0x01, 0x11, 0x70]);
    assert_eq!(framed(&[]), vec![0, 0, 0, 0]);
    assert_eq!(framed(b"x"), vec![0, 0, 0, 1, b'x']);
}

#[test]
fn back_to_back_frames_are_read_in_order() {
    let mut bytes = framed(b"first");
    bytes.extend(framed(b""));
    bytes.extend(framed(b"third"));
    let mut r = Cursor::new(bytes);
    assert_eq!(read_frame(&mut r, 16).unwrap(), Some(b"first".to_vec()));
    assert_eq!(read_frame(&mut r, 16).unwrap(), Some(Vec::new()));
    assert_eq!(read_frame(&mut r, 16).unwrap(), Some(b"third".to_vec()));
    assert_eq!(read_frame(&mut r, 16).unwrap(), None);
}

#[test]
fn write_frame_flushes_after_the_payload() {
    let mut w = FlushTracker::default();
    write_frame(&mut w, b"probe").unwrap();
    assert!(w.flushed_after_last_write);
    assert_eq!(w.bytes, vec![0, 0, 0, 5, b'p', b'r', b'o', b'b', b'e']);
}

#[test]
fn write_frame_refuses_payload_above_max_and_writes_nothing() {
    let payload = vec![0u8; MAX_FRAME_BYTES + 1];
    let mut out = Vec::new();
    let err = write_frame(&mut out, &payload).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(out.is_empty());
}

#[test]
fn write_frame_accepts_exactly_max() {
    let payload = vec![7u8; MAX_FRAME_BYTES];
    let bytes = framed(&payload);
    assert_eq!(&bytes[..4], &(MAX_FRAME_BYTES as u32).to_be_bytes());
    let got = read_frame(&mut Cursor::new(bytes), MAX_FRAME_BYTES).unwrap();
    assert_eq!(got.map(|v| v.len()), Some(MAX_FRAME_BYTES));
}

#[test]
fn header_above_max_is_too_large_before_any_body_read() {
    // Header only, no body: an implementation that allocated or read the body
    // first would hit EOF and report Truncated instead of TooLarge.
    let header = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec();
    let mut r = CountingReader {
        inner: Cursor::new(header),
        served: 0,
    };
    match read_frame(&mut r, MAX_FRAME_BYTES) {
        Err(FrameError::TooLarge { len }) => assert_eq!(len, (MAX_FRAME_BYTES + 1) as u64),
        other => panic!("expected TooLarge, got {other:?}"),
    }
    assert_eq!(r.served, 4);
}

#[test]
fn caller_max_above_spec_max_is_capped() {
    let header = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec();
    let res = read_frame(&mut Cursor::new(header), usize::MAX);
    assert!(matches!(res, Err(FrameError::TooLarge { .. })));
    let header = u32::MAX.to_be_bytes().to_vec();
    let res = read_frame(&mut Cursor::new(header), usize::MAX);
    assert!(matches!(res, Err(FrameError::TooLarge { len }) if len == u64::from(u32::MAX)));
}

#[test]
fn worker_limit_rejects_one_mib_plus_one_and_accepts_one_mib() {
    let too_big = framed(&vec![1u8; WORKER_FRAME_MAX_BYTES + 1]);
    let res = read_frame(&mut Cursor::new(too_big), WORKER_FRAME_MAX_BYTES);
    assert!(
        matches!(res, Err(FrameError::TooLarge { len }) if len == (WORKER_FRAME_MAX_BYTES + 1) as u64)
    );

    let exact = framed(&vec![1u8; WORKER_FRAME_MAX_BYTES]);
    let got = read_frame(&mut Cursor::new(exact), WORKER_FRAME_MAX_BYTES).unwrap();
    assert_eq!(got.map(|v| v.len()), Some(WORKER_FRAME_MAX_BYTES));
}

#[test]
fn short_body_is_truncated() {
    let mut bytes = framed(b"0123456789");
    bytes.truncate(4 + 3);
    let res = read_frame(&mut Cursor::new(bytes), MAX_FRAME_BYTES);
    assert!(matches!(res, Err(FrameError::Truncated)), "{res:?}");
}

#[test]
fn partial_header_is_truncated() {
    for n in 1..4 {
        let res = read_frame(&mut Cursor::new(vec![0u8; n]), MAX_FRAME_BYTES);
        assert!(
            matches!(res, Err(FrameError::Truncated)),
            "{n} header bytes: {res:?}"
        );
    }
}

#[test]
fn empty_reader_is_clean_eof() {
    let res = read_frame(&mut io::empty(), MAX_FRAME_BYTES);
    assert!(matches!(res, Ok(None)), "{res:?}");
}

#[test]
fn reader_errors_other_than_eof_are_io() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "gone"))
        }
    }
    let res = read_frame(&mut Broken, MAX_FRAME_BYTES);
    assert!(matches!(res, Err(FrameError::Io(e)) if e.kind() == io::ErrorKind::BrokenPipe));
}

#[test]
fn one_byte_at_a_time_reader_still_reads_whole_frames() {
    struct Trickle(Cursor<Vec<u8>>);
    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let end = buf.len().min(1);
            self.0.read(&mut buf[..end])
        }
    }
    let payload = pattern(300);
    let mut r = Trickle(Cursor::new(framed(&payload)));
    assert_eq!(read_frame(&mut r, MAX_FRAME_BYTES).unwrap(), Some(payload));
    assert_eq!(read_frame(&mut r, MAX_FRAME_BYTES).unwrap(), None);
}

#[cfg(feature = "async")]
mod async_codec {
    use super::*;
    use atlas_duck_ipc::sandbox::frame::codec;
    use tokio_util::bytes::{Bytes, BytesMut};
    use tokio_util::codec::{Decoder, Encoder};

    #[test]
    fn write_frame_bytes_decode_with_codec() {
        let mut buf = BytesMut::new();
        for len in [0usize, 1, 70_000] {
            buf.extend_from_slice(&framed(&pattern(len)));
        }
        let mut c = codec();
        for len in [0usize, 1, 70_000] {
            let frame = c
                .decode(&mut buf)
                .unwrap()
                .expect("a whole frame is buffered");
            assert_eq!(&frame[..], &pattern(len)[..]);
        }
        assert!(c.decode(&mut buf).unwrap().is_none());
        assert!(buf.is_empty());
    }

    #[test]
    fn codec_output_is_byte_identical_to_write_frame() {
        for len in [0usize, 1, 70_000] {
            let payload = pattern(len);
            let mut encoded = BytesMut::new();
            codec()
                .encode(Bytes::from(payload.clone()), &mut encoded)
                .unwrap();
            assert_eq!(&encoded[..], &framed(&payload)[..], "len {len}");
        }
    }

    #[test]
    fn codec_rejects_max_plus_one_on_decode_and_encode() {
        let mut header = BytesMut::from(&((MAX_FRAME_BYTES + 1) as u32).to_be_bytes()[..]);
        let err = codec().decode(&mut header).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut out = BytesMut::new();
        let too_big = Bytes::from(vec![0u8; MAX_FRAME_BYTES + 1]);
        assert!(codec().encode(too_big, &mut out).is_err());
    }

    #[test]
    fn codec_accepts_exactly_max() {
        let mut buf = BytesMut::from(&framed(&vec![9u8; MAX_FRAME_BYTES])[..]);
        let frame = codec().decode(&mut buf).unwrap().expect("whole frame");
        assert_eq!(frame.len(), MAX_FRAME_BYTES);
    }
}

#[test]
fn ipc_without_default_features_has_no_tokio() {
    // §3.3/§9.3: the worker build (ipc with default-features = false) stays tokio-free.
    let out = std::process::Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "tree",
            "-p",
            "atlas-duck-ipc",
            "--no-default-features",
            "-e",
            "normal",
            "--prefix",
            "none",
            "--locked",
        ])
        .output()
        .expect("run cargo tree");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tree = String::from_utf8(out.stdout).expect("utf-8 cargo tree output");
    assert!(
        tree.lines().any(|l| l.starts_with("atlas-duck-ipc ")),
        "{tree}"
    );
    let tokio: Vec<&str> = tree.lines().filter(|l| l.starts_with("tokio")).collect();
    assert!(
        tokio.is_empty(),
        "tokio in the worker-facing ipc build: {tokio:?}"
    );
}

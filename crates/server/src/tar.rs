//! The export download (M14 PD-256): one uncompressed POSIX ustar stream of regular files, mode
//! 0600, mtime the export time, written by hand (no archive crate). A name longer than 100 bytes
//! is split at a `/` into ustar's `prefix` (155 bytes) and `name` (100 bytes); one that cannot be
//! split is refused. A file is at most 8 GiB - 1 (11 octal digits). The stream reads each file in
//! 64 KiB pieces and ends with two zero blocks; an `on_end` future runs only after the last block
//! was handed out (a client that disconnects never reaches it).

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use axum::body::Bytes;
use futures::Stream;
use tokio::io::AsyncReadExt;

pub const BLOCK: usize = 512;
/// The largest size an 11-digit octal field holds.
pub const MAX_FILE: u64 = 0o77_777_777_777;
const CHUNK: usize = 64 * 1024;

/// One archive member: its name in the archive and the file it comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarError {
    /// The name does not fit ustar's `prefix` + `name` (or is empty, or not ASCII).
    Name,
    /// The file is larger than [`MAX_FILE`].
    TooLarge,
}

fn octal(field: &mut [u8], v: u64) {
    // `width - 1` digits, NUL-terminated.
    let digits = field.len() - 1;
    let s = format!("{v:0digits$o}");
    field[..digits].copy_from_slice(&s.as_bytes()[s.len() - digits..]);
    field[digits] = 0;
}

/// `(prefix, name)` for a path name.
fn split(name: &str) -> Result<(&str, &str), TarError> {
    if name.is_empty() || !name.is_ascii() || name.contains('\0') {
        return Err(TarError::Name);
    }
    if name.len() <= 100 {
        return Ok(("", name));
    }
    // The rightmost `/` that leaves at most 100 bytes after it and 155 before it.
    for (i, _) in name.match_indices('/').rev() {
        let (prefix, rest) = (&name[..i], &name[i + 1..]);
        if rest.len() > 100 {
            break;
        }
        if !rest.is_empty() && !prefix.is_empty() && prefix.len() <= 155 {
            return Ok((prefix, rest));
        }
    }
    Err(TarError::Name)
}

/// The 512-byte ustar header of a regular file.
pub fn header(name: &str, size: u64, mtime: u64) -> Result<[u8; BLOCK], TarError> {
    if size > MAX_FILE {
        return Err(TarError::TooLarge);
    }
    let (prefix, base) = split(name)?;
    let mut h = [0u8; BLOCK];
    h[..base.len()].copy_from_slice(base.as_bytes());
    octal(&mut h[100..108], 0o600);
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], mtime.min(MAX_FILE));
    h[148..156].fill(b' ');
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
    let s = format!("{sum:06o}");
    h[148..154].copy_from_slice(&s.as_bytes()[s.len() - 6..]);
    h[154] = 0;
    h[155] = b' ';
    Ok(h)
}

fn padded(size: u64) -> u64 {
    size.div_ceil(BLOCK as u64) * BLOCK as u64
}

/// The archive's length: a header and the padded data per entry, then two zero blocks.
pub fn archive_len(entries: &[Entry]) -> u64 {
    entries
        .iter()
        .map(|e| BLOCK as u64 + padded(e.size))
        .sum::<u64>()
        + 2 * BLOCK as u64
}

/// Checks every header can be written (before a response starts).
pub fn check(entries: &[Entry]) -> Result<(), TarError> {
    entries
        .iter()
        .try_for_each(|e| header(&e.name, e.size, 0).map(|_| ()))
}

type OnEnd = Pin<Box<dyn Future<Output = ()> + Send>>;

enum State {
    /// The next entry's header.
    Header(usize),
    /// Reading entry `i`; `left` bytes of its declared size remain.
    Data {
        i: usize,
        file: tokio::fs::File,
        left: u64,
    },
    /// The two zero blocks.
    Trailer,
    Done,
}

struct Tar {
    entries: Vec<Entry>,
    mtime: u64,
    state: State,
    on_end: Option<OnEnd>,
}

fn io_err(what: &str) -> std::io::Error {
    std::io::Error::other(what.to_owned())
}

/// The archive of `entries` as a byte stream. A file that changed size since `entries` was made
/// ends the stream with an error (the response is then cut short, never padded silently).
pub fn stream(
    entries: Vec<Entry>,
    mtime: u64,
    on_end: OnEnd,
) -> impl Stream<Item = std::io::Result<Bytes>> + Send {
    let tar = Tar {
        entries,
        mtime,
        state: State::Header(0),
        on_end: Some(on_end),
    };
    futures::stream::unfold(tar, |mut t| async move {
        let out = step(&mut t).await;
        out.map(|o| (o, t))
    })
}

async fn step(t: &mut Tar) -> Option<std::io::Result<Bytes>> {
    loop {
        match std::mem::replace(&mut t.state, State::Done) {
            State::Header(i) => {
                let Some(e) = t.entries.get(i) else {
                    t.state = State::Trailer;
                    continue;
                };
                let h = match header(&e.name, e.size, t.mtime) {
                    Ok(h) => h,
                    Err(_) => return Some(Err(io_err("an archive name does not fit"))),
                };
                let file = match tokio::fs::File::open(&e.path).await {
                    Ok(f) => f,
                    Err(e) => return Some(Err(e)),
                };
                t.state = State::Data {
                    i,
                    file,
                    left: e.size,
                };
                return Some(Ok(Bytes::copy_from_slice(&h)));
            }
            State::Data { i, mut file, left } => {
                if left == 0 {
                    // The file must end here, then the padding.
                    let mut probe = [0u8; 1];
                    match file.read(&mut probe).await {
                        Ok(0) => {}
                        Ok(_) => return Some(Err(io_err("a file grew during the download"))),
                        Err(e) => return Some(Err(e)),
                    }
                    t.state = State::Header(i + 1);
                    let size = t.entries.get(i).map_or(0, |e| e.size);
                    let pad = padded(size) - size;
                    if pad > 0 {
                        return Some(Ok(Bytes::from(vec![0u8; pad as usize])));
                    }
                    continue;
                }
                let want = usize::try_from(left).unwrap_or(CHUNK).min(CHUNK);
                let mut buf = vec![0u8; want];
                let n = match file.read(&mut buf).await {
                    Ok(0) => return Some(Err(io_err("a file shrank during the download"))),
                    Ok(n) => n,
                    Err(e) => return Some(Err(e)),
                };
                buf.truncate(n);
                t.state = State::Data {
                    i,
                    file,
                    left: left - n as u64,
                };
                return Some(Ok(Bytes::from(buf)));
            }
            State::Trailer => {
                t.state = State::Done;
                return Some(Ok(Bytes::from(vec![0u8; 2 * BLOCK])));
            }
            State::Done => {
                if let Some(f) = t.on_end.take() {
                    f.await;
                }
                return None;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(crate) mod tests {
    use super::*;
    use futures::StreamExt;
    use proptest::prelude::*;

    /// A hand-written ustar reader (tests): `(name, mode, size, mtime, data)` per member; checks
    /// the magic, the checksum and the two zero blocks at the end.
    pub(crate) fn read(archive: &[u8]) -> Vec<(String, u64, u64, u64, Vec<u8>)> {
        let field = |h: &[u8], a: usize, b: usize| {
            let s = &h[a..b];
            let end = s.iter().position(|c| *c == 0).unwrap_or(s.len());
            String::from_utf8(s[..end].to_vec()).unwrap()
        };
        let num =
            |h: &[u8], a: usize, b: usize| u64::from_str_radix(field(h, a, b).trim(), 8).unwrap();
        assert_eq!(archive.len() % BLOCK, 0);
        let mut out = Vec::new();
        let mut at = 0;
        loop {
            let h = &archive[at..at + BLOCK];
            if h.iter().all(|b| *b == 0) {
                assert!(archive[at..].iter().all(|b| *b == 0));
                assert_eq!(
                    archive.len() - at,
                    2 * BLOCK,
                    "two zero blocks end the archive"
                );
                break;
            }
            assert_eq!(&h[257..263], b"ustar\0");
            assert_eq!(&h[263..265], b"00");
            assert_eq!(h[156], b'0', "regular file");
            let mut copy = h.to_vec();
            copy[148..156].fill(b' ');
            let sum: u64 = copy.iter().map(|b| u64::from(*b)).sum();
            assert_eq!(num(h, 148, 155), sum, "checksum");
            let prefix = field(h, 345, 500);
            let base = field(h, 0, 100);
            let name = if prefix.is_empty() {
                base
            } else {
                format!("{prefix}/{base}")
            };
            let size = num(h, 124, 136);
            let data_at = at + BLOCK;
            let data = archive[data_at..data_at + size as usize].to_vec();
            out.push((name, num(h, 100, 108), size, num(h, 136, 148), data));
            at = data_at + padded(size) as usize;
        }
        out
    }

    async fn collect(entries: Vec<Entry>, mtime: u64) -> (Vec<u8>, bool) {
        let ended = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = ended.clone();
        let s = stream(
            entries,
            mtime,
            Box::pin(async move { flag.store(true, std::sync::atomic::Ordering::SeqCst) }),
        );
        let chunks: Vec<_> = s.collect().await;
        let mut out = Vec::new();
        for c in chunks {
            out.extend_from_slice(&c.unwrap());
        }
        (out, ended.load(std::sync::atomic::Ordering::SeqCst))
    }

    #[tokio::test]
    async fn an_archive_round_trips_through_the_reader() {
        let dir = tempfile::tempdir().unwrap();
        let mut entries = Vec::new();
        for (name, len) in [
            ("a.txt", 0usize),
            ("b.bin", 511),
            ("c.bin", 512),
            ("d", 70_000),
        ] {
            let p = dir.path().join(name);
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            std::fs::write(&p, &data).unwrap();
            entries.push(Entry {
                name: format!("atlas-duck-export-{}/{name}", "x".repeat(90)),
                path: p,
                size: len as u64,
            });
        }
        let want_len = archive_len(&entries);
        let (bytes, ended) = collect(entries.clone(), 1_790_000_000).await;
        assert!(ended, "on_end runs after the last block");
        assert_eq!(bytes.len() as u64, want_len);
        let members = read(&bytes);
        assert_eq!(members.len(), 4);
        for ((name, mode, size, mtime, data), e) in members.iter().zip(&entries) {
            assert_eq!(name, &e.name);
            assert_eq!((*mode, *size, *mtime), (0o600, e.size, 1_790_000_000));
            assert_eq!(data, &std::fs::read(&e.path).unwrap());
        }
    }

    #[tokio::test]
    async fn a_file_that_changed_size_ends_the_stream_with_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"0123456789").unwrap();
        for declared in [5u64, 20] {
            let e = vec![Entry {
                name: "f".into(),
                path: p.clone(),
                size: declared,
            }];
            let s = stream(e, 0, Box::pin(async {}));
            let chunks: Vec<_> = s.collect().await;
            assert!(chunks.iter().any(Result::is_err), "declared {declared}");
        }
    }

    #[test]
    fn names_that_do_not_fit_and_oversized_files_are_refused() {
        assert_eq!(header("", 0, 0), Err(TarError::Name));
        assert_eq!(header(&"n".repeat(101), 0, 0), Err(TarError::Name));
        assert_eq!(
            header(&format!("{}/{}", "p".repeat(156), "n"), 0, 0),
            Err(TarError::Name)
        );
        assert_eq!(header("ü", 0, 0), Err(TarError::Name));
        assert_eq!(header("a", MAX_FILE + 1, 0), Err(TarError::TooLarge));
        assert!(
            header(
                &format!("{}/{}", "p".repeat(155), "n".repeat(100)),
                MAX_FILE,
                0
            )
            .is_ok()
        );
        assert!(
            check(&[Entry {
                name: "x".repeat(101),
                path: PathBuf::new(),
                size: 0
            }])
            .is_err()
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        /// Headers round-trip names (split or not) and sizes; the checksum is valid.
        #[test]
        fn headers_round_trip(
            dir in "[a-z0-9-]{1,140}",
            file in "[a-z0-9._-]{1,60}",
            size in 0u64..=MAX_FILE,
            mtime in 0u64..=MAX_FILE,
        ) {
            let name = format!("{dir}/{file}");
            let h = header(&name, size, mtime).unwrap();
            // A one-member archive without data: header and size fields only.
            let mut a = h.to_vec();
            a.extend_from_slice(&[0u8; 2 * BLOCK]);
            let field = |x: &[u8]| {
                let end = x.iter().position(|c| *c == 0).unwrap_or(x.len());
                String::from_utf8(x[..end].to_vec()).unwrap()
            };
            let prefix = field(&h[345..500]);
            let base = field(&h[..100]);
            let back = if prefix.is_empty() { base } else { format!("{prefix}/{base}") };
            prop_assert_eq!(back, name);
            prop_assert_eq!(u64::from_str_radix(&field(&h[124..136]), 8).unwrap(), size);
            prop_assert_eq!(u64::from_str_radix(&field(&h[136..148]), 8).unwrap(), mtime);
            let mut copy = h.to_vec();
            copy[148..156].fill(b' ');
            let sum: u64 = copy.iter().map(|b| u64::from(*b)).sum();
            prop_assert_eq!(u64::from_str_radix(&field(&h[148..155]), 8).unwrap(), sum);
            if size == 0 {
                prop_assert_eq!(read(&a).len(), 1);
            }
        }
    }
}

//! A minimal ustar writer and reader for `admin backup --stdout` and `admin restore --stdin`
//! (lead decision after batch 3): a bundle directory travels as a tar stream through
//! `kubectl exec`, so the distroless image needs no `tar` and no debug container. Regular files
//! and directories only; the reader refuses links, absolute paths and `..`, and every file is
//! checked again against the bundle's manifest by the restore itself.

use std::path::{Path, PathBuf};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::backup::safe_rel;

const BLOCK: usize = 512;

fn octal(field: &mut [u8], value: u64) {
    let width = field.len() - 1;
    let text = format!("{value:0width$o}");
    let bytes = text.as_bytes();
    let start = bytes.len().saturating_sub(width);
    field[..width].copy_from_slice(&bytes[start..]);
    field[width] = 0;
}

/// One ustar header for `name` (`/`-separated, relative).
pub(crate) fn header(name: &str, size: u64, dir: bool) -> std::io::Result<[u8; BLOCK]> {
    let mut h = [0u8; BLOCK];
    let (prefix, base) = if name.len() <= 100 {
        ("", name)
    } else {
        // Split at a '/' so that prefix <= 155 and name <= 100.
        let cut = name[..name.len().min(156)]
            .rfind('/')
            .filter(|&i| name.len() - i - 1 <= 100)
            .ok_or_else(|| std::io::Error::other("path too long for ustar"))?;
        (&name[..cut], &name[cut + 1..])
    };
    h[..base.len()].copy_from_slice(base.as_bytes());
    octal(&mut h[100..108], if dir { 0o755 } else { 0o644 });
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], 0);
    h[156] = if dir { b'5' } else { b'0' };
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    let text = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(text.as_bytes());
    Ok(h)
}

fn walk(root: &Path, rel: &Path, out: &mut Vec<(PathBuf, bool)>) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(root.join(rel))?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let r = rel.join(e.file_name());
        let ty = e.file_type()?;
        if ty.is_dir() {
            out.push((r.clone(), true));
            walk(root, &r, out)?;
        } else if ty.is_file() {
            out.push((r, false));
        }
    }
    Ok(())
}

fn tar_name(top: &str, rel: &Path) -> String {
    std::iter::once(top.to_owned())
        .chain(
            rel.components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned()),
        )
        .collect::<Vec<_>>()
        .join("/")
}

/// The exact byte length [`write_dir`] will produce for `root` (the stream's announced size).
pub fn tar_size(root: &Path) -> std::io::Result<u64> {
    let mut entries = Vec::new();
    walk(root, Path::new(""), &mut entries)?;
    let mut n = BLOCK as u64; // the top directory
    for (rel, dir) in entries {
        n += BLOCK as u64;
        if !dir {
            let size = std::fs::metadata(root.join(rel))?.len();
            n += size.div_ceil(BLOCK as u64) * BLOCK as u64;
        }
    }
    Ok(n + 2 * BLOCK as u64)
}

/// Writes the directory `root` as `top/...` into `w`, then the end-of-archive blocks. Answers
/// the byte count and the SHA-256 of everything written (final review I1: the stream's trailer).
pub async fn write_dir<W: AsyncWrite + Unpin>(
    w: &mut W,
    root: &Path,
    top: &str,
) -> std::io::Result<(u64, [u8; 32])> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let mut n = 0u64;
    let mut put = |chunk: &[u8], h: &mut Sha256| {
        h.update(chunk);
        n += chunk.len() as u64;
    };
    let mut entries = Vec::new();
    walk(root, Path::new(""), &mut entries)?;
    let first = header(&format!("{top}/"), 0, true)?;
    put(&first, &mut h);
    w.write_all(&first).await?;
    let mut buf = vec![0u8; 64 * 1024];
    for (rel, dir) in entries {
        let name = tar_name(top, &rel);
        if dir {
            let hd = header(&format!("{name}/"), 0, true)?;
            put(&hd, &mut h);
            w.write_all(&hd).await?;
            continue;
        }
        let mut f = tokio::fs::File::open(root.join(&rel)).await?;
        let size = f.metadata().await?.len();
        let hd = header(&name, size, false)?;
        put(&hd, &mut h);
        w.write_all(&hd).await?;
        let mut left = size;
        while left > 0 {
            let want = buf.len().min(usize::try_from(left).unwrap_or(buf.len()));
            let got = f.read(&mut buf[..want]).await?;
            if got == 0 {
                return Err(std::io::Error::other("file changed while streaming"));
            }
            put(&buf[..got], &mut h);
            w.write_all(&buf[..got]).await?;
            left -= got as u64;
        }
        let pad = vec![0u8; (BLOCK - (size as usize % BLOCK)) % BLOCK];
        put(&pad, &mut h);
        w.write_all(&pad).await?;
    }
    let end = [0u8; 2 * BLOCK];
    put(&end, &mut h);
    w.write_all(&end).await?;
    w.flush().await?;
    Ok((n, h.finalize().into()))
}

/// Final review M3: a stream that goes quiet this long is abandoned (its lock is released).
pub const STREAM_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

async fn read_exact_t<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> Result<(), &'static str> {
    tokio::time::timeout(STREAM_IDLE, r.read_exact(buf))
        .await
        .map_err(|_| "restore/stream_idle")?
        .map(drop)
        .map_err(|_| "restore/stream_invalid")
}
fn field_str(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn parse_octal(b: &[u8]) -> Option<u64> {
    let s = field_str(b);
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(s, 8).ok()
}

/// Reads a tar stream into `dest` (which must not exist yet), at most `max_bytes` of file data.
/// Answers the single top-level directory the archive holds (the bundle).
pub async fn read_into<R: AsyncRead + Unpin>(
    r: &mut R,
    dest: &Path,
    max_bytes: u64,
) -> Result<PathBuf, &'static str> {
    let bad = "restore/stream_invalid";
    std::fs::create_dir(dest).map_err(|_| "restore/stage_failed")?;
    let mut top: Option<String> = None;
    let mut total = 0u64;
    loop {
        let mut h = [0u8; BLOCK];
        read_exact_t(r, &mut h).await?;
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let stored: u32 = parse_octal(&h[148..156]).ok_or(bad)? as u32;
        let mut copy = h;
        copy[148..156].copy_from_slice(b"        ");
        let sum: u32 = copy.iter().map(|&b| u32::from(b)).sum();
        if sum != stored {
            return Err(bad);
        }
        let name = {
            let base = field_str(&h[..100]);
            let prefix = field_str(&h[345..500]);
            if prefix.is_empty() {
                base
            } else {
                format!("{prefix}/{base}")
            }
        };
        let size = parse_octal(&h[124..136]).ok_or(bad)?;
        let kind = h[156];
        let trimmed = name.trim_end_matches('/');
        let rel = safe_rel(trimmed).ok_or(bad)?;
        let first = rel
            .components()
            .next()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .ok_or(bad)?;
        match &top {
            None => top = Some(first),
            Some(t) if *t == first => {}
            Some(_) => return Err(bad),
        }
        let path = dest.join(&rel);
        match kind {
            b'5' => std::fs::create_dir_all(&path).map_err(|_| "restore/stage_failed")?,
            b'0' | 0 => {
                total = total.saturating_add(size);
                if total > max_bytes {
                    return Err("restore/stream_too_large");
                }
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|_| "restore/stage_failed")?;
                }
                let mut f = tokio::fs::File::create(&path)
                    .await
                    .map_err(|_| "restore/stage_failed")?;
                let mut left = size;
                let mut buf = vec![0u8; 64 * 1024];
                while left > 0 {
                    let want = buf.len().min(usize::try_from(left).unwrap_or(buf.len()));
                    let got = tokio::time::timeout(STREAM_IDLE, r.read(&mut buf[..want]))
                        .await
                        .map_err(|_| "restore/stream_idle")?
                        .map_err(|_| bad)?;
                    if got == 0 {
                        return Err(bad);
                    }
                    f.write_all(&buf[..got])
                        .await
                        .map_err(|_| "restore/stage_failed")?;
                    left -= got as u64;
                }
                f.sync_all().await.map_err(|_| "restore/stage_failed")?;
                let pad = (BLOCK - (size as usize % BLOCK)) % BLOCK;
                let mut skip = vec![0u8; pad];
                read_exact_t(r, &mut skip).await?;
            }
            // Links, devices and anything else are refused.
            _ => return Err(bad),
        }
    }
    let top = top.ok_or(bad)?;
    Ok(dest.join(top))
}

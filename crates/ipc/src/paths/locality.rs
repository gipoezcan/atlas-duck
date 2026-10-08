//! §7.7 "Local filesystem only, enforced": the per-OS local-filesystem check.
//!
//! Linux: `statfs` `f_type` against the network/FUSE types (§15 V29 open).
//! macOS: `statfs` `f_flags & MNT_LOCAL`.
//! Windows: UNC paths refused before any API call, then `GetDriveTypeW` on
//! the volume root (`GetVolumePathNameW`, long-path aware).
//!
//! The classifiers are pure and compiled on every OS so the tables are
//! tested everywhere; only `check_locality` touches the OS.

use std::io;
use std::path::Path;

/// Result of the local-filesystem check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locality {
    Local,
    NotLocal(NotLocalKind),
}

/// Why a path counts as not local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotLocalKind {
    /// Windows UNC or `\\?\UNC\` path (refused before any API call).
    Unc,
    /// Windows `GetDriveTypeW` == `DRIVE_REMOTE` (mapped network drive).
    RemoteDrive,
    /// Windows `GetDriveTypeW` == `DRIVE_UNKNOWN` / `DRIVE_NO_ROOT_DIR`, an
    /// unknown drive type, or a `\\.\` device-namespace path.
    UnknownDrive,
    /// Linux network filesystem; `f_type` is the 32-bit `statfs` magic.
    NetworkFs { f_type: u64 },
    /// Linux FUSE mount (any FUSE filesystem, sshfs included; fail-closed).
    Fuse,
    /// macOS `statfs` without `MNT_LOCAL`.
    NotMntLocal,
    /// Linux overlayfs whose layers could not be resolved through
    /// `/proc/self/mountinfo` (unreadable, no matching mount, a layer that
    /// cannot be examined or nesting that is too deep). Fail-closed.
    OverlayUnresolved,
}

// Linux `f_type` magics, copied from include/uapi/linux/magic.h and statfs(2)
// (Lustre from coreutils src/stat.c). Not yet verified against live mounts
// (§15 V29): T22 records what the CI mounts report.
const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;
const NFS_SUPER_MAGIC: u64 = 0x6969;
const SMB_SUPER_MAGIC: u64 = 0x517B;
const CIFS_SUPER_MAGIC: u64 = 0xFF53_4D42;
const SMB2_SUPER_MAGIC: u64 = 0xFE53_4D42;
const AFS_SUPER_MAGIC: u64 = 0x5346_414F;
const AFS_FS_MAGIC: u64 = 0x6B41_4653; // kAFS
const CEPH_SUPER_MAGIC: u64 = 0x00C3_6400;
const LUSTRE_SUPER_MAGIC: u64 = 0x0BD0_0BD0;
const V9FS_MAGIC: u64 = 0x0102_1997;
const GFS2_MAGIC: u64 = 0x0116_1970;
const OCFS2_SUPER_MAGIC: u64 = 0x7461_636F;
const CODA_SUPER_MAGIC: u64 = 0x7375_7245;
const NCP_SUPER_MAGIC: u64 = 0x564C;
const PANFS_SUPER_MAGIC: u64 = 0xAAD7_AAEA;
const VBOXSF_SUPER_MAGIC: u64 = 0x786F_4256;
/// overlayfs: local only if every layer is (see [`overlay_layer_paths`]).
pub const OVERLAYFS_SUPER_MAGIC: u64 = 0x794C_7630;

/// The network and cluster filesystems of §15 ("at least NFS, SMB/CIFS/SMB2,
/// AFS, Ceph, Lustre, 9p"), plus GFS2, OCFS2, Coda, NCP, PanFS and VirtualBox
/// shared folders. FUSE is handled separately (always non-local; virtiofs
/// reports the FUSE magic). overlayfs is resolved through its layers.
const LINUX_NETWORK_F_TYPES: &[u64] = &[
    NFS_SUPER_MAGIC,
    SMB_SUPER_MAGIC,
    CIFS_SUPER_MAGIC,
    SMB2_SUPER_MAGIC,
    AFS_SUPER_MAGIC,
    AFS_FS_MAGIC,
    CEPH_SUPER_MAGIC,
    LUSTRE_SUPER_MAGIC,
    V9FS_MAGIC,
    GFS2_MAGIC,
    OCFS2_SUPER_MAGIC,
    CODA_SUPER_MAGIC,
    NCP_SUPER_MAGIC,
    PANFS_SUPER_MAGIC,
    VBOXSF_SUPER_MAGIC,
];

/// Classifies a Linux `statfs` `f_type`. Only the low 32 bits are compared
/// (on 32-bit targets `f_type` is a sign-extended `i32`). Unknown types are
/// local (plan decision: the spec lists only network/FUSE types). overlayfs is
/// reported local here; `check_locality` then looks at its layers.
pub fn classify_linux_f_type(f_type: u64) -> Locality {
    let magic = f_type & 0xFFFF_FFFF;
    if magic == FUSE_SUPER_MAGIC {
        Locality::NotLocal(NotLocalKind::Fuse)
    } else if LINUX_NETWORK_F_TYPES.contains(&magic) {
        Locality::NotLocal(NotLocalKind::NetworkFs { f_type: magic })
    } else {
        Locality::Local
    }
}

/// Linux: the layer directories of the overlayfs mount that contains `path`,
/// read from the text of `/proc/self/mountinfo`. `path` must be absolute and
/// canonical. The mount is the one with the longest mount point that is a
/// path-prefix of `path` (the last such line wins, later mounts shadow
/// earlier ones). Returns the `lowerdir`, `lowerdir+`, `datadir+` and
/// `upperdir` entries of its super options, octal escapes decoded.
///
/// `None` when no mount covers `path`, the covering mount is not an overlay,
/// or it names no layer: the caller treats that as not local (fail-closed).
/// Pure text parsing, compiled and tested on every OS.
pub fn overlay_layer_paths(mountinfo: &str, path: &str) -> Option<Vec<String>> {
    let mut best: Option<(usize, Option<Vec<String>>)> = None;
    for line in mountinfo.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        // id parent major:minor root mount_point options [optional...] - fstype source super_options
        let Some(dash) = tokens.iter().skip(6).position(|t| *t == "-").map(|i| i + 6) else {
            continue;
        };
        if tokens.len() < dash + 3 {
            continue;
        }
        let mount_point = unescape_mountinfo(tokens[4]);
        if !is_path_prefix(&mount_point, path) {
            continue;
        }
        if best
            .as_ref()
            .is_some_and(|(len, _)| mount_point.len() < *len)
        {
            continue;
        }
        let layers =
            (tokens[dash + 1] == "overlay").then(|| overlay_layers(&tokens[dash + 3..].join(" ")));
        best = Some((mount_point.len(), layers));
    }
    best.and_then(|(_, layers)| layers)
        .filter(|l| !l.is_empty())
}

/// `mount_point` is `path` or one of its ancestors (component-wise).
fn is_path_prefix(mount_point: &str, path: &str) -> bool {
    let mp = mount_point.trim_end_matches('/');
    mp.is_empty()
        || path == mp
        || path
            .strip_prefix(mp)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The layer directories named by overlay super options (`k=v,k=v,...`).
fn overlay_layers(super_options: &str) -> Vec<String> {
    let mut out = Vec::new();
    for opt in super_options.split(',') {
        let Some((key, value)) = opt.split_once('=') else {
            continue;
        };
        if matches!(key, "lowerdir" | "lowerdir+" | "datadir+" | "upperdir") {
            // `lowerdir=a:b:c`; `::` introduces data-only layers, so empty parts are skipped.
            out.extend(
                value
                    .split(':')
                    .filter(|p| !p.is_empty())
                    .map(unescape_mountinfo),
            );
        }
    }
    out
}

/// Decodes the `\NNN` octal escapes (space, tab, newline, backslash, comma,
/// equals) that the kernel writes into mountinfo and option values.
fn unescape_mountinfo(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (u32::from(b[i + 1] - b'0') << 6)
                | (u32::from(b[i + 2] - b'0') << 3)
                | u32::from(b[i + 3] - b'0');
            out.push((v & 0xFF) as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// macOS `MNT_LOCAL` (sys/mount.h; `libc::MNT_LOCAL` = 0x0000_1000).
pub const MACOS_MNT_LOCAL: u64 = 0x0000_1000;

/// Classifies a macOS `statfs` `f_flags` value.
pub fn classify_macos_mnt_flags(f_flags: u64) -> Locality {
    if f_flags & MACOS_MNT_LOCAL != 0 {
        Locality::Local
    } else {
        Locality::NotLocal(NotLocalKind::NotMntLocal)
    }
}

/// `GetDriveTypeW` return values (WinBase.h), defined here so the
/// classifier compiles and is tested on every OS.
pub mod win_drive_type {
    pub const DRIVE_UNKNOWN: u32 = 0;
    pub const DRIVE_NO_ROOT_DIR: u32 = 1;
    pub const DRIVE_REMOVABLE: u32 = 2;
    pub const DRIVE_FIXED: u32 = 3;
    pub const DRIVE_REMOTE: u32 = 4;
    pub const DRIVE_CDROM: u32 = 5;
    pub const DRIVE_RAMDISK: u32 = 6;
}

/// Classifies a Windows `GetDriveTypeW` result. `DRIVE_UNKNOWN`,
/// `DRIVE_NO_ROOT_DIR` and any value outside WinBase.h are not local
/// (plan decision, fail-closed).
pub fn classify_windows_drive_type(drive_type: u32) -> Locality {
    use win_drive_type::*;
    match drive_type {
        DRIVE_FIXED | DRIVE_REMOVABLE | DRIVE_CDROM | DRIVE_RAMDISK => Locality::Local,
        DRIVE_REMOTE => Locality::NotLocal(NotLocalKind::RemoteDrive),
        _ => Locality::NotLocal(NotLocalKind::UnknownDrive),
    }
}

/// Checks whether `path` is on a local filesystem. Symlinks are followed
/// (a local link into a network mount is not local). On Linux and macOS a
/// missing path is an error. On Windows a UNC or device path is refused
/// without touching the OS, and a drive letter with no volume behind it
/// returns `UnknownDrive` before the existence check; any other missing
/// path is an error.
pub fn check_locality(path: &Path) -> io::Result<Locality> {
    os::check(path)
}

/// Windows only: classifies a path by its prefix alone (no OS call).
/// `\\server\share`, `\\?\UNC\server\share` and `\\.\UNC\…` are UNC; any
/// other `\\.\` device path is an unknown drive.
#[cfg(windows)]
pub(crate) fn windows_prefix_refusal(path: &Path) -> Option<NotLocalKind> {
    use std::path::{Component, Prefix};
    match path.components().next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::UNC(..) | Prefix::VerbatimUNC(..) => Some(NotLocalKind::Unc),
            Prefix::DeviceNS(name) if name.eq_ignore_ascii_case("UNC") => Some(NotLocalKind::Unc),
            Prefix::DeviceNS(_) => Some(NotLocalKind::UnknownDrive),
            _ => None,
        },
        _ => None,
    }
}

/// Non-Windows: no path prefix is refused before the OS check.
#[cfg(not(windows))]
pub(crate) fn windows_prefix_refusal(_path: &Path) -> Option<NotLocalKind> {
    None
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod os {
    use super::{
        Locality, NotLocalKind, OVERLAYFS_SUPER_MAGIC, classify_linux_f_type, overlay_layer_paths,
    };
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    pub(super) fn check(path: &Path) -> io::Result<Locality> {
        let st = statfs(path)?;
        // `f_type` is i64 (glibc 64-bit), i32 (32-bit) or unsigned (musl);
        // keep the low 32 bits, which hold the magic.
        #[allow(clippy::unnecessary_cast)]
        let f_type = (st.f_type as u64) & 0xFFFF_FFFF;
        if f_type == OVERLAYFS_SUPER_MAGIC {
            return Ok(check_overlay(path, 0));
        }
        Ok(classify_linux_f_type(f_type))
    }

    /// Layers of an overlay can nest (an overlay used as a lower layer);
    /// deeper than this is treated as unresolved.
    const MAX_OVERLAY_DEPTH: u32 = 4;

    fn f_type_of(path: &Path) -> io::Result<u64> {
        let st = statfs(path)?;
        #[allow(clippy::unnecessary_cast)]
        Ok((st.f_type as u64) & 0xFFFF_FFFF)
    }

    /// overlayfs is local only if every layer is: any network or FUSE layer
    /// makes it not local. Anything that cannot be resolved is not local.
    fn check_overlay(path: &Path, depth: u32) -> Locality {
        let unresolved = Locality::NotLocal(NotLocalKind::OverlayUnresolved);
        if depth >= MAX_OVERLAY_DEPTH {
            return unresolved;
        }
        let Some(canonical) = std::fs::canonicalize(path)
            .ok()
            .and_then(|p| p.to_str().map(str::to_owned))
        else {
            return unresolved;
        };
        let Ok(mountinfo) = std::fs::read("/proc/self/mountinfo") else {
            return unresolved;
        };
        let Some(layers) = overlay_layer_paths(&String::from_utf8_lossy(&mountinfo), &canonical)
        else {
            return unresolved;
        };
        for layer in layers {
            let layer = Path::new(&layer);
            let verdict = match f_type_of(layer) {
                Ok(OVERLAYFS_SUPER_MAGIC) => check_overlay(layer, depth + 1),
                Ok(f_type) => classify_linux_f_type(f_type),
                Err(_) => unresolved,
            };
            if verdict != Locality::Local {
                return verdict;
            }
        }
        Locality::Local
    }

    fn statfs(path: &Path) -> io::Result<libc::statfs> {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
        loop {
            let mut st = std::mem::MaybeUninit::<libc::statfs>::zeroed();
            // SAFETY: `c_path` is NUL-terminated and outlives the call; `st`
            // points to writable memory of the right size.
            let rc = unsafe { libc::statfs(c_path.as_ptr(), st.as_mut_ptr()) };
            if rc == 0 {
                // SAFETY: statfs returned 0, so it initialised the struct.
                return Ok(unsafe { st.assume_init() });
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod os {
    use super::{Locality, classify_macos_mnt_flags};
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    pub(super) fn check(path: &Path) -> io::Result<Locality> {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
        loop {
            let mut st = std::mem::MaybeUninit::<libc::statfs>::zeroed();
            // SAFETY: `c_path` is NUL-terminated and outlives the call; `st`
            // points to writable memory of the right size. libc links
            // `statfs$INODE64` on x86_64, matching its struct layout.
            let rc = unsafe { libc::statfs(c_path.as_ptr(), st.as_mut_ptr()) };
            if rc == 0 {
                // SAFETY: statfs returned 0, so it initialised the struct.
                let st = unsafe { st.assume_init() };
                return Ok(classify_macos_mnt_flags(u64::from(st.f_flags)));
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

#[cfg(windows)]
mod os {
    use super::{Locality, classify_windows_drive_type, windows_prefix_refusal};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Component, Path, Prefix};
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetVolumePathNameW};

    const MAX_PATH: usize = 260;

    pub(super) fn check(path: &Path) -> io::Result<Locality> {
        // 1. UNC / device paths: refused from the string alone, no OS call.
        if let Some(kind) = windows_prefix_refusal(path) {
            return Ok(Locality::NotLocal(kind));
        }
        // 2. The drive letter as written. A mapped drive (`net use Y:`) is
        //    DRIVE_REMOTE here; canonicalising first would turn it into a
        //    `\\?\UNC\` path.
        if let Some(letter) = drive_letter(path) {
            let root = [u16::from(letter), u16::from(b':'), u16::from(b'\\'), 0];
            let verdict = classify_windows_drive_type(drive_type(&root));
            if verdict != Locality::Local {
                return Ok(verdict);
            }
        }
        // 3. The final path: follows symlinks, junctions and subst drives,
        //    and is a `\\?\` path, so it is long-path safe.
        let canonical = std::fs::canonicalize(path)?;
        if let Some(kind) = windows_prefix_refusal(&canonical) {
            return Ok(Locality::NotLocal(kind));
        }
        let root = volume_root(&canonical)?;
        Ok(classify_windows_drive_type(drive_type(&root)))
    }

    fn drive_letter(path: &Path) -> Option<u8> {
        match path.components().next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::Disk(l) | Prefix::VerbatimDisk(l) => Some(l.to_ascii_uppercase()),
                _ => None,
            },
            _ => None,
        }
    }

    /// `root` must be NUL-terminated.
    fn drive_type(root: &[u16]) -> u32 {
        debug_assert_eq!(root.last(), Some(&0));
        // SAFETY: `root` is a NUL-terminated UTF-16 string that outlives the call.
        unsafe { GetDriveTypeW(root.as_ptr()) }
    }

    /// The volume mount point containing `path`, NUL-terminated.
    fn volume_root(path: &Path) -> io::Result<Vec<u16>> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut buf = vec![0u16; wide.len().max(MAX_PATH + 1)];
        let cap = u32::try_from(buf.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path too long"))?;
        // SAFETY: `wide` is NUL-terminated; `buf` has `cap` writable u16s.
        let ok = unsafe { GetVolumePathNameW(wide.as_ptr(), buf.as_mut_ptr(), cap) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        buf.truncate(len);
        buf.push(0);
        Ok(buf)
    }
}

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_os = "macos"
)))]
mod os {
    use super::Locality;
    use std::io;
    use std::path::Path;

    pub(super) fn check(_path: &Path) -> io::Result<Locality> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local-filesystem check is not implemented on this OS",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = r"
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
30 22 0:25 / /srv/nfs rw,relatime shared:5 - nfs4 srv:/export rw,vers=4.2
41 22 0:40 / /var/lib/docker/overlay2/x/merged rw,relatime - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/A:/var/lib/docker/overlay2/l/B,upperdir=/var/lib/docker/overlay2/x/diff,workdir=/var/lib/docker/overlay2/x/work
42 22 0:41 / /mnt/with\040space rw,relatime - overlay overlay rw,lowerdir=/srv/nfs/lower\040dir,upperdir=/mnt/up,workdir=/mnt/work
43 22 0:42 / /mnt/new rw,relatime - overlay overlay rw,lowerdir+=/a,lowerdir+=/b,datadir+=/data,upperdir=/up
44 22 0:43 / /mnt/dataonly rw,relatime - overlay overlay rw,lowerdir=/l1::/data1:/data2
";

    fn strings(v: &[&str]) -> Option<Vec<String>> {
        Some(v.iter().map(|s| (*s).to_owned()).collect())
    }

    #[test]
    fn overlay_layers_are_read_from_the_covering_mount() {
        let want = strings(&[
            "/var/lib/docker/overlay2/l/A",
            "/var/lib/docker/overlay2/l/B",
            "/var/lib/docker/overlay2/x/diff",
        ]);
        assert_eq!(
            overlay_layer_paths(MOUNTINFO, "/var/lib/docker/overlay2/x/merged/some/dir"),
            want
        );
        assert_eq!(
            overlay_layer_paths(MOUNTINFO, "/var/lib/docker/overlay2/x/merged"),
            want
        );
    }

    #[test]
    fn overlay_octal_escapes_are_decoded() {
        assert_eq!(
            overlay_layer_paths(MOUNTINFO, "/mnt/with space/x"),
            strings(&["/srv/nfs/lower dir", "/mnt/up"])
        );
    }

    #[test]
    fn overlay_new_style_and_data_only_layers_are_all_listed() {
        assert_eq!(
            overlay_layer_paths(MOUNTINFO, "/mnt/new"),
            strings(&["/a", "/b", "/data", "/up"])
        );
        assert_eq!(
            overlay_layer_paths(MOUNTINFO, "/mnt/dataonly"),
            strings(&["/l1", "/data1", "/data2"])
        );
    }

    #[test]
    fn overlay_lookup_fails_closed_when_it_cannot_resolve() {
        // Covered by a non-overlay mount, by `/` only, or not at all.
        assert_eq!(overlay_layer_paths(MOUNTINFO, "/srv/nfs/file"), None);
        assert_eq!(overlay_layer_paths(MOUNTINFO, "/home/user"), None);
        assert_eq!(overlay_layer_paths("", "/home/user"), None);
        assert_eq!(
            overlay_layer_paths("garbage line\nstill - garbage", "/x"),
            None
        );
        // An overlay with no layer option names nothing to check.
        let bare = "50 22 0:50 / /mnt/bare rw - overlay overlay rw\n";
        assert_eq!(overlay_layer_paths(bare, "/mnt/bare/x"), None);
    }

    #[test]
    fn mount_prefix_matches_whole_components_and_the_deepest_wins() {
        // `/mnt/new` must not cover `/mnt/newer`.
        assert_eq!(overlay_layer_paths(MOUNTINFO, "/mnt/newer"), None);
        // A deeper non-overlay mount shadows the overlay.
        let shadow = format!(
            "{MOUNTINFO}60 41 8:2 / /var/lib/docker/overlay2/x/merged/data rw - ext4 /dev/sdb rw\n"
        );
        assert_eq!(
            overlay_layer_paths(&shadow, "/var/lib/docker/overlay2/x/merged/data/f"),
            None
        );
        assert!(overlay_layer_paths(&shadow, "/var/lib/docker/overlay2/x/merged/other").is_some());
    }

    #[test]
    fn unescape_leaves_malformed_escapes_alone() {
        assert_eq!(unescape_mountinfo(r"a\040b\134c\054d"), r"a b\c,d");
        assert_eq!(unescape_mountinfo(r"a\9zb\04"), r"a\9zb\04");
    }

    #[test]
    fn the_added_network_magics_are_not_local() {
        for magic in [
            0x0116_1970_u64,
            0x7461_636F,
            0x7375_7245,
            0x564C,
            0xAAD7_AAEA,
            0x786F_4256,
        ] {
            assert_eq!(
                classify_linux_f_type(magic),
                Locality::NotLocal(NotLocalKind::NetworkFs { f_type: magic })
            );
        }
        assert_eq!(
            classify_linux_f_type(OVERLAYFS_SUPER_MAGIC),
            Locality::Local
        );
    }
}

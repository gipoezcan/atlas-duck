//! The server's file-creation mask (ADR 0004): with the data volume's group being the process's
//! own (gid 0 on the team's NFS class), nothing the server creates may be group or other
//! accessible, so the server sets umask 077 before it creates anything.

/// Sets the process umask to 077; answers the previous mask. Unix only (`None` elsewhere).
#[cfg(unix)]
pub fn restrict_umask() -> Option<u32> {
    // SAFETY: umask(2) only swaps the process's creation mask and cannot fail.
    let previous = unsafe { libc::umask(0o077) };
    Some(u32::from(previous))
}

#[cfg(not(unix))]
pub fn restrict_umask() -> Option<u32> {
    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn files_created_after_it_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let previous = restrict_umask();
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").expect("write");
        let sub = dir.path().join("d");
        std::fs::create_dir(&sub).expect("mkdir");
        let file_mode = std::fs::metadata(&file).expect("meta").permissions().mode();
        let dir_mode = std::fs::metadata(&sub).expect("meta").permissions().mode();
        // SAFETY: restores the mask this test replaced.
        unsafe { libc::umask(previous.expect("unix") as libc::mode_t) };
        assert_eq!(file_mode & 0o077, 0, "{file_mode:o}");
        assert_eq!(dir_mode & 0o077, 0, "{dir_mode:o}");
    }
}

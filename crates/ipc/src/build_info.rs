//! Build identity (§3.3: `build_id` = release version + commit, compiled into every binary; §3.4: the
//! probe records the sandbox binary's embedded version).

/// The workspace release version (`[workspace.package] version`).
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `<version>+<12 lowercase hex digits of the commit>`, or `<version>+unknown` when the build had no
/// git checkout and no `ATLAS_DUCK_COMMIT`. The commit half is computed by `build.rs`.
pub const BUILD_ID: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "+",
    env!("ATLAS_DUCK_BUILD_COMMIT")
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_id_is_version_plus_commit() {
        let (version, commit) = BUILD_ID.split_once('+').expect("BUILD_ID has a '+'");
        assert_eq!(version, APP_VERSION);
        assert!(
            commit == "unknown"
                || (commit.len() == 12
                    && commit
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))),
            "unexpected commit part {commit:?}"
        );
    }
}

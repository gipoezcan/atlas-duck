# Export fixture `pass` (S-03)

Not committed: the export is generated at run time into a scratch directory by
`atlas_duck_audit::testing::export_fixture(FixtureKind::Pass, out)` (feature `testing`,
`crates/audit/src/testing.rs`): a throwaway store with a few records of several kinds and its
full-range compliance export.

`verify-export <dir> --manifest-sha256 <FixtureInfo.manifest_sha256>` exits 0
(`FixtureInfo.expected_exit`). Used by `crates/audit/tests/verify_export.rs`, T28's CLI flow and
T31's AppImage step.

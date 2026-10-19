# Export fixture `no-trust-root` (S-03)

Not committed: the export is generated at run time into a scratch directory by
`atlas_duck_audit::testing::export_fixture(FixtureKind::NoTrustRoot, out)` (feature `testing`,
`crates/audit/src/testing.rs`): an honest export, as for `pass`.

`verify-export <dir>` without `--manifest-sha256` and `--anchor-dir` exits 20
("internally consistent; trust root NOT verified", `FixtureInfo.expected_exit`). Used by
`crates/audit/tests/verify_export.rs`, T28's CLI flow and T31's AppImage step.

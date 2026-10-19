# Export fixture `tamper` (S-03)

Not committed: the export is generated at run time into a scratch directory by
`atlas_duck_audit::testing::export_fixture(FixtureKind::Tamper, out)` (feature `testing`,
`crates/audit/src/testing.rs`): the `pass` export with the `target` column of its third
`events.jsonl` row changed afterwards (the manifest stays the honest one).

`verify-export <dir> --manifest-sha256 <FixtureInfo.manifest_sha256>` exits 21
(`FixtureInfo.expected_exit`). Used by `crates/audit/tests/verify_export.rs`, T28's CLI flow and
T31's AppImage step.

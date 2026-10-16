# M6 open pre-release items

Owner: M10 Task 36 owns every item below (it lists the owner of each M10 item). None of them is filled
in here; the TBDs stay in the checklists until the owner resolves them. Sources are the review-ledger
entries in `docs/superpowers/specs/2026-10-07-atlas-duck-review-ledger.md`.

## Open pre-release items (L133)

Checklist TBDs and values still owed, in `docs/release/macos-gui-checklist.md` and its Windows section 9:

- canary payload preview
- `Get-ProcessMitigation` values
- held-Enter duration on the native batch Confirm (WebView2/WKWebView)
- bidi sample for the visual check
- stale-frame timing
- macOS logout reason path
- mock write-delay for the write-on-the-wire step
- checksum
- evidence (screenshot) folder
- DMG name and build id source
- SC3 scenarios (order, batch size) and reviewer count
- Rosetta acceptability for x86_64 (the checklist currently says no)

Also named in L133 and still to settle: the CLI command for the Jira create submit, the redaction
sample, the Cmd+Shift chord list, the V30 crash-report step.

## CI-04 recorded PARTIAL (L132, L216)

CI-04 stays PARTIAL: a release run through `tauri-driver`, the release through the window, `await`
and a `--timeout 0` cold start are covered only by UI-06; the AppImage M6 section has no release/await
step and window focus is not asserted. The Linux credential-window flows are Windows-only (L216 (a)).
L204 records that the packaged-build Linux jobs are driver-free; the wizard and store-backed steps are
the manual rows of `docs/release/linux-gui-checklist.md`.

## Deferrals (L134, L217)

L134 (M6 deferred and follow-up list) and L217 (skipped minors and final-review handoffs) list the
remaining deferrals with their owners (M7, M8, M9, M10). Open on the release side: the live Jira run
(PD-60) before the first release, the macOS GUI checklist per release, signing credentials, and a
store-provisioning helper to return the Fedora store-backed steps to CI (L204).

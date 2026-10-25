# atlas-duck v1 release checklist

M10 Task 33. This is the list of everything that needs a human, a release run or real hardware before
v1 ships. `docs/release/go-no-go-v1.md` records the decision; `ci/check-release-go-no-go.mjs` reads both
files in release.yml's `release-go-no-go` job and blocks `upload` until every row below is `PASS` or
`N/A: <reason>`.

How to fill a row:

- **Owner**: the person or role who runs it. `unassigned (Q7)` means the human decision Q7 (who runs
  the manual rows and when) has not been made. The gate refuses an unassigned owner.
- **Evidence**: a CI run URL, or the name of an evidence file kept outside the repository (spec 7.7: no
  screenshots in the repo). The gate refuses an empty evidence cell on a `PASS`.
- **Result**: `PENDING` until run, then `PASS`, `FAIL` (with the build id in the evidence) or
  `N/A: <reason>`. `PENDING` and `FAIL` block the release.
- Keep the row ids unchanged and keep `|` out of the cells (the checker reads the table by its ids).
- Every row says which build it was run on. The build id is the one in the go/no-go record.

Evidence comes from the release candidate R, the commit named in the go/no-go record: run URLs are runs of
R (a release-candidate `v*` tag run or the branch runs for that commit). The tagged commit is R plus a
docs-only change, checked by the gate. Rows whose evidence exists only in the tag run itself (signing
verification, install probes of the signed packages) are not filled with a URL: their Result is
`verified by job <name> in the tag run`, accepted only for `release-signing-verification`,
`release-secrets-present`, `windows-extra-exes-signed`, `macos-dmg-spctl` and `install-probes-run-id`,
with the job named in the row's text. Each of those jobs is in `upload`'s needs, so a red job blocks
the upload. Owner `CI (release run)` marks them.

## 1. CI and release pipeline

| ID | Item | Owner | Evidence | Result |
|----|------|-------|----------|--------|
| ci-green-release-commit | CI green on the release commit: URLs of the `ci`, `bundle`, `e2e-bundle` and `install-probes` runs for that exact commit (all legs, including Rosetta, the Windows and Linux e2e legs and GitLab), runs of R. | CI (release run) | | PENDING |
| release-signing-verification | Release pipeline signing verification output: `release-verify-windows` (signtool verify /pa /v) and `release-verify-macos` for both arches (codesign deep strict, hardened runtime, no get-task-allow, spctl, stapler), pasted or linked from the tag run. | CI (release run) | | PENDING |
| release-secrets-present | T26 first release run: the guard step passed, so all nine signing secrets are present in the `release` environment (Q1 to Q3). The run must show the guard step green, not skipped. | unassigned (Q7) | | PENDING |
| release-env-tags-only | T26 first release run: the `release` GitHub environment is limited to `v*` tags (Settings, Environments, deployment branches and tags), and a run from a branch cannot read its secrets. | unassigned (Q7) | | PENDING |
| windows-extra-exes-signed | T26 first release run: Tauri signs the two extra Windows executables (`atlas-duck.exe` and `atlas-duck-sandbox.exe`) as well as the main exe. `release-verify-windows` checks all three and fails if not. If it fails, a pre-bundle signing step is needed (check-release-build.sh already allows `beforeBundleCommand`). | CI (release run) | | PENDING |
| macos-dmg-spctl | T26 first release run: the dmg passes `spctl -a -t open --context context:primary-signature` and `stapler validate` for both arches (notarization covers the dmg, not only the .app inside it). | CI (release run) | | PENDING |
| install-probes-run-id | T26 first release run: `install-probes` downloads this run's own `bundle-*` artifacts by `run-id` while the release run is still in progress (download-artifact by run-id of the caller's own run). Also that the nine named secrets reach the signing jobs through the `bundle` call. | CI (release run) | | PENDING |
| ci-t27-evidence | T27 CI evidence lines in the `install-probes` run on the release commit: `RUNTIME_VERSIONS` per package, `CI_FIXTURE_STORE` and identical `CI_FIXTURE_ENTRIES` (kek=present), `DOCTOR`, the drain lines (`os_end_session reason=installer_quit`, `app_stop reason=installer`), `I40 uninstall drain`, `I45 RELEASE OK` on both macOS arches, the S-04 line, and "left N files unchanged" for the uninstall and reinstall of each package. | CI (release run) | | PENDING |
| ci-t27a-evidence | T27a CI evidence lines in the `e2e-bundle` run on the release commit: `bundle-macos-e2e` on both arches (`ci_fixture` built, the three `ci_fixture_*_macos` tests listed, `CDHash=`) and `install-test-macos-debug` on both arches (the fourteen lines ending `OK: install-test macos debug-app <arch>`, `CDHASH` equal across the reinstall, `CI_FIXTURE_VERIFY ok ... findings=0`). This is the first proof of PD-179's premise (a debug app reads its own keychain items after a reinstall). | CI (release run) | | PENDING |
| ci-v19-v32-evidence | V19 (NSIS hooks, upgrade drain, "delete app data" disabled, deb/rpm upgrade with the app running) and V32 (package baseline: WebView2 runtime, WebKitGTK 4.1, libayatana-appindicator3, AppImage runtime versions) evidence lines from the `bundle` and `install-probes` runs. Record the runtime versions in the evidence. | CI (release run) | | PENDING |
| ci-unix-fifo-first-run | First CI run of the unix FIFO test and the unix `O_NOFOLLOW` paths (T8, T19 fix round): green on the Linux and macOS legs of the release commit's `ci` run. | CI (release run) | | PENDING |

## 2. macOS (`docs/release/macos-gui-checklist.md`)

Run the macOS GUI checklist once per architecture on native hardware. Rosetta does not stand in for
the Intel run: mark the x86_64 row `N/A: <reason>` only with the lead's ruling.

| ID | Item | Owner | Evidence | Result |
|----|------|-------|----------|--------|
| macos-gui-arm64 | macOS GUI checklist, all sections and its evidence table, on an Apple silicon Mac, with the signed build of the release commit. | unassigned (Q7) | | PENDING |
| macos-gui-x86_64 | The same checklist on an Intel Mac. | unassigned (Q7) | | PENDING |
| macos-menubar-count | T18 menu-bar count: with 1, then 3, then 12 pending requests the menu-bar item shows `1`, `3`, `12` next to the tray icon; with 0 pending no number is shown; the number is the only text (no agent string). Per arch. | unassigned (Q7) | | PENDING |
| macos-gui-path-wording | T19 GUI PATH wording: launched from Finder, the app's Install CLI answer says the CLI is "not on your PATH" (a GUI-launched macOS process has a minimal PATH), and the text after the install matches what a Terminal shows for `command -v atlas-duck`. Check that the wording does not promise more than the Terminal shows. | unassigned (Q7) | | PENDING |
| macos-i45-signed-app | I-45 on the signed macOS `.app`: install the release dmg, create the store through the app's own first-run wizard (PD-179), quit, remove the app, reinstall the same build and start it: it reaches serving state with no keychain prompt and the log has the earlier records. The lead may strike this row with `N/A: struck by the lead (PD-179)`. | unassigned (Q7) | | PENDING |
| macos-dock-no-bounce | T18: a request arriving in default mode does not bounce the Dock (macOS) and does not set an urgency hint or flash (Linux). Windows flashes the taskbar button once (own row below). | unassigned (Q7) | | PENDING |

## 3. Windows (`docs/release/macos-gui-checklist.md` section 9 and the M6 final review)

The real-webview items of the M6 final review (`final-review.md` line 316: held Enter on the native
Confirm, bidi visual, chords in the iframe, emit before show, shutdown reason text, hardening DLL
check) have no automated cover on a real WebView2 window.

| ID | Item | Owner | Evidence | Result |
|----|------|-------|----------|--------|
| windows-held-enter | Batch approve on the native Confirm dialog with Enter held (section 9 item 9, section 4 step 5): it does not confirm while Enter is held or was released before the dialog appeared. | unassigned (Q7) | | PENDING |
| windows-bidi-visual | Bidi controls (U+202E, U+2067 to U+2069) in an editable value field and in the Detail view are shown visibly neutralised and nothing reorders (section 9 item 10). | unassigned (Q7) | | PENDING |
| windows-chords-iframe | The approvals window's chords work with focus inside the preview iframe and do nothing when the window is not focused (section 7 step 4, Windows form). | unassigned (Q7) | | PENDING |
| windows-emit-before-show | Raise through the tray icon, the taskbar and the toast click: the first painted frame already lists the current queue (section 9 item 8). | unassigned (Q7) | | PENDING |
| windows-shutdown-reason-text | Sign-out or shutdown reason text: "atlas-duck is finishing an approved write" only while a write is on the wire, otherwise "atlas-duck is saving its log before shutdown" (section 9 item 2). On macOS the Cmd+Q texts are in the macOS checklist section 5. | unassigned (Q7) | | PENDING |
| windows-hardening-dll | Hardening DLL check on the first real webview: `Get-ProcessMitigation -Id <pid>` for `atlas-duck-app.exe` shows `SetDefaultDllDirectories`, `ProcessExtensionPointDisable` and `ProcessImageLoad` with `NoRemoteImages`, `NoLowMandatoryLabelImages`, `PreferSystem32Images` (section 9 item 6). Attach the output. | unassigned (Q7) | | PENDING |
| windows-taskbar-overlay | T18 taskbar overlay: with 1 to 9 pending the Approvals taskbar button shows a red disc with that digit; with 10 or more it shows `9+`; at 0 it disappears. Per arch (x64 and arm64 where available). | unassigned (Q7) | | PENDING |
| windows-overlay-reopen | T18 fix round: with a count pending (for example 3), close the Approvals window, reopen it from the tray menu ("Open approvals") and check the taskbar button shows the overlay digit 3 (and `9+` at ten or more). Also launch a second instance with the window closed and check the overlay. | unassigned (Q7) | | PENDING |
| windows-flash-once | T18: a new request in default mode (show without activating) flashes the taskbar button once. | unassigned (Q7) | | PENDING |
| windows-installer-visuals | Installer visuals on a real Windows machine: the finish page text is not clipped (if it is, add `!define MUI_FINISHPAGE_TEXT_LARGE` in `hooks.nsh`), and the uninstall confirmation page states that data, settings and keychain entries are kept (the suggested `MUI_UNCONFIRMPAGE_TEXT_TOP` wording from the T23 review, if the lead adopts it). | unassigned (Q7) | | PENDING |
| windows-installer-upgrade-variants | T23/T27 manual variants CI cannot reach: a per-machine upgrade while a second user's session runs the app and `atlas-duck mcp`; the app started elevated with a per-user installer (immediate kill, no 90 s wait); `ENDSESSION_CLOSEAPP` through the Restart Manager; PowerShell blocked by AppLocker or WDAC (only Tauri's own check on the main exe is left). Name the variants run in the evidence. | unassigned (Q7) | | PENDING |
| windows-10-22h2-install | V32, human decision Q13: manual install of the signed package on Windows 10 22H2 (or a self-hosted runner), recording the WebView2 runtime version and that the app starts. | unassigned (Q7) | | PENDING |
| windows-clean-machine-dry-run | D11 manual half (M8 ruling R11), on the same clean Windows machine and a freshly created local user profile: install the signed package and record the probe report Settings shows (`floor=met`, `failed=none`); then complete the first-run wizard by hand and record the answer of one `script run --dry-run`. | unassigned (Q7) | | PENDING |
| windows-onedrive-placeholder | T8 residual: reading an import or export file on a real OneDrive-redirected folder (a placeholder file) behaves as the `FILE_FLAG_OPEN_REPARSE_POINT` code path intends (reads or refuses with the documented message, never hangs). Not checked by any automated test. | unassigned (Q7) | | PENDING |

## 4. Linux and cross-platform

| ID | Item | Owner | Evidence | Result |
|----|------|-------|----------|--------|
| linux-gui-checklist | `docs/release/linux-gui-checklist.md` on the packaged build (the wizard and store-backed steps CI cannot drive, CI-04 partial scope). | unassigned (Q7) | | PENDING |
| clipboard-webview | T17: `navigator.clipboard.writeText` works under the shipped CSP and permissions in each real webview (WebView2, WKWebView, WebKitGTK): the copy buttons (CLI command, MCP config) show "Copied", not "Could not copy". Unit tests mock the clipboard. | unassigned (Q7) | | PENDING |
| nvda-live-regions | T20/T21 fix round: with NVDA on Windows, the persistent status regions (Verification, Incidents, Export and backup, Trail, payload page, event list) announce their changes once. | unassigned (Q7) | | PENDING |
| l133-tbds-resolved | The L133 TBDs (`docs/release/m6-open-items.md`) are filled in `docs/release/macos-gui-checklist.md` and its Windows section: canary payload preview, `Get-ProcessMitigation` values, held-Enter duration, bidi sample, stale-frame timing, macOS logout reason path, mock write-delay, checksum, evidence folder, dmg name and build id source, SC3 order and reviewer count, Rosetta ruling, CLI submit command, redaction sample, chord list, V30 crash-report step. No `TBD by lead` is left. | unassigned (Q7) | | PENDING |
| ui-07 | UI-07 (the M6 human item, unchanged). | unassigned (Q7) | | PENDING |
| sc3-walkthrough | SC3 walkthrough (`docs/release/sc3-walkthrough.md`), run by the reviewers it names. | unassigned (Q7) | | PENDING |
| pd-60-live-jira | M5 PD-60 live Jira run against a real Data Center instance with a PAT the user provides. | unassigned (Q7) | | PENDING |
| v26-live-probe | V26 live probe against the same real instance. | unassigned (Q7) | | PENDING |
| v27-sleep-windows | V27 (M2 sleep and hibernate check) on real Windows hardware: suspend for 10 minutes, resume, compare the suspend-aware elapsed time with the wall clock. | unassigned (Q7) | | PENDING |
| v27-sleep-macos | V27 on real macOS hardware, same procedure. | unassigned (Q7) | | PENDING |
| v27-sleep-linux | V27 on real Linux hardware, same procedure. | unassigned (Q7) | | PENDING |
| restore-settings-bundle | T30 (lead ruling Q12): restore from a backup bundle in Settings, by hand, because the native confirmation and the file dialog cannot be answered by the WebDriver and no new test seam was added. Cover the confirmation text, a cancel, and a completed restore with the log verifying afterwards. | unassigned (Q7) | | PENDING |
| restore-keychain-lost | T30 (Q12): restore from the `keychain_lost` screen through the credential window path, by hand, for the same reason. | unassigned (Q7) | | PENDING |
| tray-anchor-dir-gap | Known gap, recorded as a row so nobody claims otherwise (T21b): Settings shows the anchor-dir status lines (`anchor_dir_write_failing`, `anchor_dir_lines_pending`, `anchors_missing`); the tray menu and tooltip do not. Check that no shipped text says the tray shows them. Set `N/A: known gap, follow-up T36` when the Settings lines are verified and the gap is accepted. | unassigned (Q7) | | PENDING |
| mcp-real-client | D8 / M9 live handoff: one real MCP client lists the tools and approves one write through the approvals window (config from `docs/release/mcp-client-config.md`). | unassigned (Q7) | | PENDING |
| upgrade-from-previous | Spec 8.13: upgrade from the previous release with a backup taken first; the store opens, the log verifies, and a restore of the pre-upgrade backup works. | unassigned (Q7) | | PENDING |
| release-notes-wording | The release notes contain "Restart your MCP clients" and the backup recommendation (take a backup before upgrading). | unassigned (Q7) | | PENDING |

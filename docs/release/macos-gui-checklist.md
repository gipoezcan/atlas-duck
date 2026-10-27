# macOS GUI release checklist (M6)

Tester-facing checklist for the atlas-duck approvals UI on macOS. Run it once per architecture:

- **arm64** (Apple silicon) on native hardware.
- **x86_64** (Intel) on native hardware. Do not substitute a Rosetta run for this arch; mark the row N/A and tell the lead if no Intel Mac is available. A Rosetta run of the arm64 build is never accepted as the Intel pass (ruling, set M10 T36b).

Spec references: §13 (macOS GUI release checklist), §1.4 (SC3), §5.6 (approvals UI), §6.4 (rendering safety), §7.7 (paths and screenshot storage), §10.3 (credential window), §15 (verification items). Plan: Task 35.

## 0. Before you start

1. Record the build id from the installer's About panel or the `atlas-duck --version` output. Write it in the evidence table (section 5). The source of the build id is the `atlas-duck --version` text, copied whole (set M10 T36b).
2. Confirm the build under test is the one attached to the release candidate, and that the checksum matches the one the lead gave you. Checksum: the SHA-256 of the `.dmg` file, written by the lead next to the draft release of the candidate tag (the release workflow attaches no checksum file). Compute yours with `shasum -a 256 "<file>.dmg"` and compare all 64 hex characters (set M10 T36b).
3. Screenshots and recordings go **outside the repository**, in the test-evidence folder the lead names. Do not commit them (spec §7.7). Folder: `~/atlas-duck-evidence/<YYYY-MM-DD>-<arch>/` on the test Mac, copied to the lead's evidence share after the run (set M10 T36b).
4. Use a clean macOS user account, or a user with no prior atlas-duck data at `~/Library/Application Support/atlas-duck`. Note in the evidence table if you reused an account.

### 0.1 Start the mock Jira endpoint

The mock Atlassian servers are created inside the `cli_flows` test harness (`app/src-tauri/tests/cli_flows/harness.rs`, `World::new` and `MockDc::start` in `crates/atlassian/src/testing/mock_dc.rs`). They run only inside a `cargo test` process. Testers have no cargo-free way to start them, and this checklist does not invent a standalone command.

Step: **ask the lead for the mock Jira endpoint** (base URL, PAT canary value, and the instance alias to use). Record the URL and the alias in the evidence table.

> Note for the report: a cargo-free mock start command is not documented yet. If the lead provides a standalone runner, replace this step with its command.

## 1. Install

For each architecture:

1. Mount the `.dmg` for the build under test. File name: the file the release workflow attached to the draft release, named by Tauri `Atlas Duck_<version>_aarch64.dmg` (Apple silicon) or `Atlas Duck_<version>_x64.dmg` (Intel); `<version>` is the one in `app/src-tauri/tauri.conf.json` (set M10 T36b).
2. Drag atlas-duck to Applications, then launch it from Applications.
   - Expected: no "damaged" or unidentified-developer dialog. If Gatekeeper blocks it, stop and record the dialog text as FAIL.
3. Expected: the first-run wizard opens. If the approvals window opens instead, FAIL.
4. Hardening check (read-only; run once, after the first launch that creates a webview). Run `codesign -dvv` and `codesign -d --entitlements -` on the installed `atlas-duck-app` binary.
   - Expected: the signature flags include the hardened runtime (`runtime`), and the entitlements output does not contain `com.apple.security.get-task-allow`. The repo's bundle check script is `ci/check-macos-bundle.sh`; compare its result with this step. Any other entitlement key is recorded as a note, not a FAIL (ruling, set M10 T36b): only a missing `runtime` flag or `com.apple.security.get-task-allow` is a FAIL.

## 2. First-run wizard

1. Work through the wizard in its order: create the store, add the mock Jira instance (URL from 0.1), paste the PAT.
2. Expected: the connection test succeeds against the mock. The PAT is stored in the macOS Keychain; it does not appear in any log or on screen after entry.
3. Expected: the wizard finishes and the approvals window stays closed until something is submitted.
4. Setup window rebuild. Stop at step 2 of the wizard (or any later step) with non-secret values entered (for example the instance alias and URL). Close the setup window with the red button. Reopen it from the tray icon.
   - Expected: the wizard resumes at the same step, and the non-secret values are still filled in.
   - Expected: the passphrase field is empty. No passphrase is retained across the close and reopen. A retained passphrase is FAIL.

## 3. CLI submit, toast, reopen, approve

1. In a Terminal, submit a Jira create through the CLI against the mock instance (command, the one the e2e flow `ui06` runs; set M10 T36b): `atlas-duck jira issue create --project ABC --type Bug --summary "E2E create" --reason "M6 checklist: create a Jira issue" --timeout 120`. The mock serves project `ABC`.
2. Expected: a toast appears saying a request is waiting for approval.
3. Click the toast. Expected: the approvals window opens and shows the request.
4. Close the approvals window with the red button. Expected: the window hides, and atlas-duck keeps running (menu bar icon remains).
5. Click the Dock icon. Expected: the approvals window reopens (`RunEvent::Reopen`). Note any delay.
5a. Raise paths show the current queue on the first frame (emit before show). Repeat the raise through each path: the tray icon, the Dock icon (step 5), and the toast click (step 3). Each time, watch the first painted frame of the window.
   - Expected: the first painted frame already lists the current queue. No stale first frame (an empty or older list that is replaced a moment later) is FAIL.
   - Expected: the window is shown only after the queue is loaded, so the three paths behave the same.
   - Stale-frame timing on this build (set M10 T36b): no duration is measured, and none is accepted. The test covers the order of emit and show; it does not measure the painted frame on a real WebKit window. Record each raise with the system screen recorder (Shift+Cmd+5) and step through the frames: the first frame that shows the window must already list the queue.
6. Find the request again and try to approve it **immediately** after it appears. Expected: the Approve button is disabled for the first 1 s after focus or after the candidate changes (inert period, §5.6). Record the observed delay.
7. Wait until the inert period passes, then approve.
8. Expected: the CLI process that submitted the request exits with code **0** and prints a receipt. Check with `echo $?`.

## 3a. Confluence: get, update, attachment collision

Run on each architecture. Every command carries `--reason`; the reason text below is the checklist's own. Every command also carries the global flag `--instance <alias>` (the Confluence instance alias from 0.1; the flag is accepted anywhere before `--`, see `atlas-duck --help`). The Confluence instance must be set up in the wizard or settings like the Jira one (section 2).

Values for all of 3a (the fixture set of `app/src-tauri/tests/confluence_flows/flows.rs`; set M10 T36b): `<PAGE_ID>` is `65537`, the instance alias is `wiki`, the base version `<N>` is `7`, the value to mask (3a.1) is `REDACT-ME-4711`, which the lead writes into the description of the mock page before the run (the mock has no built-in value for it), and the collision file (3a.3) is `notes.txt`, a 5-byte file containing `hello`, the same name and size as the page's existing attachment.

1. **Page get, release with redaction.** In a Terminal:
   `atlas-duck confluence page get <PAGE_ID> --instance <alias> --reason "M7 checklist: read Confluence page for release"`
   - Expected: a toast appears and the approvals window shows the request. Open the **Preview** tab (default) and check the page renders in the sandboxed frame.
   - Expected: open the redaction edit, mask the value the lead names, then release the edit. A redaction creates a new revision of the request: open the new revision, review it, and release it a second time. The CLI is still waiting after the first release; that is not a FAIL.
   - Expected: after the second release the CLI read result shows `redacted: true`, and the CLI exits with code **0**.
2. **Page update with Markdown, approve.** In a Terminal (`<N>` must equal the current version of the page, otherwise the flow becomes a conflict card instead of the diff):
   `atlas-duck confluence page update <PAGE_ID> --instance <alias> --base-version <N> --body "**done**" --reason "M7 checklist: approve Confluence page update"`
   - Expected: the approvals window shows the request. On the **Preview** tab the diff renders with its styling (see 4.3, `preview.css`). Plain unstyled text is FAIL.
   - Expected: approve after the inert period (1 s). The CLI exits with code **0** and prints a receipt.
3. **Attachment collision, deny.** In a Terminal, with a local file whose name collides with an existing attachment on the page (file path: `~/atlas-duck-evidence/notes.txt`, set M10 T36b):
   `atlas-duck confluence attachment upload <PAGE_ID> --instance <alias> --content-base64-file <path> --reason "M7 checklist: deny attachment collision"`
   - Expected: the approvals window shows the request. Deny it in the UI.
   - Expected: the CLI exits with code **3**. The attachment on the page is unchanged.

## 4. Deny, redaction, preview

1. Submit a second request, then deny it in the UI.
   - Expected: the CLI exits with code **3**.
2. Submit a request whose body contains a value the tester is told to redact (sample, set M10 T36b: `REDACT-ME-4711`, in the description of the Jira issue `ABC-77`). In the approvals window, open the redaction edit, mask the value, and approve.
   - Expected: the CLI read result shows `redacted: true`.
3. Open the preview of a Confluence page update with a small diff.
   - Expected: the preview renders in a sandboxed frame with the diff styling applied. Plain unstyled text in the diff means `preview.css` is not applied: FAIL and report to the lead (the sandboxed frame carries preview.css as one inline `<style>` admitted by its sha256 in both policies, PD-92 as built; V24 macOS WKWebView evidence).
4. Expected: the approvals window opens and responds to clicks. A window that stays blank or hangs on the first click means the isolation origin is wrong on this build (V34 / §6.4): FAIL, record the Developer Tools console error.
5. Batch approve with a held Enter. Select two or more requests, then press Approve. While the native Confirm dialog appears, hold Enter for about 2 s, then release it.
   - Expected: the dialog does not confirm while Enter is held or released before the dialog is shown. Nothing is approved.
   - Expected: only a deliberate press of Enter (or the default button) after the dialog is visible confirms the batch.
   - Expected: if the batch was not confirmed, the requests stay pending.
   - Hold duration and confirm key (set M10 T36b): hold Enter for about 2 s. The Confirm button stays inert for the first 1 s after the dialog opens, Enter never activates it (and a key auto-repeat is ignored), so confirm afterwards with a mouse click or one press of Space (acts on key-up). The existing test covers Enter and Space on a single Approve button, not the native Confirm dialog.
6. Bidi control characters. Create or edit a request whose editable value field contains a right-to-left override (U+202E) and an isolate character (for example U+2067 ... U+2069). The sample value (set M10 T36b): `report U+202E gnp.exe U+2067 abc U+2069 end`, with each `U+XXXX` typed or pasted as the real character (the e2e corpus uses `U+202E gnp.exe`).
   - Expected: the control characters are shown visibly neutralised (as a visible marker, not as invisible or as reordering).
   - Expected: the surrounding text does not reorder. Check the same value in the Detail view as well.
   - Expected: nothing in the value is executed or rendered as active content.
7. Window open refusal and canary. In the preview, use the injection payload from the corpus (`window.__pwned=1`, the full payload, set M10 T36b, is `<script>window.__pwned=1;document.title='pwned'</script>` as the text of a request field).
   - Expected: no new window opens. Nothing runs (the canary `window.__pwned` stays unset). The window title is unchanged.
   - Release builds have no devtools, so check the title and the window count only. Do not use devtools to check the canary.

## 5. Quit, shutdown and restart

1. With no write in flight, press Cmd+Q.
   - Expected: atlas-duck quits without a dialog. The shutdown screen (if shown) says "atlas-duck is saving its log before shutdown".
   - Expected: the shutdown screen never says "atlas-duck is finishing an approved write" while no write is on the wire.
   - Logout or system shutdown reason text on macOS (set M10 T36b): there is none. macOS shows no reason text for atlas-duck (the app answers the terminate request with "terminate later"; the Windows reason text has no macOS counterpart). Expected evidence: the logout is not held up, and the next launch's history shows `APP_STOP` with reason `os_shutdown`.
2. Relaunch. Expected: the approvals window and tray behave as in section 3.
3. Start an approved write, then press Cmd+Q **while the write is on the wire** (set M10 T36b: ask the lead to start the mock with a 20 s delay on `POST /rest/api/2/issue`, which is below the 75 s shutdown bound).
   - Expected: the shutdown screen says "atlas-duck is finishing an approved write".
   - Expected: the app waits for the write to finish, then quits. It must not hang. A hang longer than the grace period (note the time) is FAIL.
4. Relaunch. Open the request's history.
   - Expected: the log has the `APP_STOP {quit}` entry from the Cmd+Q.
   - If the write outcome is unknown, the history row shows "Verify now". Press it. Expected: the verify result is recorded; it does not change the original receipt silently.

## 6. Credential window

1. Open the credential window from the wizard or the instance settings (V35 / §10.3).
2. Expected: it opens as a private (incognito-style) session. Log in with the mock, then close the window and reopen it.
   - Expected: no stored session survives the reopen (no shared storage with the main window).
3. Check that the window does not share session state with the approvals window (expected: logging in through the credential window does not sign the approvals window in).

Debug build only, not part of the release pass (the release build has no Web Inspector, `DEVTOOLS_ALLOWED`): when checking a debug build, open the Web Inspector of the credential window after it loaded. The console should show no "Refused to ..." Content Security Policy message, and the token form should be shown (its `credential_context` call answered through the isolation frame). In a release build the evidence is the token form shown in step 2 (it needs the `credential_context` answer) and no blank window.

Coverage of the credential window by OS (M6 CI ruling, run 38859187604): the e2e flows that drive this window (`credential_page_meta_csp_enforced`, `s07_credential_window_incognito_or_own_data_dir`, `s09_isolation_invoke_round_trips_credential_window`, `s09_main_frame_navigation_refused_in_credential_window`) run on Windows only (`WINDOWS_ONLY_FLOWS` in `app/src-tauri/tests/e2e/flows.rs`). The window has its own data directory (S-07), so its own browser context, and on Linux `tauri-runtime-wry` allows WebKit automation for the first web context only; no shared context is added for tests.

- macOS: CI drives no webview at all. The credential window's CSP and its own data directory are checked by hand, steps 1 to 3 above (the Web Inspector check is a debug-build note only).
- Linux: covered only by the unit tests of Tasks 5, 6 and 20: `ci/check-csp.mjs` and its tests (the meta CSP of `credential.html`), `ci/check-credential-bundle.mjs` (no shared chunk, no web storage), `windows::credential_builder_incognito_or_own_dir` (own data directory), `csp::tests` (the isolation style hash in the credential policy) and `app/src-tauri/tests/credential.rs`. No real WebKitGTK webview checks the enforced policy on Linux.

## 7. Tray and menu

1. Use the tray icon to show the approvals window.
2. Expected: the window appears and gains focus.
3. Hide it, then use "Quit" from the tray menu.
   - Expected: same behaviour as Cmd+Q in section 5, step 1.
4. Press each Cmd+Shift chord from the approvals window's help list (list, set M10 T36b: Cmd+Shift+Enter approve or release, Cmd+Shift+D deny, Cmd+Shift+Down next request, Cmd+Shift+Up previous request).
   - Expected: the chord performs the action listed, or does nothing if the window is not focused.

## 7a. Visual design (M11)

Look at every window once in the light appearance and once in the dark appearance (System Settings, Appearance): Setup, Settings, Approvals, Audit, Running scripts, Onboarding and the credential window.

1. Expected: the system font (no serif), cards separated, labels above their fields, one button row per form, readable text in both appearances. Queue rows and audit rows are not clipped (badges and both lines fully visible).
2. Press Tab through Settings and through Approvals. Expected: every control shows a visible focus ring in turn. A control with no visible focus is FAIL.
3. System Settings, Accessibility, Display, turn on "Reduce motion". Expected: no transition or animation on buttons or hover.
4. Expected: native controls (scrollbars, date pickers, checkboxes) follow the appearance.

## 8. Evidence table

Fill one row per check, per architecture. Mark each item `PASS`, `FAIL` or `N/A` (with a reason).

| Date | Tester | Arch | Build id | Item | Result | Evidence (file name outside repo) |
|------|--------|------|----------|------|--------|-----------------------------------|
|      |        | arm64 / x86_64 |  | 1. Install and Gatekeeper |  |  |
|      |        |      |  | 1.4 Hardening: no get-task-allow (codesign) |  |  |
|      |        |      |  | 2. Wizard and Keychain PAT |  |  |
|      |        |      |  | 2.4 Setup window rebuild, no passphrase kept |  |  |
|      |        |      |  | 3.1 CLI submit and toast |  |  |
|      |        |      |  | 3.3 Toast opens approvals |  |  |
|      |        |      |  | 3.5 Hide keeps running |  |  |
|      |        |      |  | 3.5 Dock reopen (RunEvent::Reopen) |  |  |
|      |        |      |  | 3.5a Raise paths: current queue on first frame |  |  |
|      |        |      |  | 3.6 Inert period (1 s) |  |  |
|      |        |      |  | 3.8 Approve exit 0 with receipt |  |  |
|      |        | arm64 / x86_64 |  | 3a.1 Confluence page get, two releases (redaction), `redacted: true`, exit 0 |  |  |
|      |        | arm64 / x86_64 |  | 3a.2 Confluence page update (Markdown), approve exit 0 |  |  |
|      |        | arm64 / x86_64 |  | 3a.3 Attachment collision, deny exit 3 |  |  |
|      |        |      |  | 4.1 Deny exit 3 |  |  |
|      |        |      |  | 4.2 Redaction gives `redacted: true` |  |  |
|      |        |      |  | 4.3 preview.css loads (V24) |  |  |
|      |        |      |  | 4.4 Isolation origin, no hang (V34) |  |  |
|      |        |      |  | 4.5 Batch approve, held Enter does not confirm |  |  |
|      |        |      |  | 4.6 Bidi controls neutralised, no reorder |  |  |
|      |        |      |  | 4.7 window.open refused, canary unset, title unchanged |  |  |
|      |        | x64 / arm64 |  | 9.6 Hardening policies on first webview (Windows) |  |  |
|      |        | x64 / arm64 |  | 9.7 Setup window rebuild (Windows) |  |  |
|      |        | x64 / arm64 |  | 9.8 Raise paths, current queue on first frame (Windows) |  |  |
|      |        | x64 / arm64 |  | 9.9 Batch approve, held Enter (Windows) |  |  |
|      |        | x64 / arm64 |  | 9.10 Bidi controls neutralised (Windows) |  |  |
|      |        | x64 / arm64 |  | 9.11 window.open refused, canary unset (Windows) |  |  |
|      |        |      |  | 5.1 Cmd+Q idle, shutdown text |  |  |
|      |        |      |  | 5.3 Cmd+Q with write on wire, waits, no hang |  |  |
|      |        |      |  | 5.4 APP_STOP {quit} logged, Verify now |  |  |
|      |        |      |  | 6. Credential window private (V35) |  |  |
|      |        |      |  | 7. Tray show, tray quit |  |  |
|      |        |      |  | 7.4 Cmd+Shift chords |  |  |
|      |        |      |  | 7a.1 Light and dark appearance, no clipped rows (M11) |  |  |
|      |        |      |  | 7a.2 Focus ring visible on Tab (M11) |  |  |
|      |        |      |  | 7a.3 Reduce motion honoured (M11) |  |  |

Also record: mock Jira URL and alias (from 0.1), macOS version, hardware model, whether the account was reused.

## 9. Windows manual items

These run on Windows, not on the macOS hosts, and are listed here so they are not lost. Record them in the same evidence table format, with Arch set to `x64` or `arm64` as applicable.

1. **Hidden end-session window in the taskbar.** Start atlas-duck, then sign out or shut down. Expected: no visible taskbar entry for the hidden end-session window.
2. **Shutdown with a write on the wire.** Expected: the block reason reads "atlas-duck is finishing an approved write" only while a write is in flight. Otherwise it reads "atlas-duck is saving its log before shutdown" (the second text is the lead's ruling, T29 review). Confirm both texts, and that "Shut down anyway" works.
3. **WebView2 fixed-version runtime on a local disk.** A runtime on a UNC share is blocked by NoRemoteImages. Expected: the app starts with the runtime on a local disk, and fails visibly with the runtime path if the runtime is on a share.
4. **Hardening DLL restrictions.** Expected: no DLL-load failure dialog during normal use.
5. **Crash-report directory.** After a forced WebView2 renderer crash (if you can produce one safely), check that the Crashpad reports directory is cleared at next start (V30). Record whether reports were written locally.
6. **Hardening DLL proof on the first real webview.** Start atlas-duck until the first webview is shown, then read the process mitigation policies of the app process (`atlas-duck-app.exe`) with Process Explorer, or with `Get-ProcessMitigation -Id <pid>` (read-only). Record the output.
   - Expected: these policies are active, as set in `app\src-tauri\src\startup\hardening.rs` and spec §2.5: `SetDefaultDllDirectories`, `ProcessExtensionPointDisablePolicy`, and `ProcessImageLoadPolicy` with `NoRemoteImages`, `NoLowMandatoryLabelImages`, and `PreferSystem32Images`.
   - Expected values and field names (set M10 T36b, from `hardening.rs`): `ExtensionPoint` shows `DisableExtensionPoints : ON`; `ImageLoad` shows `BlockRemoteImageLoads : ON`, `BlockLowLabelImageLoads : ON`, `PreferSystem32 : ON`. The default-DLL-directories setting is not shown by `Get-ProcessMitigation`. A failure to set any of them is logged as `startup_mitigation_failed`; see the history.
   - Whether the same policies are visible on the `msedgewebview2` child processes (set M10 T36b): not asserted for v1. The repo sets them on the app process only, so record the observed values of the `msedgewebview2` children as a note, never as PASS or FAIL.
   - If `ProcessImageLoadPolicy` is not active, record FAIL with the output and the build id. The startup log then contains `startup_mitigation_failed`.
7. **Setup window rebuild.** Close the setup window mid-wizard with non-secret values entered, then reopen it from the tray. Expected: the wizard resumes at the same step, the non-secret values are filled in, and the passphrase field is empty. Same expectations as §2 step 4 on macOS.
8. **Raise paths show the current queue (emit before show).** Raise the approvals window through the tray icon, the taskbar, and the toast click. Expected: the first painted frame already lists the current queue. Same expectations as §3 step 5a on macOS.
9. **Batch approve with a held Enter.** On the native Confirm dialog, hold Enter while the dialog appears. Expected: it does not confirm. Only a deliberate press after the dialog is shown confirms the batch. Hold duration and the key to use (set M10 T36b): as in §4 step 5, hold Enter about 2 s, then confirm with a click or one press of Space. Same expectations as §4 step 5.
10. **Bidi control characters.** Use the sample value from §4 step 6 in an editable value field and in the Detail view. Expected: the RLO and isolate characters are shown visibly neutralised, and the surrounding text does not reorder. Sample value (set M10 T36b): the one in §4 step 6.
11. **window.open refusal and canary.** Use the payload from §4 step 7. Expected: no new window opens, `window.__pwned` stays unset, and the window title is unchanged. Release builds have no devtools. Payload (set M10 T36b): the one in §4 step 7.
12. **Shutdown texts.** Covered by item 2 above. Not repeated here.

## 10. Reporting

- Any FAIL goes to the lead with the evidence file name, the build id and the architecture.
- Items marked N/A need a reason in the table.
- Do not publish screenshots or recordings to the repository or to any shared channel without the lead's approval.

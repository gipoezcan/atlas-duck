# macOS GUI release checklist (M6)

Tester-facing checklist for the atlas-duck approvals UI on macOS. Run it once per architecture:

- **arm64** (Apple silicon) on native hardware.
- **x86_64** (Intel) on native hardware. Do not substitute a Rosetta run for this arch; mark the row N/A and tell the lead if no Intel Mac is available.

Spec references: §13 (macOS GUI release checklist), §1.4 (SC3), §5.6 (approvals UI), §6.4 (rendering safety), §7.7 (paths and screenshot storage), §10.3 (credential window), §15 (verification items). Plan: Task 35.

## 0. Before you start

1. Record the build id from the installer's About panel or the `atlas-duck --version` output. Write it in the evidence table (section 5).
2. Confirm the build under test is the one attached to the release candidate, and that the checksum matches the one the lead gave you. Checksum: **TBD by lead**.
3. Screenshots and recordings go **outside the repository**, in the test-evidence folder the lead names. Do not commit them (spec §7.7). Folder: **TBD by lead**.
4. Use a clean macOS user account, or a user with no prior atlas-duck data at `~/Library/Application Support/atlas-duck`. Note in the evidence table if you reused an account.

### 0.1 Start the mock Jira endpoint

The mock Atlassian servers are created inside the `cli_flows` test harness (`app/src-tauri/tests/cli_flows/harness.rs`, `World::new` and `MockDc::start` in `crates/atlassian/src/testing/mock_dc.rs`). They run only inside a `cargo test` process. Testers have no cargo-free way to start them, and this checklist does not invent a standalone command.

Step: **ask the lead for the mock Jira endpoint** (base URL, PAT canary value, and the instance alias to use). Record the URL and the alias in the evidence table.

> Note for the report: a cargo-free mock start command is not documented yet. If the lead provides a standalone runner, replace this step with its command.

## 1. Install

For each architecture:

1. Mount the `.dmg` for the build under test. File name: **TBD by lead**.
2. Drag atlas-duck to Applications, then launch it from Applications.
   - Expected: no "damaged" or unidentified-developer dialog. If Gatekeeper blocks it, stop and record the dialog text as FAIL.
3. Expected: the first-run wizard opens. If the approvals window opens instead, FAIL.

## 2. First-run wizard

1. Work through the wizard in its order: create the store, add the mock Jira instance (URL from 0.1), paste the PAT.
2. Expected: the connection test succeeds against the mock. The PAT is stored in the macOS Keychain; it does not appear in any log or on screen after entry.
3. Expected: the wizard finishes and the approvals window stays closed until something is submitted.

## 3. CLI submit, toast, reopen, approve

1. In a Terminal, submit a Jira create through the CLI against the mock instance (command: **TBD by lead**, the M6 CLI example is not yet fixed in the plan).
2. Expected: a toast appears saying a request is waiting for approval.
3. Click the toast. Expected: the approvals window opens and shows the request.
4. Close the approvals window with the red button. Expected: the window hides, and atlas-duck keeps running (menu bar icon remains).
5. Click the Dock icon. Expected: the approvals window reopens (`RunEvent::Reopen`). Note any delay.
6. Find the request again and try to approve it **immediately** after it appears. Expected: the Approve button is disabled for the first 1 s after focus or after the candidate changes (inert period, §5.6). Record the observed delay.
7. Wait until the inert period passes, then approve.
8. Expected: the CLI process that submitted the request exits with code **0** and prints a receipt. Check with `echo $?`.

## 4. Deny, redaction, preview

1. Submit a second request, then deny it in the UI.
   - Expected: the CLI exits with code **3**.
2. Submit a request whose body contains a value the tester is told to redact (sample: **TBD by lead**). In the approvals window, open the redaction edit, mask the value, and approve.
   - Expected: the CLI read result shows `redacted: true`.
3. Open the preview of a Confluence page update with a small diff.
   - Expected: the preview renders in a sandboxed frame with the diff styling applied. Plain unstyled text in the diff means `preview.css` did not load: FAIL and report to the lead (sha256 contingency is the lead's ruling, PD-92 / V24).
4. Expected: the approvals window opens and responds to clicks. A window that stays blank or hangs on the first click means the isolation origin is wrong on this build (V34 / §6.4): FAIL, record the Developer Tools console error.

## 5. Quit, shutdown and restart

1. With no write in flight, press Cmd+Q.
   - Expected: atlas-duck quits without a dialog. The shutdown screen (if shown) says "atlas-duck is saving its log before shutdown".
2. Relaunch. Expected: the approvals window and tray behave as in section 3.
3. Start an approved write, then press Cmd+Q **while the write is on the wire** (use the mock's delay setting, if the lead provides one: **TBD by lead**).
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

## 7. Tray and menu

1. Use the tray icon to show the approvals window.
2. Expected: the window appears and gains focus.
3. Hide it, then use "Quit" from the tray menu.
   - Expected: same behaviour as Cmd+Q in section 5, step 1.
4. Press each Cmd+Shift chord from the approvals window's help list (list: **TBD by lead**).
   - Expected: the chord performs the action listed, or does nothing if the window is not focused.

## 8. Evidence table

Fill one row per check, per architecture. Mark each item `PASS`, `FAIL` or `N/A` (with a reason).

| Date | Tester | Arch | Build id | Item | Result | Evidence (file name outside repo) |
|------|--------|------|----------|------|--------|-----------------------------------|
|      |        | arm64 / x86_64 |  | 1. Install and Gatekeeper |  |  |
|      |        |      |  | 2. Wizard and Keychain PAT |  |  |
|      |        |      |  | 3.1 CLI submit and toast |  |  |
|      |        |      |  | 3.3 Toast opens approvals |  |  |
|      |        |      |  | 3.5 Hide keeps running |  |  |
|      |        |      |  | 3.5 Dock reopen (RunEvent::Reopen) |  |  |
|      |        |      |  | 3.6 Inert period (1 s) |  |  |
|      |        |      |  | 3.8 Approve exit 0 with receipt |  |  |
|      |        |      |  | 4.1 Deny exit 3 |  |  |
|      |        |      |  | 4.2 Redaction gives `redacted: true` |  |  |
|      |        |      |  | 4.3 preview.css loads (V24) |  |  |
|      |        |      |  | 4.4 Isolation origin, no hang (V34) |  |  |
|      |        |      |  | 5.1 Cmd+Q idle, shutdown text |  |  |
|      |        |      |  | 5.3 Cmd+Q with write on wire, waits, no hang |  |  |
|      |        |      |  | 5.4 APP_STOP {quit} logged, Verify now |  |  |
|      |        |      |  | 6. Credential window private (V35) |  |  |
|      |        |      |  | 7. Tray show, tray quit |  |  |
|      |        |      |  | 7.4 Cmd+Shift chords |  |  |

Also record: mock Jira URL and alias (from 0.1), macOS version, hardware model, whether the account was reused.

## 9. Windows manual items

These run on Windows, not on the macOS hosts, and are listed here so they are not lost. Record them in the same evidence table format, with Arch set to `x64` or `arm64` as applicable.

1. **Hidden end-session window in the taskbar.** Start atlas-duck, then sign out or shut down. Expected: no visible taskbar entry for the hidden end-session window.
2. **Shutdown with a write on the wire.** Expected: the block reason reads "atlas-duck is finishing an approved write" only while a write is in flight. Otherwise it reads "atlas-duck is saving its log before shutdown" (the second text is the lead's ruling, T29 review). Confirm both texts, and that "Shut down anyway" works.
3. **WebView2 fixed-version runtime on a local disk.** A runtime on a UNC share is blocked by NoRemoteImages. Expected: the app starts with the runtime on a local disk, and fails visibly with the runtime path if the runtime is on a share.
4. **Hardening DLL restrictions.** Expected: no DLL-load failure dialog during normal use.
5. **Crash-report directory.** After a forced WebView2 renderer crash (if you can produce one safely), check that the Crashpad reports directory is cleared at next start (V30). Record whether reports were written locally.

## 10. Reporting

- Any FAIL goes to the lead with the evidence file name, the build id and the architecture.
- Items marked N/A need a reason in the table.
- Do not publish screenshots or recordings to the repository or to any shared channel without the lead's approval.

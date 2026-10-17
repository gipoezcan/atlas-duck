# SC3 informal timed walkthrough (M6)

Informal protocol for spec §1.4 (SC3): a reviewer can decide on a typical approval in under about 10 s, thanks to the preview. The 1 s inert period after window focus or a candidate change (§5.6) counts against that budget.

This is a small, informal check with a few reviewers. It is not a benchmark. Record times honestly, including slow ones.

## 1. Setup

1. Use a build from the same release candidate as the macOS checklist. Record the build id in the results table.
2. Use the mock Jira endpoint the lead provides (ask the lead; there is no cargo-free start command yet, see `docs/release/macos-gui-checklist.md` section 0.1).
3. Each reviewer sees the approvals window cold: close it, and make sure no request is currently focused.
4. Use a stopwatch (phone or desktop timer). The tester runs it, not the reviewer.
5. Keep the reviewer's hands off the keyboard until the stopwatch starts.

## 2. Timing rule

- **Start:** the moment the approvals window gains focus on the request (not when the CLI command was sent, and not when the toast appeared).
- **Stop:** the moment the reviewer clicks Approve or Deny (or presses the key that does so). Stop at the decision, not when the CLI exits.
- The inert period is included. If the reviewer tries to decide during the inert period, the timer keeps running until the decision button becomes active and is pressed.
- Target: **under about 10 s** per decision, including the 1 s inert period.
- If a decision needs a redaction edit, time the edit as part of the decision.

Record: start time (stopwatch reading), decision time (stopwatch reading), elapsed time, and whether the reviewer had to re-read the preview (yes/no).

## 3. Reference scenarios

Run each scenario once per reviewer. Use the same order for every reviewer, and vary the order between reviewers if you can (sequence: **TBD by lead**).

| # | Scenario | Setup | What to decide |
|---|----------|-------|----------------|
| S1 | Approve a Jira create | A `jira.issue.create` request with a short summary and description | Approve |
| S2 | Approve a comment with a redaction edit | A comment on a Jira issue containing one value to mask | Edit the redaction, then approve |
| S3 | Deny a batch | A batch of several operations (count: **TBD by lead**) | Deny the whole batch |
| S4 | Release a Confluence page read | A Confluence page of about 5,000 words (the fixture page the scenario reads; the word count describes the fixture, not this document). Submit with `atlas-duck confluence page get <PAGE_ID> --reason "M7 SC3 walkthrough: read Confluence page"` | Release. The reviewer opens the request on the **Preview** tab (default), reads the page render, then decides |
| S5 | Approve a small Confluence page update | A `confluence.page.update` with a small Markdown diff. Submit with `atlas-duck confluence page update <PAGE_ID> --base-version <N> --body "<markdown>" --reason "M7 SC3 walkthrough: approve Confluence page update"` (`<PAGE_ID>`, `<N>` and the body: **TBD by lead**) | Approve. The reviewer opens the request on the **Preview** tab (default) and checks the diff styling, then decides |

S4 and S5 follow the same timing rule (section 2). Tab labels in the approvals window are Preview, Structured, Raw and Request; Preview is the default. The reviewer may switch tabs, and a tab switch counts as a re-read of the preview (record it as Y).

Substitution if the lead prefers the spec's SC3 reference list instead: **TBD by lead**. The spec list (§1.4) includes `jira.issue.get`, `jira.search` with 50 rows, a Confluence page of about 5,000 words, `jira.issue.create`, a small `confluence.page.update` diff, and a 200-row script result. Only use it if the lead names it.

## 4. Protocol per reviewer

1. Brief the reviewer in one sentence: "Decide each request as you would in real use. Approve or deny."
2. Do not explain the preview or the inert period.
3. Start the stopwatch at focus, as defined in section 2.
4. Record the result in the table below, immediately.
5. Ask one question after the last scenario: "Was anything in the window confusing?" Write the answer verbatim.

## 5. Results table

Fill one row per reviewer per scenario. Times are in seconds, to one decimal place.

| Reviewer (initials) | Role | Scenario | Start (s) | Decision (s) | Elapsed (s) | Under 10 s? (Y/N) | Decision (Approve/Deny) | Re-read preview? (Y/N) | Notes |
|---------------------|------|----------|-----------|--------------|-------------|--------------------|-------------------------|------------------------|-------|
|  |  | S1 |  |  |  |  |  |  |  |
|  |  | S2 |  |  |  |  |  |  |  |
|  |  | S3 |  |  |  |  |  |  |  |
|  |  | S4 |  |  |  |  |  |  |  |
|  |  | S5 |  |  |  |  |  |  |  |

Summary to record after all reviewers:

- Number of reviewers: **TBD by lead** (aim for a few).
- Median elapsed time per scenario.
- Number of decisions over 10 s, and the scenario each one came from.
- Verbatim confusion notes.

## 6. Reporting

- Store the raw table and any screen recordings outside the repository (spec §7.7). Location: **TBD by lead**.
- Do not commit results to the repository.
- Report the summary to the lead, plus the build id and the mock endpoint alias used.
- If any scenario is consistently over 10 s, report it as a finding. Do not adjust the target to make the result pass.

# atlas-duck v1 go/no-go record

M10 Task 33. Read by `ci/check-release-go-no-go.mjs` in release.yml's `release-go-no-go` job, together
with `docs/release/release-checklist.md`. The checker is red on this file until the fields below are
filled by a human. That is intended: it keeps `upload` blocked.

Before tagging, a human fills the Decision section (verdict `GO`, the release-candidate commit R, the
build id, the date and the named reviewer), turns every open item below into a resolved line with the
answer, and every checklist row is `PASS`, `N/A: <reason>` or (tag-run rows only) `verified by job <name>
in the tag run`.

`commit` is R: the commit whose CI and manual evidence the checklist cites (the run URLs are runs of R).
A file cannot contain the hash of its own commit, so the tagged commit is R plus a docs-only change: the
checker (given `--commit $GITHUB_SHA`) requires that R is an ancestor of the tagged commit and that
`git diff --name-only R <tagged commit>` lists only `docs/release/go-no-go-v1.md` and
`docs/release/release-checklist.md`. `docs/release/` is not bundled into any package, so the tagged
commit builds source-identical to R. The tag run builds and ships the tagged commit, and its own jobs
re-verify the signed packages (rows marked as tag-run rows in the checklist).

## Decision

- verdict: NO-GO
- commit:
- build id:
- date:
- reviewed by:

The verdict stays `NO-GO` until the named reviewer (Q7) sets it. `reviewed by` is a required field: the
checker fails while it is empty or holds a placeholder such as `none`, `n/a` or `<name>`.

## Open items

Human decisions (the plan's section "Human decisions (Q1-Q7, Q13)") and recorded gaps. Each list item
has the form below. The checker fails a GO record that has any line with the open marker, in any list
form and under any heading, and a resolved item must carry its answer.

```
- [open] <id>: <text>
- [resolved] <id>: <the answer>
```

- [open] Q1: Windows Authenticode identity: certificate type and provider (OV or EV PFX, cloud HSM, Azure Trusted Signing or another service), who holds it, the timestamp server URL, whether EV and SmartScreen reputation matter for the first release. Long lead time. Blocks the first release run and the "signing verification" row.
- [open] Q2: macOS Developer ID: the Developer ID Application identity name and Team ID, and who owns the Apple Developer account. Long lead time. Blocks the first release run and the I-45 row on the signed `.app`.
- [open] Q3: Notarization credentials and secret plumbing: App Store Connect API key or Apple ID with an app-specific password, the environment name (`release` is the placeholder), its required reviewers and the secret names. A repository admin creates the environment, limits it to `v*` tags and enters the secrets.
- [open] Q4: Bundle identifier, icons and installer identity: the final reverse-DNS identifier (it moves the NSIS install key, single-instance names and the WebView2 user data if changed later), the real icon set, product name, publisher, copyright and licence text. T25's guard fails a release tag until this is final.
- [open] Q5: Release channel: where signed artifacts are published, the tag and version scheme, who writes the release notes, whether pre-release tags exist. `upload` is a draft GitHub Release placeholder until then.
- [open] Q6: Linux package signing: sign (GPG key or service, key id, public key location, repository) or ship unsigned, which then needs one sentence in the docs and the release notes.
- [open] Q7: Reviewer and executors: the named go/no-go reviewer (this record), and who runs the manual checklist rows and when.
- [open] Q13: Windows 10 22H2 baseline (V32): a manual install as evidence, or a self-hosted runner. Blocks the `windows-10-22h2-install` row and D11's manual half.
- [open] backup-verify: spec 8.7 describes a backup check at offboarding, but the CLI has no `verify-backup` command (T32). Add the command or reword the spec; until then decommissioning has no real check of the backup.
- [open] macos-cli-usr-local-bin: spec 12.3 describes an admin variant of Install CLI that writes to `/usr/local/bin` on macOS. The app installs only to `~/.local/bin` (T32). Build the variant or drop it from the spec.
- [open] tray-anchor-dir-lines: known gap (T21b). Settings shows the anchor-dir status lines; the tray menu and tooltip do not, because the tray is built without the core and shares this gap with `anchor_write_failing`. The release notes and docs must not say the tray shows them. Follow-up: T36. Resolve by accepting the gap for v1 (state it here) or by closing it.

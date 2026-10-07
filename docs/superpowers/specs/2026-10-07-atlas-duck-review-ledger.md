# atlas-duck spec — review ledger

Companion to `2026-10-07-atlas-duck-design.md`. Records what each automated review round changed, which behaviour/scope decisions were applied **provisionally** (pending the user's confirmation), which decisions are still open, and what was deferred.

Reviewers: entries under "Applied — pending user confirmation" are settled for the purpose of the review loop; do not re-litigate them. Entries under "Open decisions" are intentionally not applied.

Severity scale used by the loop:
- **P0** — a core guarantee can be violated (a write executes without approval of exactly that payload; unreleased Atlassian data reaches the agent; a read or write escapes the audit log; a credential leaks) or the spec is unimplementable as written.
- **P1** — a significant gap/contradiction that would cause a real incident in normal use or force a redesign during implementation.
- **P2/P3** — everything else.

## Applied — pending user confirmation

(From the brainstorming revision, before the loop.)
- Read upstream errors are approval-gated (§5.2 step 6).
- Script failures after any fetch are approval-gated (§9.5).
- Scripts disabled when the sandbox floor cannot be verified (§9.4).
- CLI default timeout 100 s; MCP default 50 s (§4.1, §4.6).
- Batch approve requires every item opened + native confirmation (§5.6).
- Target params read-only in the edit form (§5.4).
- No server-side Confluence preview render before approval (§5.4, §7.6).
- Separate credential-entry window (§10.3).
- Retention minimum 92 days (§8.8).

## Open decisions (not applied)

## Deferred to v1.1

## Round log

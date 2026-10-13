# atlas-duck M5 (Jira adapter + previews) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. One implementer subagent per task, one reviewer after each task. Each task below is self-contained: it names every file it touches, the interfaces it consumes from earlier tasks and the ones it must produce, and the tests with the assertions that matter.
>
> **Model policy for the executing agents:** implementers use **Sonnet (effort medium)**; every reviewer uses **Opus**; the security-critical or complicated tasks are implemented by **Opus** as well (marked `Model: Opus` in the task header: the wiki parser, the Markdown→wiki escaping and the re-parse hard check, the validation wiring of conversions, the metadata-cache `SYSTEM_FETCH`, the composite `--comments` read, staged enrichment and name resolution, the `expected` conflict check and edit diffs, the extended write paths with stale rules, the identity/recheck sweep, the write-scoped audit cover). Never Fable. Haiku (effort high) may do pure doc edits the lead asks for.
>
> **Hard execution limits (corporate AV, memory `agent-execution-limits`):** no subagent downloads or runs executables or installers, no `cargo install`, `pip install`, `npm install -g`; no `icacls`, registry or ACL changes on the developer machine; no `taskkill`/`kill` of processes; nothing outside the repo and the session scratchpad (not `/tmp`, not `%TEMP%`). **`jira_flows` (like `cli_flows`) spawns the real app and CLI binaries and therefore runs in CI only**: an implementer compiles it (`cargo test … --test jira_flows --no-run`) and runs its pure helpers, never the spawning flows (they skip without `ATLAS_DUCK_CLI_FLOWS=1`; do not set it locally). The live L-01 tests need a real Jira DC (a Docker trial image would be a download): they are `#[ignore]` + env-gated, and no agent runs them (Task 24).

**Goal:** Complete the 28 Jira operations end to end: the Markdown→Jira-wiki converter with the code-body rule and the re-parse hard check, a local wiki→preview renderer, Jira-specific previews (issue card, search/list tables, create card, edit diffs, transition, assign/link/worklog/sprint summaries) with the §6.2 warning levels, the remaining five write executors with their enrichment, name resolution and stale rules, the `jira.issue.create` missing-required-fields warning with the Rust side of the edit form and the `missing_fields` deny details, `jira.issue.get --comments`, `meta.page` semantics on every paginated Jira op, the `X-AUSERNAME` behaviour on Agile/search answers (RF-5b), plus the M3 carry-overs M5 owns, all proved in-process against wiremock and end to end through the real binaries (`jira_flows`).

**Architecture:** `convert` (pure functions, no I/O) gains `md_to_wiki`, a wiki tokenizer/parser shared by `hard_check_wiki` and `wiki_to_preview_html`, and a text projection for the rendered diff. `preview` gains Jira body variants, a line diff, and the `EditForm` model (Rust side only; M6 renders it). `core::ops::jira` gets real executors, staged enrichment rules (Δ C.7), stale rules and Jira previewers; `core::engine` gets the composite `--comments` read, staged-enrichment driving, the per-instance Jira field-name cache (`SYSTEM_FETCH {purpose: metadata_cache}`) and the write-scoped cover. `atlassian` changes only for two M3 carry-overs (paging end test, 429 answer) and the write cover type. `app/src-tauri` gains the `jira_flows` test target over the M4 `cli_flows` harness. No new workspace crate, no new process, no IPC change.

**Tech Stack:** Rust 1.95.0 (edition 2024, MSRV 1.90), `pulldown-cmark =0.13.4` (new, `default-features = false`), existing pins otherwise (tokio 1.53.2, serde_json 1.0.151, ammonia 4.2.3, wiremock 0.6.5, proptest 1.11.0, jsonschema 0.58.6). Full table in "Dependency pins".

**Spec:** `docs/superpowers/specs/2026-10-07-atlas-duck-design.md` (+ ledger `docs/superpowers/specs/2026-10-07-atlas-duck-review-ledger.md`, L01–L83). **Master plan:** `docs/superpowers/plans/2026-10-07-atlas-duck-master-plan.md` (M5 entry; contracts C.1, C.4, C.5, C.6, C.7; Placements "core then extended"; RF-5). **M3/M4 plans:** `2026-10-07-atlas-duck-m03-core-lifecycle.md` (PD-09, PD-10, Task 18 and Task 22 "As built"), `2026-10-07-atlas-duck-m04-ipc-cli.md` (the `cli_flows` harness, PD-01..PD-03, Task 26 CI). **Ledgers:** `.superpowers/sdd/2026-10-07-atlas-duck-m03-core-lifecycle/final-review.md` (M-16, M-18, deferred table), its `task-10-review.md`, `task-24-review.md`, `task-26-review.md`/`task-26-report.md`, `task-29-review.md`; `.superpowers/sdd/2026-10-07-atlas-duck-m04-ipc-cli/progress.md`.

**Prerequisite:** M1–M4 merged on `master` (true at `b09adf1`); branch `m5-jira-adapter`. Before Task 1 the lead applies the contract deltas Δ1–Δ7 below to the master plan (C.4, C.5, C.6, C.7) and records the ledger entries listed under "Ledger entries the lead adds" (L84 onward); the plan's code already assumes them.

---

## What exists for Jira on `master` (b09adf1) and what M5 adds

Checked in `crates/registry/src/jira/*`, `crates/core/src/ops/{mod,jira,generic,stale}.rs`, `crates/core/src/validate/mod.rs`, `crates/core/src/decision/mod.rs`, `crates/core/src/engine/{read,write}.rs`, `crates/preview/src/*`, `crates/convert/src/lib.rs` (empty).

| Op | Registry spec (M3) | Executor | Enrichment / resolution | Stale rule | Previewer | M5 adds |
|---|---|---|---|---|---|---|
| `jira.myself`, `project.list`, `project.get`, `comment.list`, `worklog.list`, `transition.list`, `issue.editmeta`, `createmeta.issuetypes`, `createmeta.fields`, `field.list`, `issuelinktype.list`, `attachment.meta`, `user.assignable`, `board.list`, `sprint.list` (15 reads) | complete | `generic::read_executor` | — | — | `generic::fallback_preview` (JSON tree) | list-table previewers (T11), X-09 case each (T22) |
| `jira.sprint.issues`, `jira.backlog.issues` | complete | generic paged | — | — | fallback | search-style table (T11), `meta.page` tests (T11) |
| `jira.issue.get` | complete | `jira::issue_get_executor` (`changelog`/`rendered` → `expand`); **`comments: true` is accepted and inert** (M3 PD-09) | — | — | fallback | composite `--comments` read (T09), issue card + §6.2 warnings + U-27 (T10), field-name cache (T08) |
| `jira.search` | complete | generic search (`POST`, the allowlisted one) | — | — | fallback (+ JQL in `PreviewModel.query`) | search table (T11), I-09 budget probe (T11), RF-5b (T19) |
| `jira.issue.create` | complete | `issue_create_executor` (wiki only; markdown **rejected** at validation, M3 PD-09) | issuetype resolution only (createmeta issuetypes); **no project resolution, no createmeta fields** | none (spec) | `generic::write_preview` (request list) | md→wiki (T07), staged enrichment: project + issuetype + required fields, `missing_fields` deny details, edit form (T12), create card (T12) |
| `jira.issue.edit` | complete | `issue_edit_executor` | `expected` vs current by JSON equality, conflict hold | `stale::ISSUE_EDIT` | request list | edit diffs + `raw_only_diff` + conflict card with diff (T13), I-36 Jira half (T13) |
| `jira.comment.add` | complete | `comment_add_executor` (wiki only) | — | none (spec) | request list | md→wiki (T07), comment preview (T14) |
| `jira.issue.transition` | complete | `issue_transition_executor` | transition resolution + from-status | `stale::ISSUE_TRANSITION` | request list | transition preview (T14) |
| `jira.issue.assign` | complete (`assignee: string|null`) | **`LATER_WRITE`** (`NotInThisBuild` → `internal` at validation) | — | — | fallback | executor, assignable-user resolution, stale rule, preview (T15) |
| `jira.worklog.add` | complete | **`LATER_WRITE`** | — | none (spec) | fallback | executor + preview (T17) |
| `jira.issuelink.create` | complete (`success {[201], Empty}`) | **`LATER_WRITE`** | — | none (spec) | fallback | executor, link-type resolution, preview, I-25 op cases (T16) |
| `jira.sprint.move_issues` | complete (`move_limit: 50`) | **`LATER_WRITE`** | — | — | fallback | executor, sprint-state enrichment, stale rule, preview, U-02, I-06 moves, RF-4 move seeding (T18) |
| `jira.backlog.move_issues` | complete (`move_limit: 50`) | **`LATER_WRITE`** | — | none (spec) | fallback | executor, preview, U-02 (T18) |

Already built and only re-used (do not redo): `meta.page` (`engine/read.rs::release_meta`), the redaction engine incl. `ISSUE_COPIES`/`ISSUE_MIRRORS`/`SEARCH_MIRRORS` and the mirror check (`core::redact`), the 50-issue move limit (`validate/caps.rs::move_limit`), `edited_keys`/`executed_params` (`core::edit`), `recheck_failed` classes (`engine/write.rs::recheck_failed`), `DenyDetails::{UpstreamHttp, OutcomeHint, ResolutionFailed}` (`decision/mod.rs`), the similarity index incl. move-key seeding code (`similarity.rs`), the per-response `X-AUSERNAME` check and coalesced `token_recheck` (`identity.rs`), the `TestHooks::read_budget` hook, `MockDc` (`atlassian::testing`), and the `cli_flows` `World` harness (`app/src-tauri/tests/cli_flows/harness.rs`).

---

## Global Constraints

The master plan's "Global Constraints" apply verbatim; read them once before Task 1. The subset M5 touches most:

- **Dependency rule (§2.2, `node ci/check-workspace.mjs`):** `convert` and `preview` depend on no workspace crate except what they have (`preview` none; `convert` none); `core` keeps its exact six edges; `atlassian` stays a leaf. `convert` external deps: `pulldown-cmark` only (+ `proptest` dev); never `reqwest`, never I/O.
- **Audit-before-effect (§5.1 inv. 1):** every new GET (enrichment stage, resolution lookup, stale-check GET, comment pages of `--comments`, the metadata-cache fill) runs under an `AuditCover` minted only after its covering record committed (`REQUEST_RECEIVED` for request GETs, `SYSTEM_FETCH {phase: start}` for the cache fill), and each response is recorded (`PREVIEW_FETCH {purpose}`, `READ_FETCHED`, `SYSTEM_FETCH {phase: result}`). Writes are sent only with the write-scoped cover of Task 20 from that task on.
- **Method guard (§5.1 inv. 3):** enrichment, resolution, stale checks, the cache fill and the comment pages are GET-only; the only read `POST` stays `POST /rest/api/2/search`; every write is exactly one HTTP request (L13).
- **Opacity (§4.5):** before a decision only `pending`; no resolution result, missing-field list, sprint state, conflict text, field name or diff ever reaches an envelope, `details` or progress notification except through a deny hint the user chose (§4.3 `denied` rows).
- **Static validation (§2.3):** conversion and the hard check depend only on the params; nothing fetched influences pass/fail or error text. The metadata cache is display-only and never feeds validation.
- **Text rules:** every Atlassian- or agent-derived string that reaches a preview, a Caution text, a deny hint `message` or a dialog goes through `preview::invisible::escape_for_display`; previews render links as text, never load a remote resource; the wiki renderer ignores `{color}` and similar styling (§6.4); preview HTML always passes `preview::sanitize_html`.
- **Lints and panics:** `clippy -D warnings`; `unwrap_used`/`expect_used` errors in `core`, `atlassian` **and now `convert`** (Task 1 adds the crate-level `#![deny(..)]` like `atlassian`), tests return `TestResult`; `node ci/check-no-panic-macros.mjs` scans `convert/src` from Task 1 on. `preview` follows the same rule by convention.
- **Secrets and logs:** no JQL, params, field names, field values, wiki text, usernames or Atlassian error text in any `tracing` line; new diag events carry constants and ids only.
- **Fixed strings** are copied verbatim from the spec section that defines them, each constant with a `/// §x.y (verbatim)` doc comment; plan-text strings carry `/// plan text (PD-xx)`.
- **Tests:** integration tests in `crates/<crate>/tests/`; each file starts with `type TestResult = Result<(), Box<dyn std::error::Error>>;`; async tests `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]`; core tests run with `--features atlas-duck-atlassian/testing,atlas-duck-core/testing`; Unix-/Windows-only tests are `#[cfg]` modules, never runtime skips; `#[ignore]` reasons are a `const IGNORE: &str` naming the CI step (or "manual live run") that runs them.
- **Commits:** one commit per task (more where a task says so), message `<type>(<crate>): <summary>`, trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (Opus tasks: `Claude Opus 5.5`); explicit pathspecs (never `git add -A`); every cargo command uses `--locked` after the task that changes `Cargo.lock` (Task 1) has run its one unlocked build.

---

## Dependency pins

Verified 2026-10-13 against crates.io (`/api/v1/crates/pulldown-cmark`: newest 0.13.4, published 2026-05-20, MIT, `rust_version` 1.71.1; default features `getopts`, `html`). Existing workspace pins are reused.

| Crate | Pin | Features | Added by | Used in | Why |
|---|---|---|---|---|---|
| `pulldown-cmark` | `=0.13.4` | `default-features = false` (drops `getopts`, a CLI-only dep, and `html`, which we never use: our renderers emit wiki markup and, in M7, storage XHTML) | T01 | convert | §7.6 names `pulldown-cmark`; event stream with `into_offset_iter()` source spans (M7's placeholder check needs them too). After adding: `cargo tree -p atlas-duck-convert -e normal` must show only `pulldown-cmark` and its own deps (`bitflags`, `memchr`, `unicase`; stop and report on anything network- or I/O-related); `cargo deny check` runs in CI (`supply-chain`), not locally |
| `ammonia` | `=4.2.3` (existing) | — | — | preview (sanitizing `wiki_to_preview_html` output) | §6.4 |
| `proptest` | `=1.11.0` (existing, dev) | — | T04 | convert (fuzz of the hard check) | §13 "golden and fuzz tests" |
| `jsonschema` | `=0.58.6` (existing, dev in core) | — | T22 | core X-09 (fixture bodies validate against `result_schema`) | |
| `wiremock` | `=0.6.5` (existing) | — | — | core tests, `jira_flows` | |

No diff crate is added: the edit preview's line diff is a small in-house Myers implementation in `preview::diff` with a size cap (PD-51), so no unverified pin enters the TCB.

**No new test-only feature (PD-64).** U-24's "test-injected converter fault" is injected inside `core` under its existing, already-locked `testing` feature (`TestHooks::converter_fault`, Task 7), which appends one unrecorded construct to the converter's output before the hard check; `convert` itself stays feature-free (its own fault test builds the faulty output in the test). So the `scripted-approver` app build gains no new test code path beyond the inert `core/testing` hook, and the feature-leak check (`cargo tree -p atlas-duck-app -e normal,build --target all --locked --format "{p} [{f}]" --prefix none`) keeps its M4 pattern unchanged.

---

## Plan decisions and contract deltas

Tagged **(spec silent)** where the spec does not say; **(spec gap → ledger)** where the lead adds a ledger entry and, where named, a spec line before the task merges (master plan rule: "A milestone plan never resolves a gap silently"); **Δ C.x** = master-plan contract change the lead applies before Task 1. PD numbering continues after the M4 plan (PD-01..PD-41).

**Contract deltas (applied before Task 1):**
- **Δ1 C.5 `convert` (Jira half), names fixed.** `pub fn markdown_to_wiki(md: &str) -> (String, EmittedConstructs)`; `pub fn hard_check_wiki(wiki: &str, e: &EmittedConstructs) -> Result<(), Unrecorded>`; `pub fn wiki_to_preview_html(wiki: &str) -> String`; additive: `pub fn wiki_to_text(wiki: &str) -> String` (the text projection of the renderer's output used by the Jira rendered diff, §6.3 "Edit/update") and `pub fn wiki_constructs(wiki: &str) -> WikiConstructs` (the inventory the write previews list, §7.6 "The preview lists every macro, mention, include and link target present in an outgoing payload"). Types: `pub struct EmittedConstructs { pub code_blocks: Vec<EmittedCode> }` with `EmittedCode { pub kind: CodeKind /* Code | Noformat */, pub byte_range: std::ops::Range<usize> }` (the converter's own containers, by position in its output); `pub struct Unrecorded { pub kind: ConstructKind, pub count: u64 }` (no text, no offset: the error must not echo the body); `pub enum ConstructKind { Macro, Mention, Include, Image, Attachment }`; `pub struct WikiConstructs { pub macros: Vec<String> /* names */, pub mentions: Vec<String>, pub includes: Vec<String>, pub links: Vec<String> /* targets */, pub images: Vec<String>, pub attachments: Vec<String> }`. All pure, no I/O, no panics, deterministic.
- **Δ2 C.6 `preview` additions.** `PreviewBody` gains `JiraIssue { card: IssueCard, fields: Vec<FieldRow>, description_html: Option<String>, comments: Vec<CommentView> }`, `Table { columns: Vec<String>, rows: Vec<Vec<String>>, count: Option<ItemCount> }`, `WriteSummary { sentence: String, rows: Vec<(String, String)>, constructs: Option<ConstructList>, requests: Vec<RequestView> }`, `EditDiff { rendered: Vec<DiffLine>, raw: Vec<DiffLine>, raw_only_changes: u64, requests: Vec<RequestView> }`, `Transition { from: String, to: String, fields: Vec<(String, String)>, requests: Vec<RequestView> }` (every string display-escaped by core; `requests` keeps §5.1 inv. 4: the exact list is part of every write body). New module `preview::diff` (`pub fn line_diff(old: &str, new: &str) -> Vec<DiffLine>`, `DiffLine { pub op: DiffOp /* Same | Add | Del */, pub text: String }`, `DIFF_MAX_LINES = 20_000`; larger inputs → one Del-all/Add-all hunk). `Preview` gains `pub edit_form: Option<EditForm>` with `EditForm { pub inputs: Vec<EditInput> }`, `EditInput { pub path: String /* param name or "fields.<id>" */, pub label: String, pub kind: InputKind, pub read_only: bool, pub required: bool, pub pre_added: bool, pub value: serde_json::Value }`, `InputKind { Text, LongText, Integer, Boolean, Json, Choice { allowed_values: Vec<String> /* ≤ 10 */ } }` (Rust side of §5.4 step 4's edit form; M6 renders it). `PreviewHeader` is unchanged.
- **Δ3 C.7 staged enrichment.** `EnrichRule { plan, judge }` becomes `EnrichRule { pub plan: fn(&EnrichCtx<'_>, &[Value] /* answers so far, in order */) -> EnrichStep, pub judge: fn(&EnrichCtx<'_>, &[Value]) -> EnrichVerdict }` with `pub enum EnrichStep { Fetch(Vec<(EnrichPurpose, GetCall)>), Judge }`; the engine calls `plan` with the answers so far until it returns `Judge` (at most `MAX_ENRICH_STAGES = 4` rounds; a fifth `Fetch` is an `EnrichmentError` "internal", fail closed), then `judge` with all answers. A stage's plan may depend on earlier answers (resolved project key → createmeta). `plan` may also return `Judge` early (e.g. stage 1 unresolved: no further GET). `StaleRule` is unchanged (one round). Existing rules are wrapped mechanically (Task 12).
- **Δ4 C.7 `EnrichVerdict` additive fields.** `pub missing_fields: Vec<MissingField>` (`MissingField { id, name, schema_type, allowed_values: Vec<String> /* ≤ 10, raw names */ }`), `pub summary: Option<WriteSummaryFacts>` (resolved display facts for the write previews: from/to status, current assignee, link-type phrases, sprint name/state; display-escaped by the previewer). `DenyDetails::MissingFields { include_allowed_values }` is wired (it answers `refuse()` today, `decision/mod.rs:1421`).
- **Δ5 C.7 `PreviewCtx` additive field** `pub field_names: Option<&'a FieldNames>` (`core::metadata::FieldNames`, the cached `/rest/api/2/field` id → name map; `None` = unknown, ids shown). `ExecCtx` unchanged.
- **Δ6 C.4 write-scoped cover (M3 final review M-18).** `CommitProbe` gains `fn write_approved(&self, request_id: &str, candidate_counter: u64) -> bool`; `CoverIssuer::for_write(&self, request_id: &str, candidate_counter: u64) -> Result<WriteCover, NotCommitted>`; `InstanceClient::send_approved(_ctl)` take `&WriteCover` instead of `&AuditCover`. `core::audit_port` marks `(request_id, counter)` only after the `WRITE_APPROVED` append returned `Ok`, so a `WriteCover` exists only for a committed approval of that revision: the type now enforces what M3 guaranteed by control flow.
- **Δ7 C.7 `EffectiveCaps` additive field** `pub comments_cap: Option<u32>` (the configurable `jira.issue.get` comments cap, §7.3 "cap 100, configurable"; `None` = registry `caps.comments_cap`, 100). Settings writes it in M6.

**Plan decisions:**
- **PD-42 Which Jira params convert from Markdown (spec silent → ledger).** Only params whose op declares `body_format` convert: `jira.issue.create.description` and `jira.comment.add.body` (registry schemas; default `markdown`; `wiki` passes through verbatim). Every other text param is sent verbatim as Jira wiki markup (`jira.issue.transition.comment`, `jira.issuelink.create.comment`) or plain text (`jira.worklog.add.comment`), and every value inside `fields`/`update` maps (create, edit, transition) is Jira REST shape, verbatim. `ops describe` states it per op (Task 07 adds the sentence to the registry write guidance: "Text in `fields`, `update` and `comment` is sent as Jira wiki markup unchanged; only `description`/`body` with `body_format=markdown` are converted." (plan text)). Verbatim wiki is the agent's explicit choice (§7.6 "To produce macros/mentions, agents use `--body-format wiki`"); the previews list every construct in every outgoing wiki text (PD-47). Confluence keeps the M3 markdown refusal until M7 (the validator flip is per product).
- **PD-43 Conversion happens in the executor and is checked at validation (§5.4 step 1 "converted here").** `core::ops::jira_body::wiki_text(params, param) -> Result<Option<String>, ExecError>` converts (`markdown_to_wiki`) and runs `hard_check_wiki`; an `Unrecorded` is `ExecError::Invalid` with code `validation`, `details {param, construct: <kind>, count}` and message "markdown conversion produced an unrecorded <kind>" (plan text). The executors of create and comment.add call it **before** any `EnrichmentRequired` return, so the M3 validation dry call (handler step 8) rejects with `REQUEST_REJECTED`, exit 2, nothing queued; every later render (enrichment `Preview`, edit) re-converts the same params deterministically (`executors_deterministic` pins it), so `WRITE_APPROVED` hashes the same bytes. `validate::check_body_format` accepts `markdown` for `Product::Jira` from Task 07 on.
- **PD-44 Wiki parser taxonomy and hard-check strictness (spec gap → ledger, §7.6).** The app's wiki parser (`convert::wiki`) recognizes macros `{name}` / `{name:params}` (any name, known or unknown; `{code}`/`{noformat}` bodies are opaque), mentions `[~name]`, includes `{include…}` and `{excerpt-include…}` (counted as includes, not macros), links `[text|target]`/`[target]`, images `!target!`, attachment links `[^file]`, plus emphasis, headings, lists, tables, `bq.`, `{quote}`, `{panel}`. The hard check fails on any macro, mention or include the converter did not record (§7.6) **and also on any image or attachment link** (the converter never emits `!…!` or `[^…]`, so one in its output means escaping failed; stricter than §7.6, fail closed). Markdown images become wiki links `[alt|url]` (never `!url!`), raw HTML becomes escaped text, `@name` stays text (never `[~name]`).
- **PD-45 `jira.issue.get --comments` (merge shape spec silent → ledger).** With `comments: true` the read is composite: the issue `GET` (its `fields` minus a `comment` entry) then the `jira.comment.list` executor's paged `GET /rest/api/2/issue/{key}/comment?orderBy=created` (+ `expand=renderedBody` when `rendered`), up to `EffectiveCaps::comments_cap` (default 100), all under one request cover and recorded in one `READ_FETCHED` (page 0 = issue, pages 1.. = comment pages; the payload already holds a page list). The candidate is the issue JSON with `fields.comment = {"startAt", "maxResults", "total" (server value, unchanged), "comments": [...]}` and, when `rendered`, `renderedFields.comment = {"comments": [{"id", "body": <renderedBody>}]}` with `renderedBody` removed from the `fields` side, so the M3 mirror `fields.comment.comments ↔ renderedFields.comment.comments` (key `id`) applies unchanged (U-27). Comments beyond the cap: Info `truncated_by_cap(N, total)`; no `meta.page` (the op is not paginated). A failing comment page is a later-page failure (gated, M3 `LaterPageRefused`).
- **PD-46 Jira field-name cache (spec: "via the cached `/rest/api/2/field`; cache fills outside a request are logged as `SYSTEM_FETCH {purpose: metadata_cache}`"; when it fills is silent → ledger).** `core::metadata::FieldCache` per Jira instance, filled (a) after a passing connection test and at `Core::start` for every `ok` Jira instance, in a background task, and (b) refreshed in the background when an entry is older than 1 h at the moment a Jira read preview is built (that preview uses what is cached). Each fill is `SYSTEM_FETCH {purpose: metadata_cache, phase: start}` → `GET /rest/api/2/field` → `{phase: result}`, under the instance limiter, never under a request id; a failure keeps the old map and logs the constant event `metadata_cache_failed`. A preview build never waits on the network. Display-only: unknown `customfield_N` ids in a released issue render as "customfield_N (unknown field)" in the field table (plan text; no §6.2 warning id exists for it); nothing in validation reads the cache.
- **PD-47 Construct lists on write previews.** Every Jira write preview whose body carries wiki text (create description, comment body, transition/issuelink comment, edit `fields` string values) shows `WriteSummary.constructs` = `wiki_constructs` of the outgoing text, display-escaped.
- **PD-48 Project resolution (I-35 kind "project"; rule spec silent → ledger).** `jira.issue.create` stage 1: `GET /rest/api/2/project` (purpose `resolve`); `project` resolves to exactly one project whose `id` equals it, else whose `key` equals it ASCII-case-insensitively, else whose `name` equals it case-insensitively (`str::to_lowercase`, as M3 `resolve`); 0 or > 1 → `UnresolvedName {param: "project"}` with candidates (≤ 10 names); the request body uses `{"key": <resolved key>}` (the M3 all-digit → `{"id"}` guess is dropped). `target_params` stays `["project"]`.
- **PD-49 Missing required fields (§5.4 step 2; text and edit-form shape plan-decided → ledger for the text).** Stage 3 of create enrichment: `GET /rest/api/2/issue/createmeta/{projectKey}/issuetypes/{typeId}` (purpose `enrich`; further pages by `startAt` while `isLast == false`, at most 4 pages); a field is missing when `required && !hasDefaultValue` and its `fieldId` is set neither by a dedicated param (`project`, `issuetype`, `summary`, `description`) nor by a `fields` key. Caution `missing_required_fields(list)` with `list` = `"<name> (<fieldId>, <schema.type>)"` joined by `", "` in createmeta order (§6.2 "Team (customfield_10200, option)"), names display-escaped, at most 10 then `"… and N more"` (plan text). Approve stays enabled. The edit form pre-adds one `EditInput {path: "fields.<id>", pre_added: true, required: true, kind}` per missing field (`Choice` with ≤ 10 `allowedValues` names (`value`, else `name`) for `option`/`array` of `option`, `Integer` for `number`, `Text` for `string`, else `Json`). Deny with `MissingFields {include_allowed_values}` → `denied`, exit 3, `error.details.missing_fields: [{id, name, schema_type, allowed_values?}]` (`allowed_values` ≤ 10, present only when ticked), stored in `WRITE_DENIED`. `jira.issue.create.enrich_keys` becomes `["project", "issuetype", "fields"]`, so an edit that adds `fields.<id>` re-runs enrichment and the warning goes away (I-18).
- **PD-50 `expected` comparison (§5.4 step 2 "compared like the step 5 rule").** Equality of the JCS bytes (`ipc::jcs::to_jcs_vec`) of `expected.<id>` and the current `fields.<id>` (absent = `null`); a value JCS refuses (integer beyond ±(2^53−1)) counts as "differs" (fail closed into the conflict state). `stale::ISSUE_EDIT` uses the same helper `jira::field_values_equal`.
- **PD-51 Edit diffs and the raw-only count (§6.3; counting rule spec silent → ledger).** Raw diff: per edited field id (sorted), `line_diff` of the 2-space pretty JSON of the current value vs the outgoing value; rendered diff: for string-valued fields `line_diff(wiki_to_text(current), wiki_to_text(outgoing))`, other fields reuse the raw diff. `raw_only_changes` = Σ over string fields of `max(0, hunks(raw) − hunks(rendered))` (a hunk = a maximal run of non-`Same` lines); `> 0` → Caution `raw_only_diff(n)`. `update` operations (labels add/remove) appear as raw JSON lines only.
- **PD-52 `jira.issue.assign` (V05 unassign sentinel open → ledger).** `assignee: null` → body `{"name": null}`, no resolution; a string → stage 1 `GET /rest/api/2/user/assignable/search?username=<v>&issueKey=<key>&maxResults=50` (purpose `resolve`): exactly one user whose `name` matches under `atlassian::username_matches` (§7.2 comparison), else whose `key` equals, else exactly one case-insensitive `displayName` match → resolved `name`; otherwise `UnresolvedName {param: "assignee"}`. Stage 2 `GET /rest/api/2/issue/{key}?fields=assignee` (purpose `enrich`): baseline `{assignee_key: <key>|null, assignee_name}`. Stale rule: current `fields.assignee.key` (or null) equals the baseline key. Body `{"name": <resolved name>}`. If the live V05 run shows a different unassign sentinel, the lead changes this line and the ledger first.
- **PD-53 Link-type resolution (I-35 "link type"; rule spec silent → ledger).** `GET /rest/api/2/issueLinkType` (purpose `resolve`): `type` resolves by `id`, else case-insensitive `name`, else case-insensitive `outward` phrase, else `inward` phrase (the first rule with exactly one hit wins; a rule with > 1 hits is ambiguous and stops). Body `{"type": {"name": <resolved name>}, "inwardIssue": {"key": inward}, "outwardIssue": {"key": outward}, "comment"?: {"body": comment}}`. Preview sentence "<outward> <outward phrase> <inward> (<type name>)", e.g. "ABC-123 blocks ABC-124 (Blocks)".
- **PD-54 Sprint state at enrichment (closed sprint spec silent → ledger).** `GET /rest/agile/1.0/sprint/{id}` (purpose `enrich`): `future`/`active` → `Preview`, baseline `{state, name}`; `closed` → `Hold::EnrichmentError` with app text "sprint <name> is closed; issues cannot be moved into a closed sprint" (plan text), Approve disabled, deny offers no hint (plain reason only). Stale rule: current state ∈ {`future`, `active`}, else `Changed {delta: "sprint closed since review"}`. `jira.backlog.move_issues` has no enrichment and no stale rule.
- **PD-55 Worklog.** Body `{"timeSpent": time_spent, "comment"?: comment, "started"?: started}` (verbatim, PD-42), no enrichment, no stale rule, receipt `{id}`.
- **PD-56 Write-scoped cover** = Δ6. `engine::write::execute` is the only `for_write` caller; `send_approved` keeps the M3 outgoing byte comparison.
- **PD-57 `READ_RELEASED.candidate_rev` (M3 T29 handoff → ledger, §8.3 payload).** Every `READ_RELEASED` and `SCRIPT_RELEASED` payload gains `candidate_rev: {counter, candidate_hash}` of the released revision (additive key). U-32 then compares `PREVIEW_SHOWN.candidate_rev == *_RELEASED.candidate_rev` for every positive decision, outcome releases included.
- **PD-58 RF-5b (V25 open).** No per-endpoint-family exemption: an Agile or `POST /rest/api/2/search` answer without `X-AUSERNAME`, while `/myself` carries a matching one, runs one `token_recheck` (coalesced per instance epoch, M3 `identity::recheck`) through the limiter, logged `SYSTEM_FETCH {purpose: token_recheck}`, and the read ends `failed`, exit 6, `upstream_unavailable`, `retryable: true`, instance state unchanged, no admin hint. The check is never skipped. If V25 live shows Agile never sends the header, the lead raises a spec change first.
- **PD-59 `jira_flows` reuses the M4 harness.** `app/src-tauri/tests/jira_flows.rs` (`#![cfg(feature = "scripted-approver")]`) declares `#[path = "cli_flows/harness.rs"] pub mod harness;` and its flows in `app/src-tauri/tests/jira_flows/*.rs`; every flow starts with `harness::opted_in(..)`. `ci/cli-flows-linux.sh` takes the test target from `CLI_FLOWS_TEST` (default `cli_flows`); the macOS/Windows/Rosetta CI steps get a sibling step for `jira_flows` with the same `check-no-skips.mjs` and pass-count checks; GitHub only (as `cli_flows`).
- **PD-60 Live L-01 tests (no CI leg → ledger).** `crates/core/tests/live_jira.rs`, every test `#[ignore = "manual live run against a real Jira DC (L-01)"]`, refusing to run unless `ATLAS_DUCK_LIVE_JIRA_URL` (https), `ATLAS_DUCK_LIVE_JIRA_PAT`, `ATLAS_DUCK_LIVE_JIRA_PROJECT` (a scratch project) are set; writes only into that project; each prints `V05 …`/`V06 …`/`V23 …`/`V25 …`/`M16 …` finding lines. No agent and no CI job runs them; a human runs them once and the lead updates spec and ledger. Until then V05, V06 (Jira), V23 (Jira) and V25 (Agile/search) are design-resolved only and M-16 stays unverified.
- **PD-61 Jira recheck answer without `name`/`key` (M3 T26 review M-3 → ledger).** Aligned with §7.1 ("any other parsed JSON response … is a confirmed token failure"): a parsed Jira `/myself` 200 lacking `name` or `key` is a token failure (`needs_token`), as for Confluence.
- **PD-62 Unresolved-name matching** reuses M3 `jira::resolve` for issue types and transitions; candidates for 0 matches = every available name (≤ 10), for > 1 = the matching names (M3 as-built). Messages (plan text, through M3 `resolution_message`): "no project named '<v>'", "no issue type named '<v>' in <project>", "no transition named '<v>' for <key>", "no assignable user '<v>' for <key>", "no issue link type named '<v>'"; values through `validate::echo` (escaped, capped).
- **PD-63 Comment-cap configuration** = Δ7; M6's Settings writes `[limits] jira_comments_cap` (1–1000).
- **PD-64 Converter fault injection without a new feature.** §13 U-24 needs "a test-injected converter fault" through validation. It is injected in `core` under the existing `testing` feature (`TestHooks::converter_fault: Option<ConverterFault>`, `ExecCtx.test_fault`, both `cfg(feature = "testing")`), which appends one unrecorded `{include:…}`, `[~…]` or `{html}` to the converter output before the hard check; `convert` has no test feature and no fault API (its own fault test appends in the test). Reason: a `convert` feature forwarded by `core/testing` would compile a faulty converter into every `scripted-approver` app binary; this way the app build gains only an inert hook inside an already-locked feature.
- **PD-65 Stale check against a `needs_token` instance (M3 T26 review M-6: "document or align").** Aligned: such a stale check records `WRITE_STALE {identity_mismatch}` (the §5.4 step 5 identity row), not `recheck_failed {class: needs_token}`; Approve stays disabled until a valid PAT exists (unchanged). Nothing is sent either way.

Spec deltas the lead records (ledger entries at the end): PD-42, PD-44, PD-45, PD-46, PD-48, PD-49 (text), PD-51, PD-52, PD-53, PD-54, PD-57, PD-60, PD-61. PD-43, PD-47, PD-50, PD-55, PD-56, PD-58, PD-59, PD-62, PD-63, PD-64, PD-65 are plan decisions only.

---

## Review Focus

Five failure modes most likely to bite users of M5's code; each has named tests the reviewer must see pass.

1. **(Tasks 02–04, 07) Markdown can never produce a macro, mention, include or image.** An escaping gap in `md_to_wiki` (a `{` in link text, a `[~` split across emphasis, `!` at a line start, a table-cell pipe, a code span containing both `{code` and `{noformat`) silently lets an agent's Markdown run a Jira macro on approval. The hard check must catch what the escaping misses, by re-parsing with the same parser the preview uses. Tests `u24_fuzz_reparse_finds_nothing_unrecorded` (proptest, ≥ 2 000 cases), `u24_code_body_containers`, `u24_injected_fault_fails_validation_exit2` (core, `TestHooks::converter_fault`), `u23_md_to_wiki_golden`, `hard_check_counts_images_and_attachments`.
2. **(Tasks 12, 13, 15, 16, 18) Approvability after enrichment.** An unresolved name, an `expected` conflict, a closed sprint or an enrichment failure must leave Approve disabled in Rust (`DECISION_INVALID {not_approvable}`, no `WRITE_APPROVED`), individually and in a batch; a missing-required-fields warning must not. Tests `i35_jira_kinds_no_match_and_ambiguous_not_approvable`, `i36_edit_expected_conflict_not_approvable`, `sprint_closed_not_approvable`, `i18_missing_fields_warning_approve_enabled`.
3. **(Tasks 09–11) Redaction and mirrors on the new read shapes.** The `--comments` merge must keep the `fields.comment.comments ↔ renderedFields.comment.comments` mirror exact, so dropping a restricted comment removes its id and both bodies; server totals stay unchanged; `returned + items_dropped = items fetched`. Tests `u27_drop_restricted_comment_rendered_leaves_nothing`, `u27_mirror_without_counterpart_blocks_release`, `comments_merge_rebuild_hash_stable`, `i22_jira_drops_keep_totals_and_next_start`.
4. **(Tasks 15, 18, 19) Stale rules and rechecks never send.** A stale-check GET that is not a parsed 2xx JSON returns the write with `recheck_failed {class}` and sends nothing; an identity failure there is `identity_mismatch`; the new rules compare the right baseline. Tests `i23_jira_stale_rules_recheck_failed_classes`, `assign_stale_when_assignee_changed`, `sprint_move_stale_when_sprint_closed`, `t26_stale_check_rename_reruns_once`, `rf5b_jira_agile_header_absent`.
5. **(Tasks 08, 20) New PAT-bearing paths keep audit-before-effect.** The metadata-cache fill must commit `SYSTEM_FETCH {start}` before its GET and never run under a request id; a write must be impossible to send without a committed `WRITE_APPROVED` for that revision (type-enforced). Tests `metadata_cache_fill_is_covered_by_system_fetch`, `metadata_cache_never_blocks_preview`, `m18_write_cover_requires_committed_approval`, `m18_stale_revision_cover_refused`, and `i19_every_hit_is_covered` (M3) extended with the new flows.

Master-plan Review Focus (copied; owners per the master plan):
- **RF-1 Clock/retention** (M2) — not M5.
- **RF-2 Oracle** (M3) — not M5; the new resolution/stage GETs reuse the M3 enrichment classification table unchanged (`i23_enrichment_stage2_3xx_direct`, Task 12).
- **RF-3 Cross-host** (M2/M3/M6) — not M5.
- **RF-4 Crash reconciliation duplicate guard** (M3): M5 adds the carried move-op seeding test `rf4_seeding_reads_move_payloads` (Task 18).
- **RF-5 Identity/anonymous** (M5 owns (b)): `rf5b_jira_agile_header_absent`, `rf5b_search_post_header_absent`, `rf5b_rechecks_coalesce_and_are_logged` (Task 19); (a) is M7.

---

## §15 items resolved in M5

- **V05** (Jira `maxResults` clamping on 10.x/11.x; labels `update` syntax; assignee unassign sentinel) → design: Task 11 (paging trusts the server's `maxResults`, M3 arithmetic, plus the T10 minor 4 end-test fix), Task 13 (labels via `update`, verbatim), Task 15 (`{"name": null}`, PD-52); live: Task 24 `v05_*` (manual, PD-60).
- **V06 (Jira half)** (declared write success shapes) → wiremock: Task 22 (`x09_jira_every_op_once` asserts each write's declared shape) and Task 16 (`i25_issuelink_*`); live: Task 24 `v06_jira_write_success_shapes`.
- **V23 (Jira half, live)** → Task 24 `v23_jira_sso_front_classification` (manual); the wiremock design stays M3's.
- **V25 (Agile 1.0 and `POST /rest/api/2/search` header half)** → Task 19 (RF-5b per PD-58) and Task 24 `v25_agile_and_search_send_xausername` (manual).
- **M3 final review M-16** (public CA still connects while a custom CA is configured) → Task 24 `m16_public_ca_with_custom_ca_connects` (manual).

**Ledger entries M5 depends on (master plan M5 "Ledger"):** L06 (target params and baselines read-only: `EditForm.read_only`, T06/T12/T13), L12 (`expected` conflict, T13), L13 (moves ≤ 50, one request per write, T18), L17 (direct-read cap/budget outcomes gated: `--comments` pages T09, I-09 budget T11), L22 (per-op similarity incl. MoveIssues, T18), L25 (post-send enrichment failures gated: every new stage, T12/T15/T16/T18), L29 (pre-write identity call for every new write, T15–T18), L31 (status/header- vs body-decided on stage GETs, T12). Also touched: L56 (`no_instance` routing unchanged), L59 (an over-range integer in `expected` counts as "differs", PD-50), L81 (T15 launch-stub wait; owner "M5/M7 when the launch path is next touched": M5 does not touch the launch path, so it stays with M7, see Handoffs).

---

## Traceability (M5 exit criterion → task → test)

Every id in the M5 exit criterion (master plan, M5 entry) and every carried item maps to at least one named test; paths relative to the repo root. "Existing" = green on `master`, kept green, not rewritten.

| Id | What M5 must show | Task | Test(s) (file :: fn) |
|---|---|---|---|
| U-02 | move ops with > 50 issues rejected by static validation (exit 2, the §7.3 hint) | T18, T23 | `crates/core/tests/jira_moves.rs` :: `u02_sprint_move_over_50_rejected`, `u02_backlog_move_over_50_rejected`; `app/src-tauri/tests/jira_flows/flows.rs` :: `u02_move_51_issues_usage_exit2` |
| U-23 (wiki half) | golden files md→wiki (escaping of raw HTML and wiki specials) and wiki→html | T03, T05 | `crates/convert/tests/md_to_wiki.rs` :: `u23_md_to_wiki_golden`, `u23_escapes_raw_html_and_wiki_specials`; `crates/convert/tests/wiki_render.rs` :: `u23_wiki_to_html_golden`, `wiki_to_text_projection_golden` |
| U-24 | code bodies: golden + fuzz; re-parse finds nothing unrecorded; injected converter fault → exit 2, nothing queued | T04, T07 | `crates/convert/tests/hard_check.rs` :: `u24_code_body_containers`, `u24_code_and_noformat_both_escaped_monospace`, `u24_fuzz_reparse_finds_nothing_unrecorded`, `u24_faulty_converter_detected`, `hard_check_counts_images_and_attachments`; `crates/core/tests/jira_validate.rs` :: `u24_injected_fault_fails_validation_exit2` |
| U-27 | dropping a restricted comment from `jira.issue.get --rendered` leaves neither id nor bodies; per-item drop and mask reach the mirror; orphan mirror blocks release; rendered ops declare mirrors | T10 | `crates/core/tests/jira_reads.rs` :: `u27_drop_restricted_comment_rendered_leaves_nothing`, `u27_per_item_field_drop_and_mask_reach_mirror`, `u27_mirror_without_counterpart_blocks_release`; `crates/registry/tests/catalog.rs` :: `rendered_fields_ops_declare_mirrors` (existing) |
| U-30 | edited writes: only agent keys in `executed_params`, `edited_keys` incl. `fields.<id>`, no added value delivered (Jira create) | T12 | `crates/core/tests/jira_create.rs` :: `u30_create_added_field_value_not_delivered`; `crates/core/tests/edit.rs` :: `u30_*` (existing) |
| U-33 | params validation, field rules, CLI flag binding (Jira completion: markdown accepted, `--comments`) | T07 | `crates/core/tests/jira_validate.rs` :: `u33_jira_markdown_body_format_accepted`, `u33_confluence_markdown_still_rejected`, `u33_issue_get_comments_param_validates`; `crates/cli/src/binding.rs` :: `u33_every_op_roundtrips_example_through_argv` (existing) |
| U-34 (Jira half) | default `jira.issue.get` with parent, links, custom fields, no restricted comments, `security` null, no invisible chars → zero Caution; with a security level exactly one; one level per id | T10 | `crates/core/tests/jira_reads.rs` :: `u34_default_issue_get_zero_caution`, `u34_security_level_exactly_one_caution`, `u34_restricted_comment_caution_over_both_trees`; `crates/preview/tests/warnings.rs` :: `every_warning_id_has_exactly_one_level` (existing) |
| I-06 (move cases) | three disjoint opened `jira.sprint.move_issues` into one sprint are not flagged and batch-approve; two sharing a key are flagged and their batch is rejected | T18 | `crates/core/tests/jira_moves.rs` :: `i06_three_disjoint_moves_batch_approve`, `i06_moves_sharing_key_flagged_batch_rejected` |
| I-09 (`jira.search` probe) | a calibrated OR-predicate probe crossing the read budget, then `cancel`, ≡ a non-matching probe then `cancel` | T11 | `crates/core/tests/cancel.rs` :: `i09_jira_search_budget_probe_cancel_identical`; `i09_probe_cancel_envelopes_identical` (existing, cap variant) |
| I-18 | missing required field: Caution, Approve enabled; Edit & approve via the pre-added input sends the field; deny with details, `allowed_values` only when ticked | T12, T23 | `crates/core/tests/jira_create.rs` :: `i18_missing_fields_warning_approve_enabled`, `i18_edit_and_approve_preadded_input_sends_field`, `i18_deny_missing_fields_allowed_values_only_when_ticked`; `jira_flows/flows.rs` :: `i18_create_missing_field_edit_and_approve` |
| I-22 (`meta.page`) | after item drops totals unchanged, `returned + items_dropped = fetched`, a `next_start` loop re-requests no dropped item; Agile `isLast` and short pages | T11 | `crates/core/tests/jira_reads.rs` :: `i22_jira_drops_keep_totals_and_next_start`, `i22_next_start_loop_rerequests_no_dropped_item`, `i22_agile_islast_and_short_page` |
| I-23 (`recheck_failed`) | every Jira stale-ruled write: a stale-check 503, 302, HTML 200, > 32 MiB, network error → `recheck_failed {class}`, nothing sent, rev bumped; stage GETs of enrichment classify like M3 | T19, T12 | `crates/core/tests/jira_identity.rs` :: `i23_jira_stale_rules_recheck_failed_classes`; `crates/core/tests/jira_create.rs` :: `i23_enrichment_stage2_3xx_direct`; `crates/core/tests/upstream.rs` :: `i23_*` (existing) |
| I-25 | `jira.issuelink.create` 201 empty `text/html` → `succeeded`, receipt `{}`, no attention event; 201 HTML body → `outcome_unknown`; empty 200 on a `Json` op → `outcome_unknown` | T16 | `crates/core/tests/jira_writes_ext.rs` :: `i25_issuelink_201_empty_html_succeeded_receipt_empty`, `i25_issuelink_201_html_body_outcome_unknown`, `i25_comment_add_empty_200_outcome_unknown`; `crates/atlassian/tests/writes.rs` :: `i25_*` (existing classifier) |
| I-26 (`jira.issue.transition`) | crash after the stale-check fetch → `outcome_unknown`, exit 6, startup notice (+ the new stale-ruled `jira.issue.assign`) | T15 | `crates/core/tests/reconcile.rs` :: `i26_crash_after_stale_check_fetch_is_outcome_unknown_jira_transition` (existing), `i26_crash_after_stale_check_fetch_is_outcome_unknown_jira_assign` |
| I-28 (`jira.comment.add`) | anonymous fallback: the pre-write identity call returns the comment (also with a Markdown body) as `WRITE_STALE {identity_mismatch}`, nothing sent | T14 | `crates/core/tests/identity.rs` :: `i28_comment_add_identity_call_stale` (existing); `crates/core/tests/jira_writes.rs` :: `i28_markdown_comment_identity_call_stale` |
| I-35 (Jira kinds) | per kind (project, issue type, transition, assignable user, link type) no match and ambiguous match disable Approve; deny with hint → `denied`, exit 3, `resolution_failed`, `candidates` only when ticked | T12, T14, T15, T16 | `jira_create.rs` :: `i35_project_no_match_and_ambiguous`, `i35_issuetype_no_match_and_ambiguous`; `jira_writes.rs` :: `i35_transition_no_match_and_ambiguous`; `jira_writes_ext.rs` :: `i35_assignee_no_match_and_ambiguous`, `i35_link_type_no_match_and_ambiguous`, `i35_jira_kinds_no_match_and_ambiguous_not_approvable` (table over all five kinds, incl. the batch case) |
| I-36 (`jira.issue.edit`) | `expected` differs → conflict state, Approve disabled; deny pre-fill text; match → approvable | T13 | `crates/core/tests/jira_edit.rs` :: `i36_edit_expected_conflict_not_approvable`, `i36_conflict_deny_prefill_and_exit3`, `i36_expected_match_approvable`; `jira_flows/flows.rs` :: `i36_edit_conflict_denied_exit3` |
| X-09 (Jira) | every Jira registry op once against wiremock with the scripted approver (generated from the registry) | T22 | `crates/core/tests/x09_jira.rs` :: `x09_jira_every_op_once` |
| X-10 (Jira gates) | version floor at the connection test; `min_version` gate never fires above the floor; never the version string | T22 | `crates/core/tests/x09_jira.rs` :: `x10_jira_createmeta_available_on_floor`; `crates/core/tests/instances.rs` :: `x10_jira_below_8_14_refused` (existing); `crates/core/tests/validate.rs` :: `x10_min_version_unsupported_never_version_string` (existing) |
| S-12 (Jira previews) | remote images/scripts in wiki neutralized; invisible characters marked; raw-only diff changes flagged | T05, T10, T13 | `wiki_render.rs` :: `s12_remote_images_and_scripts_neutralized`; `jira_reads.rs` :: `s12_issue_preview_marks_invisible`; `jira_edit.rs` :: `s12_raw_only_diff_flagged` |
| RF-5b | Agile and search answers without `X-AUSERNAME` → exit 6 `upstream_unavailable` per read, rechecks through the limiter, logged, never skipped, bounded | T19 | `jira_identity.rs` :: `rf5b_jira_agile_header_absent`, `rf5b_search_post_header_absent`, `rf5b_rechecks_coalesce_and_are_logged` |
| L-01 (Jira) | env-gated live tests for V05, V06 (Jira), V23 (Jira), V25 (Agile/search), M-16 | T24 | `crates/core/tests/live_jira.rs` :: `v05_max_results_clamp_labels_update_unassign`, `v06_jira_write_success_shapes`, `v23_jira_sso_front_classification`, `v25_agile_and_search_send_xausername`, `m16_public_ca_with_custom_ca_connects` (all `#[ignore]`, manual) |
| jira_flows | the real binaries end to end on the new Jira paths | T23 | `app/src-tauri/tests/jira_flows/flows.rs` :: `jira_flows_smoke`, `md_comment_sent_as_wiki`, `i18_create_missing_field_edit_and_approve`, `i36_edit_conflict_denied_exit3`, `issue_get_comments_released`, `issuelink_201_empty_succeeded`, `unresolved_transition_deny_hint_exit3`, `u02_move_51_issues_usage_exit2` |
| M3 M-18 | write cover type-enforced | T20 | `crates/atlassian/tests/cover.rs` :: `m18_write_cover_requires_committed_approval`, `m18_stale_revision_cover_refused`; `crates/core/tests/writes.rs` :: `m18_execute_uses_write_cover` |
| M3 T23 move seeding | RF-4 index seeded from move payloads | T18 | `crates/core/tests/similarity.rs` :: `rf4_seeding_reads_move_payloads` |
| M3 T24 M-4 | a write's unsent 2nd GET is not recorded as in flight | T21 | `crates/core/tests/cancel.rs` :: `get2_cancel_before_send_not_recorded_in_flight` |
| M3 T29 handoff | `candidate_rev` on `READ_RELEASED`/`SCRIPT_RELEASED`; exact U-32; adversarial unopened attempts; write opacity over enrichment results | T21 | `crates/core/tests/audit_props.rs` :: `u32_released_candidate_rev_matches_preview_shown`, `u32_unopened_attempts_rejected_then_property_holds`; `crates/core/tests/opacity.rs` :: `i07_write_streams_identical_enrichment_conflict_vs_match` |
| M3 T10 minors 3, 4, 9 | 429 then budget/cancel → the 429 answer (`Failed4xx`); short last page not taken as end; one parse per page | T21, T11 | `crates/atlassian/tests/writes.rs` :: `write_429_then_budget_expiry_is_failed4xx`, `write_429_then_cancel_is_failed4xx`; `crates/atlassian/tests/pagination.rs` :: `short_last_page_is_not_end_of_results`, `page_facts_read_once_large_page` |
| M3 T26 test gaps + M-3 | stale-check rename re-run, refresh identity failure, header-class `WRITE_STALE`, inconclusive stale re-check, write-response rename; recheck without `name`/`key` = token failure | T19 | `jira_identity.rs` :: `t26_stale_check_rename_reruns_once`, `t26_refresh_identity_failure_returns_identity_mismatch`, `t26_header_class_write_stale`, `t26_inconclusive_stale_recheck_recheck_failed`, `t26_write_response_rename_stays_outcome_unknown`, `pd61_recheck_without_name_or_key_is_token_failure` |
| M3 M-16 | public CA still connects with a custom CA | T24 | `live_jira.rs` :: `m16_public_ca_with_custom_ca_connects` (manual) |
| Field-name cache | `SYSTEM_FETCH {metadata_cache}` fill, never blocking, display-only | T08 | `crates/core/tests/metadata_cache.rs` :: `metadata_cache_fill_is_covered_by_system_fetch`, `metadata_cache_never_blocks_preview`, `metadata_cache_failure_keeps_old_map`, `metadata_cache_never_under_a_request_id` |
| `--comments` | composite read, cap, mirror shape, gated later pages, rebuild-stable hash | T09 | `crates/core/tests/jira_reads.rs` :: `comments_flag_merges_comment_pages`, `comments_cap_and_truncated_info`, `comments_rendered_mirror_shape`, `comments_merge_rebuild_hash_stable`, `comment_page_failure_is_gated` |

No M5 task exists without a row here except Task 1 (pins, crate skeleton, checker rules), Task 6 (the preview model the previews need), Task 17 (worklog: no §13 id of its own; its tests are in Task 17 and X-09), Task 25 (CI) and Tasks 26/27 (exit run, final review).

---

## File Structure

New and modified files per crate (Create = new file; Modify = existing file).

### Workspace root and CI
- Modify `Cargo.toml` (`pulldown-cmark` pin), `Cargo.lock`.
- Modify `ci/check-workspace.mjs`, `ci/check-workspace.test.mjs` (T01: `convert` external allowlist), `ci/check-no-panic-macros.mjs` + test (T01: scan `crates/convert/src`).
- Modify `.github/workflows/ci.yml` (T25), `ci/cli-flows-linux.sh` (T25: `CLI_FLOWS_TEST`).

### crates/convert
- Modify `Cargo.toml`, `src/lib.rs` (lints, `compile_error!` lock, re-exports).
- Create `src/wiki/mod.rs`, `src/wiki/lexer.rs`, `src/wiki/parse.rs` (T02), `src/md_to_wiki.rs`, `src/escape.rs` (T03), `src/hard_check.rs` (T04), `src/wiki_html.rs`, `src/wiki_text.rs` (T05).
- Create tests `tests/wiki_parse.rs` (T02), `tests/md_to_wiki.rs` (T03), `tests/hard_check.rs` (T04), `tests/wiki_render.rs` (T05); golden files `tests/golden/md_to_wiki/*.md` + `*.wiki`, `tests/golden/wiki_html/*.wiki` + `*.html`, `tests/golden/wiki_text/*.wiki` + `*.txt`.

### crates/preview
- Modify `src/model.rs`, `src/lib.rs` (T06); Create `src/diff.rs`, `src/form.rs` (T06); tests `tests/diff.rs`, `tests/form.rs`, `tests/model_jira.rs` (T06).

### crates/registry
- Modify `src/describe.rs` (T07: PD-42 sentence for Jira writes), `src/jira/schemas.rs` (T12: create `fields` description mentions missing-field inputs; nothing else changes shape), `tests/describe.rs` (T07).

### crates/atlassian
- Modify `src/cover.rs`, `src/client/write.rs`, `src/lib.rs` (T20: `WriteCover`), `src/client/paginate.rs` (T11: minor 4; T21: minor 9), `src/client/send.rs` (T21: minor 3); tests `tests/cover.rs` (T20), `tests/pagination.rs`, `tests/writes.rs` (T11, T21).

### crates/core
- Create `src/ops/jira_body.rs` (T07), `src/metadata.rs` (T08), `src/ops/jira_preview.rs` (T10, T11, T13, T14), `src/ops/jira_ext.rs` (T15–T18: assign, link, worklog, moves), `src/engine/enrich.rs` (T12: the staged driver, moved out of `write.rs`).
- Modify `src/ops/mod.rs` (T12 Δ3, T15–T18 table rows), `src/ops/jira.rs` (T09, T12, T13), `src/ops/stale.rs` (T13, T15, T18), `src/ops/generic.rs` (T10, T11 dispatch to Jira previewers), `src/ops/confluence.rs` (T12: wrap `PAGE_UPDATE_ENRICH` in the staged form), `src/validate/mod.rs` (T07, Δ7), `src/engine/read.rs` (T09), `src/engine/write.rs` (T12, T20), `src/engine/cancel.rs` (T21), `src/decision/mod.rs` (T12 `MissingFields`), `src/identity.rs` (T19), `src/audit_port.rs` (T20), `src/payloads.rs` (T21), `src/core.rs` (T08 cache start), `src/instances/admin.rs` (T08 fill after connection test), `src/testing/harness.rs` (T08, T12 helpers), `src/testing/approver.rs` (T12 `edit_preadded`), `src/lib.rs`.
- Create tests `tests/jira_validate.rs` (T07), `tests/metadata_cache.rs` (T08), `tests/jira_reads.rs` (T09–T11), `tests/jira_create.rs` (T12), `tests/jira_edit.rs` (T13), `tests/jira_writes.rs` (T14), `tests/jira_writes_ext.rs` (T15–T17), `tests/jira_moves.rs` (T18), `tests/jira_identity.rs` (T19), `tests/x09_jira.rs` (T22), `tests/live_jira.rs` (T24), `tests/common/jira.rs` (T09: shared Jira mock helpers: `mount_issue`, `mount_comments`, `mount_createmeta_fields`, `mount_link_types`, `mount_assignable`, `mount_sprint`), and modify `tests/cancel.rs`, `tests/similarity.rs`, `tests/reconcile.rs`, `tests/audit_props.rs`, `tests/opacity.rs`, `tests/writes.rs`, `tests/common/flows.rs` (I-19 property gains the new Jira flows, T22).

### app/src-tauri
- Create `tests/jira_flows.rs` (`#![cfg(feature = "scripted-approver")]`, `#[path = "cli_flows/harness.rs"] pub mod harness;`), `tests/jira_flows/flows.rs` (T23).

---

## Tasks

Phase A (Tasks 1–6): `convert` and `preview` foundations (pure, no I/O; all tests run locally on Windows). Phase B (Tasks 7–11): validation wiring and the read side. Phase C (Tasks 12–14): the core-named writes (§13 names them; master plan Placements "core then extended"). Phase D (Tasks 15–18): the extended writes. Phase E (Tasks 19–22): identity sweep, write cover, carry-overs, the generated catalog test. Phase F (Tasks 23–27): `jira_flows`, live tests, CI, exit criterion, final review. Task 6 can run in parallel with Tasks 2–5; Task 8 and Task 20 can run in parallel with Phase C; Task 24 can run any time after Task 18.

Shared conventions (every task): run commands from `C:/Code/atlas-duck`; core test runs use `cargo test -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked`; a Jira harness is `core::testing::Harness::jira()` with `MockDc` fixtures from `atlassian::testing` plus the `tests/common/jira.rs` mount helpers (Task 9 creates them; later tasks add helpers there, never duplicate them); writes are decided through `core::testing::ScriptedApprover` (`open` before `approve`/`release`; `approve_unopened` only to prove the refusal).

### Task 1: Pins, `convert` crate skeleton and lints, checker rules

**Model:** Sonnet (medium).

**Files:**
- Modify: `Cargo.toml` (`pulldown-cmark = { version = "=0.13.4", default-features = false }`), `Cargo.lock`, `crates/convert/Cargo.toml` (dep `pulldown-cmark`; dev `proptest`; no `[features]`), `crates/convert/src/lib.rs`
- Modify: `ci/check-workspace.mjs`, `ci/check-workspace.test.mjs`, `ci/check-no-panic-macros.mjs`, `ci/check-no-panic-macros.test.mjs`
- Test: the two `ci/*.test.mjs`

**Interfaces:**
- Consumes: M1 crate layout; M3/M4 checker structure (`TEST_ONLY_FEATURES`, `TEST_FEATURE_FORWARDERS`, the per-crate external allowlist style of `REGISTRY_EXTERNAL_ALLOW`).
- Produces: `crates/convert/src/lib.rs` with `#![deny(clippy::unwrap_used, clippy::expect_used)]`, no module stubs (each of Tasks 2 to 5 adds its own module). Checker: `CONVERT_EXTERNAL_ALLOW = ["pulldown-cmark"]` (normal deps of `atlas-duck-convert` ⊆ it; violation `"atlas-duck-convert: external dependency <d> not allowed"`); `check-no-panic-macros.mjs` scans `crates/convert/src/**` (excluding `#[cfg(test)]` modules, as elsewhere).

**Spec:** §2.2 (convert is pure, depends on nothing in the workspace), §7.6, §7.7 (no panics, release `panic = "abort"`), §13 ("a test-injected converter fault").

- [ ] **Step 1: Failing tests.** `ci/check-workspace.test.mjs`: `convert external dependency outside allowlist is rejected` (fixture with `reqwest` under convert), real workspace passes. `ci/check-no-panic-macros.test.mjs`: a fixture `crates/convert/src/x.rs` with `.unwrap()` → violation. Rust: none yet (Task 2 adds the first tests; `cargo test -p atlas-duck-convert` must build and run zero tests).
- [ ] **Step 2: Implement.** One unlocked `cargo build -p atlas-duck-convert`, then `--locked` everywhere. `cargo tree -p atlas-duck-convert -e normal --locked` lists only `pulldown-cmark` and its own deps (record them in the report).
- [ ] **Step 3: Run** `cargo test -p atlas-duck-convert --locked`; `node ci/check-workspace.mjs && node ci/check-no-panic-macros.mjs && node --test "ci/*.test.mjs"`; `cargo build --workspace --locked`.
- [ ] **Step 4: Commit** `build(convert): pulldown-cmark pin, crate lints and checker rules` (+ trailer), pathspecs `Cargo.toml Cargo.lock crates/convert ci`.

---

### Task 2: `convert::wiki` lexer/parser and `wiki_constructs`

**Model:** Opus (the parser is the ground truth of the hard check and of the preview renderer).

**Files:**
- Create: `crates/convert/src/wiki/mod.rs`, `src/wiki/lexer.rs`, `src/wiki/parse.rs`; Modify: `crates/convert/src/lib.rs`
- Test: `crates/convert/tests/wiki_parse.rs`

**Interfaces:**
- Consumes: Task 1.
- Produces: `pub mod wiki` with `pub fn parse(wiki: &str) -> WikiDoc` (never fails: unknown syntax is text), `pub struct WikiDoc { pub blocks: Vec<Block> }`, `pub enum Block { Heading { level: u8, inlines: Vec<Inline> }, Paragraph(Vec<Inline>), List { ordered: bool, items: Vec<(u8 /* depth */, Vec<Inline>)> }, Table { rows: Vec<TableRow> }, Quote(Vec<Block>), Code { kind: CodeKind, lang: Option<String>, body: String, byte_range: Range<usize> }, Panel { title: Option<String>, blocks: Vec<Block> }, Macro { name: String, params: String, body: Option<String>, byte_range: Range<usize> }, Rule }`, `pub enum Inline { Text(String), Strong(Vec<Inline>), Emphasis(Vec<Inline>), Monospace(String), Strike(Vec<Inline>), Link { text: Option<String>, target: String }, Mention(String), Image(String), Attachment(String), Macro { name: String, params: String, byte_range: Range<usize> }, LineBreak }`, `pub enum CodeKind { Code, Noformat }`. `pub fn wiki_constructs(wiki: &str) -> WikiConstructs` (Δ1) and `pub(crate) fn construct_spans(doc: &WikiDoc) -> Vec<(ConstructKind, Range<usize>)>` (used by the hard check). Escapes: a backslash before `{ } [ ] | ! ~ * _ ^ - + ? #` makes the next char literal (Jira wiki's own escape); `{{…}}` is monospace whose content is still scanned for macros (Jira renders macros inside `{{ }}`: fail closed); `{code}`/`{noformat}` bodies are opaque until the matching closing tag; an unterminated `{code}` runs to the end (opaque, counted as one `Code` block); `{include:…}`/`{excerpt-include:…}` are `Macro` with `name` `include`/`excerpt-include` and are reported as `ConstructKind::Include` by `construct_spans`.

**Spec:** §7.6 (hard check uses "the wiki→preview renderer's parser"; renderer scope: headings, emphasis, lists, tables, `{code}`/`{noformat}`, `{quote}`, links as text, `{panel}` etc. as labelled blocks, unknown macros as placeholders), PD-44.

- [ ] **Step 1: Failing tests** (`tests/wiki_parse.rs`): `parses_headings_lists_tables_quotes`; `macros_known_and_unknown` (`{toc}`, `{jira:ABC-1}`, `{color:red}x{color}`, `{unknownmacro:a=b}` → `Macro` with names); `code_and_noformat_bodies_are_opaque` (`{code}{include:X}{code}` → one `Code` block, no `Macro`); `unterminated_code_runs_to_end`; `mentions_links_images_attachments` (`[~jdoe]`, `[text|https://x]`, `[https://x]`, `!https://x/a.png!`, `[^file.txt]`); `backslash_escapes_are_literal` (`\{toc\}`, `\[~jdoe\]`, `\!x!` → text only); `monospace_still_scanned` (`{{ {toc} }}` → a `Macro` inside); `includes_classified` (`wiki_constructs("{include:Space:Page}")` → `includes == ["Space:Page"]`, `macros` empty); `wiki_constructs_inventory` (one of each kind in one text → each list has exactly that entry, in document order); `parse_never_panics_on_garbage` (proptest over arbitrary `String` incl. unbalanced braces, 1 000 cases: `parse` returns; `construct_spans` ranges are char boundaries within the input).
- [ ] **Step 2: Implement** (a hand-written lexer over `char_indices`, no regex crate; bounded recursion depth 32 for nested blocks, deeper input is text).
- [ ] **Step 3: Run** `cargo test -p atlas-duck-convert --locked`; `cargo clippy -p atlas-duck-convert --all-targets --locked -- -D warnings`.
- [ ] **Step 4: Commit** `feat(convert): Jira wiki lexer and parser with the construct inventory` (+ trailer).

---

### Task 3: `markdown_to_wiki` with full escaping and the code-body rule

**Model:** Opus (escaping is the primary defence; the hard check is the second).

**Files:**
- Create: `crates/convert/src/md_to_wiki.rs`, `crates/convert/src/escape.rs`; Modify: `src/lib.rs`
- Test: `crates/convert/tests/md_to_wiki.rs`, golden files `crates/convert/tests/golden/md_to_wiki/{basics,lists,tables,code,links,html,specials,nested}.md` + the expected `.wiki` beside each

**Interfaces:**
- Consumes: `pulldown-cmark` (`Parser::new_ext(md, Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH)`, no other options), Task 2 types (`CodeKind`).
- Produces: `pub fn markdown_to_wiki(md: &str) -> (String, EmittedConstructs)` (Δ1). Renderers: headings `h1.`–`h6.`, emphasis `_x_`, strong `*x*`, strikethrough `-x-`, ordered/unordered lists (`#`/`*` with depth), tables (`||h||` header, `|c|` cells; `|` inside a cell escaped), links `[text|url]` (text and url escaped; a url containing `|` or `]` is percent-encoded), images → links `[alt|url]` (PD-44), blockquotes `bq. ` (single paragraph) or `{quote}` (multi-block; recorded as an emitted container like code), soft/hard breaks, horizontal rule `----`. `escape::wiki_text(s)` escapes every wiki-special sequence of §7.6 (`{`, `}`, `[`, `]`, `|`, `[~`, `!`, `\`) plus line-start markers (`h1.`…`h6.`, `bq.`, `#`, `*`, `-`, `----`) and `*`/`_`/`-`/`+`/`^`/`~`/`??` emphasis delimiters with a backslash. Raw HTML (inline and block events) → escaped text. Code bodies (fenced, indented, inline spans) per §7.6: content without `{code` → `{code[:lang]}…{code}`; containing `{code` but not `{noformat` → `{noformat}…{noformat}`; containing both → escaped monospace paragraphs (`{{…}}` per line with every wiki-special sequence escaped, an empty line as an escaped space); inline code spans use `{{…}}` with escaping (never `{code}`). Every `{code}`/`{noformat}`/`{quote}` container the converter emits is recorded in `EmittedConstructs` with its byte range in the output. Output is deterministic and ends with exactly one `\n`.

**Spec:** §7.6 ("All raw HTML and wiki-special sequences … are escaped, so Markdown input can never produce macros, mentions or includes"; code-body rule), §5.4 step 1, PD-43, PD-44.

- [ ] **Step 1: Failing tests** (`tests/md_to_wiki.rs`): `u23_md_to_wiki_golden` (every golden pair, byte-exact; the test prints a unified diff on failure); `u23_escapes_raw_html_and_wiki_specials` (`<script>x</script>`, `{toc}`, `[~jdoe]`, `!img.png!`, `{include:A}`, `|`, `\` in plain text → every one appears escaped and `wiki::parse` of the output yields only `Text`/`Strong`/… inlines, no `Macro`/`Mention`/`Image`/`Attachment`); `images_become_links`; `at_mention_stays_text` (`@jdoe` → `@jdoe`, no `[~`); `code_container_by_content` (three fenced blocks: plain → `{code}`, containing `{code}` → `{noformat}`, containing both → escaped `{{…}}` lines; inline span with `{noformat}` → escaped monospace); `emitted_constructs_ranges_point_at_containers` (each recorded range slices exactly a `{code…}`…`{code}` / `{noformat}`… / `{quote}`… block of the output); `deterministic_output` (100 random inputs converted twice are byte-equal); `link_url_with_pipe_or_bracket_is_encoded`.
- [ ] **Step 2: Implement.** Map events with an explicit state machine; `into_offset_iter()` is not needed here (M7's placeholder check uses it). Never call `.unwrap()`; impossible states fall back to escaped text.
- [ ] **Step 3: Run** `cargo test -p atlas-duck-convert --locked`; clippy as Task 2.
- [ ] **Step 4: Commit** `feat(convert): Markdown to Jira wiki with full escaping and the code-body rule` (+ trailer).

---

### Task 4: `hard_check_wiki`, U-24 golden and fuzz tests

**Model:** Opus.

**Files:**
- Create: `crates/convert/src/hard_check.rs`; Modify: `src/lib.rs`
- Test: `crates/convert/tests/hard_check.rs`

**Interfaces:**
- Consumes: Tasks 2, 3.
- Produces: `pub fn hard_check_wiki(wiki: &str, e: &EmittedConstructs) -> Result<(), Unrecorded>` (Δ1): `construct_spans(parse(wiki))`; a `Macro` span equal to a recorded container range (or the opening tag of one) is recorded; everything else of kind Macro, Mention, Include, Image, Attachment is unrecorded; the error names the first failing kind and the count of that kind (no text). No fault-injection API in `convert` (PD-64): the tests append the faulty construct themselves, and core injects through its `testing` hook (Task 7).

**Spec:** §7.6 hard check; §13 U-24 ("golden and fuzz tests with `{code}`, `{noformat}`, both together, and `]]>` inside fenced blocks and inline code; for every generated Markdown input, re-parsing … finds no macro, mention, include … the converter did not record, and a test-injected converter fault … fails validation"), PD-44.

- [ ] **Step 1: Failing tests** (`tests/hard_check.rs`): `u24_code_body_containers` (golden inputs with `{code}`, `{noformat}`, both, and `]]>` in fenced and inline code → `hard_check_wiki(markdown_to_wiki(md))` is `Ok`, and the output contains no un-escaped `{code`/`{noformat` outside its own container); `u24_code_and_noformat_both_escaped_monospace`; `u24_fuzz_reparse_finds_nothing_unrecorded` (proptest, `ProptestConfig { cases: 2048, .. }`: a strategy that builds Markdown from fragments biased to wiki specials (`{`, `}`, `[~`, `!`, `|`, `\`, `{code}`, `{noformat}`, `{include:X}`, `[^f]`, `<b>`, backticks, fences, list and table markup, emphasis delimiters, CR/LF mixes, non-ASCII, U+202E) → `hard_check_wiki(&out, &emitted) == Ok(())` for every case; failures shrink to a minimal Markdown); `u24_faulty_converter_detected` (the test appends `{include:Injected}`, `[~injected]` and `{html}<b>x</b>{html}` in turn to a real `markdown_to_wiki` output without recording them → `Err(Unrecorded {kind, count: 1})` with kind Include, Mention, Macro); `hard_check_counts_images_and_attachments` (wiki with `!a.png!` and `[^f]` and no record → `Err` Image first, then with images removed → Attachment); `recorded_containers_pass` (a recorded `{code}` block whose body holds `{toc}` → `Ok`); `unrecorded_error_has_no_text` (`format!("{e:?}")` and `Display` contain no byte of the input).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** `cargo test -p atlas-duck-convert --locked`; clippy. Record the proptest case count and runtime in the report.
- [ ] **Step 4: Commit** `feat(convert): wiki re-parse hard check with golden, fuzz and injected-fault tests (U-24)` (+ trailer).

---

### Task 5: `wiki_to_preview_html` and `wiki_to_text`; U-23 wiki goldens; S-12 neutralization

**Model:** Sonnet (medium).

**Files:**
- Create: `crates/convert/src/wiki_html.rs`, `crates/convert/src/wiki_text.rs`; Modify: `src/lib.rs`
- Test: `crates/convert/tests/wiki_render.rs`, golden files `tests/golden/wiki_html/*.wiki|.html`, `tests/golden/wiki_text/*.wiki|.txt`

**Interfaces:**
- Consumes: Task 2 `parse`.
- Produces: `pub fn wiki_to_preview_html(wiki: &str) -> String` (Δ1): `<h1>`–`<h6>`, `<p>`, `<strong>`, `<em>`, `<del>`, `<ul>/<ol>/<li>`, `<table>/<tr>/<th>/<td>`, `<blockquote>`, `<pre>` for `{code}`/`{noformat}` (body as text), `{panel}`/`{quote}`/unknown block macros as `<div data-macro="name">` labelled blocks with a text label `[macro: name]`, inline macros as text `[macro: name]`, links as text `text (url)` (never `<a>`), images as text `[image: url]` (never `<img>`), attachments `[attachment: file]`, mentions `@name`; `{color}`, `{span}` and similar styling ignored (content kept). All text HTML-escaped. The output is meant to go through `preview::sanitize_html` (core does that; this crate has no `preview` edge). `pub fn wiki_to_text(wiki: &str) -> String`: the text projection of the same rendering (one line per block, list items prefixed `• `/`1. `, table cells joined by ` | `, code bodies verbatim, macros `[macro: name]`) used for the Jira rendered diff (§6.3).

**Spec:** §7.6 "Wiki markup → preview HTML", §6.3 "Edit/update" (rendered side), §6.4 (no remote resource, links as text, no source styling), §13 S-12.

- [ ] **Step 1: Failing tests:** `u23_wiki_to_html_golden`; `wiki_to_text_projection_golden`; `s12_remote_images_and_scripts_neutralized` (`!https://evil.example/x.png!`, `{html}<script>alert(1)</script>{html}`, `[click|javascript:alert(1)]` → no `<img`, `<script`, `<a`, `href`, `src`, `on…=` in the output; the URL text appears escaped); `color_and_styling_ignored` (`{color:red}x{color}` → `x` without `style`); `deterministic_and_never_panics` (proptest 1 000 cases over the Task 4 strategy's wiki output and arbitrary strings).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** `cargo test -p atlas-duck-convert --locked`; clippy.
- [ ] **Step 4: Commit** `feat(convert): wiki preview HTML and text projection (U-23 wiki half, S-12)` (+ trailer).

---

### Task 6: `preview` model for Jira: body variants, line diff, `EditForm`

**Model:** Sonnet (medium).

**Files:**
- Modify: `crates/preview/src/model.rs`, `crates/preview/src/lib.rs`; Create: `crates/preview/src/diff.rs`, `crates/preview/src/form.rs`
- Modify: `crates/core/src/engine/*.rs` only where a `Preview { .. }` literal needs `edit_form: None` (compile fix)
- Test: `crates/preview/tests/diff.rs`, `crates/preview/tests/form.rs`, `crates/preview/tests/model_jira.rs`

**Interfaces:**
- Consumes: M3 `PreviewBody`, `RequestView`, `ItemCount`.
- Produces: Δ2 exactly: `PreviewBody::{JiraIssue, Table, WriteSummary, EditDiff, Transition}` with `IssueCard { key, summary, issue_type, status, priority: Option<String>, assignee: Option<String>, reporter: Option<String> }`, `FieldRow { id: String, name: String /* "customfield_N (unknown field)" when unknown */, value_text: String, restricted: bool }`, `CommentView { id, author: Option<String>, created: Option<String>, body_html: String, restricted: bool }`, `ConstructList { macros, mentions, includes, links, images, attachments: Vec<String> }`; `diff::{line_diff, DiffLine, DiffOp, DIFF_MAX_LINES, hunks(&[DiffLine]) -> u64}`; `form::{EditForm, EditInput, InputKind}` and `Preview.edit_form: Option<EditForm>`; all `Serialize` (snake_case tags like the M3 variants), all `Debug` derived (preview types carry display text only, the M3 rule). Tests may construct them directly.

**Spec:** §6.1 principles 1, 3, 4, §6.3 table (Jira issue, Jira search, Lists, Create, Edit/update, Transition, Assign/link/labels/worklog/sprint move, Conflict, Unresolved name), §5.4 step 4 (edit form; target params and baselines read-only), PD-47, PD-49, PD-51.

- [ ] **Step 1: Failing tests:** `tests/diff.rs`: `line_diff_identity_is_all_same`, `line_diff_insert_delete_replace`, `line_diff_myers_minimal_on_small_cases` (table of 10 known minimal edit scripts), `line_diff_cap_falls_back_to_whole_replace` (> `DIFF_MAX_LINES` lines → exactly one Del block and one Add block), `hunks_counts_runs`; `tests/form.rs`: `edit_form_serializes_kinds` (each `InputKind` round-trips to the documented JSON), `choice_allowed_values_capped_at_10` (constructor `InputKind::choice(values)` truncates); `tests/model_jira.rs`: `jira_bodies_serialize_with_kind_tags` (`{"kind":"jira_issue",…}`, `table`, `write_summary`, `edit_diff`, `transition`), `write_bodies_always_carry_requests` (a compile-time-ish check: each write variant has a `requests` field; test builds each with one `RequestView` and asserts it serializes).
- [ ] **Step 2: Implement** (Myers O(ND) with a `d` bound; no new dependency).
- [ ] **Step 3: Run** `cargo test -p atlas-duck-preview --locked`; `cargo build --workspace --locked`; `cargo test -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked` (unchanged counts: `edit_form: None` everywhere).
- [ ] **Step 4: Commit** `feat(preview): Jira preview bodies, line diff and the edit-form model` (+ trailer), pathspecs `crates/preview crates/core/src`.

---

### Task 7: Markdown bodies for Jira writes at validation; `jira_body`; describe text; the injected-fault proof (U-24 core half, U-33 Jira)

**Model:** Opus (validation path of the escaping defence).

**Files:**
- Create: `crates/core/src/ops/jira_body.rs`; Modify: `crates/core/src/ops/mod.rs`, `crates/core/src/ops/jira.rs` (`issue_create_executor`, `comment_add_executor`), `crates/core/src/validate/mod.rs` (`check_body_format` per product), `crates/core/src/core.rs` (`TestHooks::converter_fault`, `testing` only), `crates/registry/src/describe.rs`
- Test: `crates/core/tests/jira_validate.rs`, `crates/registry/tests/describe.rs` (add), `crates/core/tests/op_table.rs` (extend `executors_deterministic`)

**Interfaces:**
- Consumes: Tasks 3, 4 (`markdown_to_wiki`, `hard_check_wiki`); M3 `ExecCtx`, `ExecError::Invalid`, handler step 8 (dry executor call), `validate::invalid`.
- Produces: `pub(crate) fn jira_body::wiki_text(ctx: &ExecCtx<'_>, param: &str) -> Result<Option<String>, ExecError>` (absent param → `None`; `body_format` `wiki` → verbatim; `markdown`/absent → convert + hard check; `Unrecorded {kind, count}` → `ExecError::Invalid(ValidationError { code: Validation, message: "markdown conversion produced an unrecorded <kind>", details: {param, construct, count} })`, PD-43); under `#[cfg(feature = "testing")]`, when `ExecCtx` carries a fault, the converted text gets one unrecorded construct appended before the hard check (PD-64: `pub enum ConverterFault { Include, Mention, Html }` in `core::testing`; `ExecCtx.test_fault: Option<ConverterFault>` exists only under `cfg(feature = "testing")`, filled from `TestHooks::converter_fault` by the engine; production builds have neither). `check_body_format` keys the flip on `spec.product == Product::Jira && value == "markdown"` (an absent `body_format` counts as `markdown`, M3); every other case keeps the M3 behaviour exactly. `issue_create_executor` and `comment_add_executor` call it before any `EnrichmentRequired` return and put the wiki text into `fields.description` / `body`. `registry::describe` (`describe.rs::description`) appends for every Jira write the PD-42 sentence (plan text, a `/// plan text (PD-42)` const) after `WRITE_GUIDANCE`.

**Spec:** §5.4 step 1 (convert at validation, hard check → `REQUEST_REJECTED`, exit 2), §7.6, §2.3 (`ops describe` guidance), PD-42, PD-43.

- [ ] **Step 1: Failing tests** (`tests/jira_validate.rs`, Jira harness): `u33_jira_markdown_body_format_accepted` (`jira.comment.add` with `body: "**bold** and {toc}"`, no `body_format` → pending; after approve the wiremock-received body's `body` is `*bold* and \{toc\}` (escaped), equal to the `WRITE_APPROVED` request bytes); `u33_confluence_markdown_still_rejected` (`confluence.page.update` with `body_format: markdown` → `validation`, the M3 message); `wiki_body_format_is_verbatim` (`body_format: "wiki"`, `body: "{toc} [~jdoe]"` → sent unchanged, preview constructs list `toc` and `jdoe` — asserted in Task 14; here only the wire bytes); `u24_injected_fault_fails_validation_exit2` (`TestHooks { converter_fault: Some(ConverterFault::Include), .. }` → `jira.issue.create` with a Markdown description → `failed`, `validation`, exit 2, `request_id` set, events `[REQUEST_RECEIVED, REQUEST_REJECTED]`, `details.construct == "include"`, no wiremock hit, nothing queued; repeat for `Mention` and `Html` (→ `macro`)); `create_markdown_description_converted_before_enrichment` (the dry call rejects a fault before the createmeta GET: wiremock saw zero requests); `u33_issue_get_comments_param_validates` (`comments: "yes"` → `validation`; `true` passes). `tests/op_table.rs` `executors_deterministic` gains the markdown create and comment cases. `crates/registry/tests/describe.rs` :: `jira_writes_state_verbatim_rule` (every Jira write's `describe(..)["description"]` (built by `describe.rs::description`, after `WRITE_GUIDANCE`) contains the PD-42 sentence; no read and no Confluence write does).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite (full; markdown was rejected before, some M3 tests that asserted `pd09_markdown_body_rejected` for a Jira op must now use a Confluence op: change the test's op, not its intent, and say so in the report); `cargo test -p atlas-duck-registry --locked`; clippy core with `testing`.
- [ ] **Step 4: Commit** `feat(core): Markdown bodies for Jira writes converted and hard-checked at validation` (+ trailer), pathspecs `crates/core crates/registry`.

---

### Task 8: Jira field-name cache (`SYSTEM_FETCH {purpose: metadata_cache}`)

**Model:** Opus (a new PAT-bearing path outside requests).

**Files:**
- Create: `crates/core/src/metadata.rs`; Modify: `crates/core/src/core.rs` (start fills), `crates/core/src/instances/admin.rs` (fill after a passing connection test / `set_token`), `crates/core/src/ops/mod.rs` (Δ5 `PreviewCtx.field_names`), `crates/core/src/engine/read.rs` (pass the cached map; trigger a background refresh when stale), `crates/core/src/lib.rs`, `crates/core/src/testing/harness.rs` (`Harness::field_cache_filled().await`)
- Test: `crates/core/tests/metadata_cache.rs`

**Interfaces:**
- Consumes: M3 `payloads::{system_fetch_start, system_fetch_result, SystemFetchPurpose::MetadataCache}` (the enum value exists), `CoverIssuer::for_system_fetch`, the instance limiter, `HttpFactory`, the clock.
- Produces: `pub struct FieldNames(BTreeMap<String /* id */, String /* name */>)` with `get(id) -> Option<&str>`; `pub(crate) struct FieldCache` (per instance id: `Option<(FieldNames, UtcInstant)>`, a fill-in-progress flag so at most one fill per instance runs); `pub(crate) fn FieldCache::spawn_fill(engine, instance_id)` (start record → GET `/rest/api/2/field` → result record; a 2xx JSON array of `{id, name}` replaces the map; anything else keeps the old map and logs `metadata_cache_failed` (constant, no fields beyond `event`)); `FieldCache::snapshot(instance_id) -> Option<Arc<FieldNames>>` (never awaits); `FIELD_CACHE_TTL = 1 h`. Fill triggers: `Core::start` for every Jira instance in state `ok` (after `APP_START`, background), `InstanceAdmin::set_token`/`retest_token` success (background), and `read.rs` building a Jira read preview whose instance snapshot is older than the TTL (background; that preview uses the current snapshot). The identity check applies to the cache response like any Jira response (M3 per-response check); an identity failure is handled by the M3 recheck path for `SYSTEM_FETCH` and the map is not replaced.

**Spec:** §7.3 field rules ("Unknown custom ids are flagged in the preview (via the cached `/rest/api/2/field`; cache fills outside a request are logged as `SYSTEM_FETCH {purpose: metadata_cache}`)"), §8.3 `SYSTEM_FETCH`, §5.1 inv. 1, §6.3 Jira issue ("custom field names resolved via `/rest/api/2/field`"), PD-46.

- [ ] **Step 1: Failing tests** (`tests/metadata_cache.rs`): `metadata_cache_fill_is_covered_by_system_fetch` (after `Harness::jira()` start: the log has `SYSTEM_FETCH {purpose: metadata_cache, phase: start}` with `request_id` null, then the wiremock hit on `/rest/api/2/field`, then `{phase: result}` with the response; the hit happened after the start record's commit (sequence by `seq` vs the mock's receive order, as `i19` does)); `metadata_cache_never_under_a_request_id` (no `PREVIEW_FETCH`/`READ_FETCHED` ever names `/rest/api/2/field` during a `jira.issue.get` flow); `metadata_cache_never_blocks_preview` (the field mock delays 10 s; a `jira.issue.get` reaches `AwaitingRelease` and its preview is fetchable within 3 s; the field table shows ids as "customfield_10200 (unknown field)"); `metadata_cache_failure_keeps_old_map` (fill 1 ok, TTL elapsed via `FakeClock`, fill 2 answers 500 → names still resolved, `metadata_cache_failed` logged once); `metadata_cache_refreshes_after_ttl` (second fill after the clock passes 1 h, triggered by a preview build); `fill_after_set_token` (a replaced token triggers one fill).
- [ ] **Step 2: Implement.** No lock held across an `.await`; the fill runs on the core runtime via `tokio::spawn`; appends via the M3 port (`spawn_blocking`, PD-25).
- [ ] **Step 3: Run** the core suite; `cargo clippy` core with `testing`; `node ci/check-no-panic-macros.mjs`.
- [ ] **Step 4: Commit** `feat(core): per-instance Jira field-name cache filled through SYSTEM_FETCH metadata_cache` (+ trailer).

---

### Task 9: `jira.issue.get --comments`: the composite read (PD-45)

**Model:** Opus (read engine, candidate rebuild determinism, redaction mirror shape).

**Files:**
- Modify: `crates/core/src/ops/mod.rs` (`ReadPlan::IssueWithComments { issue: GetCall, comments: PagedCall, max_items: u64, rendered: bool }`), `crates/core/src/ops/jira.rs` (`issue_get_executor`), `crates/core/src/engine/read.rs` (fetch both under one cover and one `FetchControl`, record one `READ_FETCHED`, `result_body` merge), `crates/core/src/validate/mod.rs` (Δ7 `EffectiveCaps.comments_cap`), `crates/core/src/engine/cache.rs` only if the rebuild entry point needs the spec to merge (it calls `read::normalize`, which gains the merge)
- Create: `crates/core/tests/common/jira.rs` (helpers: `mount_issue(mock, key, body)`, `mount_comments(mock, key, pages: &[Value])`, `mount_comments_rendered`, `mount_createmeta_fields`, `mount_link_types`, `mount_assignable`, `mount_sprint`, `mount_projects`; later tasks add more here)
- Test: `crates/core/tests/jira_reads.rs`

**Interfaces:**
- Consumes: M3 `generic::read_plan`, `InstanceClient::{get_ctl, read_paginated_ctl}`, `PagedOutcome`, `read::{classify_read, result_body, normalize}`, `LaterPageRefused`; `jira.comment.list` spec (`COMMENT_LIST` endpoint, `PageSpec {comments, startAt, maxResults}`).
- Produces: `comments: true` → `ReadPlan::IssueWithComments` (issue `GET` with `fields` minus `comment`; comments `PagedCall` from `COMMENT_LIST`'s endpoint with `orderBy=created` and, when `rendered`, `expand=renderedBody`, `page_size = min(50, cap)`, `max_items = cap`); `comments: false` unchanged. Fetch order: issue, then comment pages; a non-2xx/non-JSON issue answer classifies exactly as today (the comment pages are not requested); a failing comment page is gated as `LaterPageRefused`. `READ_FETCHED` payload: the existing page list, page 0 the issue, then the comment pages (no new payload shape; `normalize` recognises the composite by the op id + `comments == true` in the committed params). Merge per PD-45 (fields.comment object; `renderedFields.comment.comments` from `renderedBody`; `renderedBody` removed from the field side); `server total` unchanged; Info `truncated_by_cap(N, total)` when `N < total` (Task 10's previewer reads a `ReadView` flag `comments_truncated: Option<(u64, u64)>`; add it here). Budget/caps: the 120 s read budget and 50 MiB fetch cap cover issue + pages together (one `ReadBudget`).

**Spec:** §7.3 `jira.issue.get` (`comments` → same executor as `jira.comment.list`, cap 100, configurable), §5.2 steps 2–4, §5.3 mirrors, §7.2 pagination, PD-45, Δ7, L17.

- [ ] **Step 1: Failing tests** (`tests/jira_reads.rs`): `comments_flag_merges_comment_pages` (issue + 2 comment pages of 50/20 → released `fields.comment.comments.len() == 70`, `total == 70`, `startAt == 0`; wiremock received exactly 1 issue GET (no `comment` in its `fields`) + 2 comment GETs with `startAt` 0 and 50); `comments_cap_and_truncated_info` (server total 250, cap 100 → exactly two comment GETs of 50 (`startAt` 0 and 50; never one page of 100), 100 comments released, `total == 250` unchanged, preview Info `truncated_by_cap (100 of 250)`; `EffectiveCaps { comments_cap: Some(10) }` via the harness limits → 10); `comments_rendered_mirror_shape` (`rendered: true` → `renderedFields.comment.comments[i] == {id, body: <renderedBody>}`, no `renderedBody` key on the field side); `comments_merge_rebuild_hash_stable` (evict the candidate (scaled cache), open again → no mock hit, same `candidate_hash`); `comment_page_failure_is_gated` (page 2 answers 302 → outcome item, never `READ_FAILED`); `issue_failure_requests_no_comment_page` (issue 404 → upstream-error item; zero comment GETs).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite (incl. `budget.rs`, `cancel.rs`, `reads.rs` unchanged); clippy.
- [ ] **Step 4: Commit** `feat(core): jira.issue.get --comments as a composite read merged into fields.comment` (+ trailer).

---

### Task 10: Jira issue previewer; §6.2 warning levels (U-34); `renderedFields` mirrors end to end (U-27); S-12 issue half

**Model:** Sonnet (medium).

**Files:**
- Create: `crates/core/src/ops/jira_preview.rs`; Modify: `crates/core/src/ops/mod.rs` (`jira.issue.get` previewer), `crates/core/src/ops/generic.rs` (expose `count_value`, `invisible_warnings`, `Identifiers` to `jira_preview`)
- Test: `crates/core/tests/jira_reads.rs` (add)

**Interfaces:**
- Consumes: Task 5 `wiki_to_preview_html`, Task 6 `PreviewBody::JiraIssue`, Task 8 `PreviewCtx.field_names`, Task 9 `ReadView.comments_truncated`, M3 `preview::sanitize_html`, `warning::*`, M3 redaction engine (`RedactionOp::DropItem`, `DropField { scope: PerItem }`, `MaskText`).
- Produces: `jira_preview::issue_preview(ctx) -> PreviewModel`: `IssueCard` from the released candidate (`key`, `fields.summary`, `issuetype.name`, `status.name`, `priority.name`, `assignee`/`reporter` `displayName (name)`), `FieldRow` for **every** released key of `fields` (and `renderedFields`, marked) in id order with `name` from `field_names` (system ids by a built-in map of the §7.3 fixed list; unknown `customfield_N` → "customfield_N (unknown field)"), `value_text` = compact JSON or the string, `description_html` = `sanitize_html(wiki_to_preview_html(description))`, `CommentView` per comment (`restricted` = `visibility` present) with `body_html` sanitized; warnings: Caution `restricted_comments` iff a released comment has `visibility` in `fields.comment.comments` **or** its `renderedFields` mirror (§6.2: "computed over both"), Caution `security_level` iff `fields.security` is non-null, Caution `all_fields` (M3 rule), the two invisible counts and mixed-script (M3 helpers), Info `linked_issue_summaries(n)` with n = `issuelinks` entries + `parent` (1) + `subtasks` entries, Info `custom_fields(n)` with n = released `customfield_*` keys, Info `truncated_by_cap` (Task 9). Rendered HTML never contains a remote URL as a resource (Task 5 guarantees; asserted here again after sanitizing).

**Spec:** §6.2 (levels follow the content; default fields include `parent`, `issuelinks`, `security` but only a non-null `security` raises a Caution), §6.3 Jira issue, §5.3 mirrors and the mirror check, §6.4, §13 U-27, U-34, S-12.

- [ ] **Step 1: Failing tests** (Jira harness; fixtures built in `tests/common/jira.rs` with an issue that has `parent`, two `issuelinks`, `customfield_10200`, `security: null`, no restricted comments, no invisible chars): `u34_default_issue_get_zero_caution` (zero `Level::Caution`, Info `linked_issue_summaries(3)` and `custom_fields(1)`); `u34_security_level_exactly_one_caution` (same issue with `security {id, name}` → exactly one Caution, id `security_level`); `u34_restricted_comment_caution_over_both_trees` (`comments: true, rendered: true` with one comment whose `visibility` is set → Caution `restricted_comments`; a variant where only the rendered mirror entry carries the restriction marker still raises it); `u27_drop_restricted_comment_rendered_leaves_nothing` (release with `DropItem` on that comment in `fields.comment.comments` → released bytes contain neither its `id`, nor its raw body, nor its rendered body; `meta.redactions.items_dropped == 1`); `u27_per_item_field_drop_and_mask_reach_mirror` (per-item drop of `body` and a mask of a word inside one comment reach the mirrored rendered entry); `u27_mirror_without_counterpart_blocks_release` (a candidate whose `renderedFields.comment.comments` holds an id absent from `fields` → release refused with the `internal` banner (M3 mirror check), `DECISION_INVALID {not_approvable}`); `s12_issue_preview_marks_invisible` (description with U+202E and `!https://evil.example/x.png!` → header bidi count 1, Caution `bidi_controls`, `description_html` without `<img`); `field_table_names_custom_fields_and_flags_unknown` (cache has `customfield_10200 → Team` → row name `Team`; `customfield_99999` → "customfield_99999 (unknown field)").
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite; clippy.
- [ ] **Step 4: Commit** `feat(core): Jira issue preview with §6.2 warning levels and mirror-safe comments` (+ trailer).

---

### Task 11: Jira search and list previewers; `meta.page` on Jira (I-22); the `jira.search` budget probe (I-09); paging end-test fix (M3 T10 minor 4)

**Model:** Sonnet (medium).

**Files:**
- Modify: `crates/core/src/ops/jira_preview.rs` (`search_preview`, `list_preview`), `crates/core/src/ops/mod.rs` (previewers of `jira.search`, `jira.sprint.issues`, `jira.backlog.issues` → `search_preview`; the 15 list/keyed reads → `list_preview`), `crates/atlassian/src/client/paginate.rs` (minor 4: `returned < l.min(want)`)
- Test: `crates/core/tests/jira_reads.rs` (add), `crates/core/tests/cancel.rs` (add), `crates/atlassian/tests/pagination.rs` (add)

**Interfaces:**
- Consumes: Task 6 `PreviewBody::Table`, M3 `release_meta`, `TestHooks::read_budget`, M3 I-09 helpers in `cancel.rs` (`probe_cancel`, `same`).
- Produces: `search_preview`: columns `key` + the requested (or default) `fields` in order, one row per issue (`value_text` of each field, string fields capped at 200 chars with "…"), `count = ItemCount {shown, total, more_available}` ("N of total"); Caution/Info as the M3 fallback (`all_fields`, invisible, mixed-script, `truncated_by_cap`). `list_preview`: for array roots and `values`/`issueLinkTypes`/`transitions`/`worklogs`/`comments` item lists, columns = the union of scalar keys of the first 50 items (first-seen order), else the M3 JSON-tree fallback (single objects such as `jira.myself`, `project.get`, `attachment.meta`, `editmeta`). The JSON tree stays the Raw-adjacent fallback; the Raw tab still shows the exact bytes (inv. 4).

**Spec:** §6.3 Jira search, Lists; §7.5 (normative `meta.page`); §7.2 pagination; §13 I-22 (first clause), I-09; V05 (paging trusts the server's page size).

- [ ] **Step 1: Failing tests:** `jira_reads.rs`: `i22_jira_drops_keep_totals_and_next_start` (`jira.search` max 10 over a mock with total 25: release with 2 issues dropped → `meta.page {start: 0, returned: 8, total: 25, truncated: true, next_start: 10}`, `meta.redactions.items_dropped == 2`, released `total == 25`); `i22_next_start_loop_rerequests_no_dropped_item` (an agent loop: three requests following `next_start` with drops each time; the union of requested `startAt` values is 0, 10, 20 and no dropped key is ever in a later page's request range); `i22_agile_islast_and_short_page` (`jira.board.list` / `jira.sprint.issues` with `isLast: true` on a short page → `next_start: null`, `truncated: false`); `search_table_columns_and_count`; `list_preview_tables` (`jira.issuelinktype.list`, `jira.transition.list`, `jira.user.assignable` → `Table` with the expected columns; `jira.myself` → JSON tree). `cancel.rs`: `i09_jira_search_budget_probe_cancel_identical` (`TestHooks::read_budget` 300 ms; probe A = an OR-predicate JQL whose mock pages each delay 200 ms so the budget expires on page 2 (outcome item); probe B = a non-matching JQL answered with 0 issues; each cancelled after reaching its queue state → identical envelope, exit code, details and status stream, by the M3 `same` helper; precondition asserted: A's queue item is an outcome item). `pagination.rs`: `short_last_page_is_not_end_of_results` (server echoes a `maxResults` larger than requested on the last page before `max_items` → `MaxReached` with `next_start: Some`).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core and atlassian suites with `testing`; clippy.
- [ ] **Step 4: Commit** `feat(core): Jira search and list previews, meta.page tests, jira.search budget probe; fix(atlassian): short last page end test` (+ trailer), pathspecs `crates/core crates/atlassian`.

---

### Task 12: Staged enrichment (Δ3); `jira.issue.create` complete: project + issue-type resolution, required fields, the edit form, `missing_fields` deny details (I-18, I-35 project/issue type, U-30 Jira)

**Model:** Opus (enrichment driver on the write path, approvability, deny details).

**Files:**
- Create: `crates/core/src/engine/enrich.rs` (the staged driver, moved out of `engine/write.rs`)
- Modify: `crates/core/src/ops/mod.rs` (Δ3 `EnrichRule`, `EnrichStep`, `MAX_ENRICH_STAGES`, Δ4 `EnrichVerdict` fields, `MissingField`, `WriteSummaryFacts`), `crates/core/src/ops/jira.rs` (wrap `ISSUE_EDIT_ENRICH`, `ISSUE_TRANSITION_ENRICH`; rewrite `ISSUE_CREATE_ENRICH` as three stages; `issue_create_executor` uses the resolved project key), `crates/core/src/ops/confluence.rs` (wrap `PAGE_UPDATE_ENRICH`), `crates/core/src/engine/write.rs` (call `enrich::run`), `crates/core/src/decision/mod.rs` (`MissingFields` arm of `deny_hint`), `crates/core/src/engine/mod.rs` or wherever `Preview` is assembled for writes (attach `edit_form`), `crates/core/src/ops/jira_preview.rs` (`create_preview`: `WriteSummary` card with resolved project/issue type, summary, rendered description, constructs, the missing-fields Caution), `crates/core/src/testing/approver.rs` (`ScriptedApprover::edit_preadded(id, path, value)`), registry `ISSUE_CREATE` `enrich_keys` lives in core: `ops/mod.rs` table row `["project", "issuetype", "fields"]`
- Test: `crates/core/tests/jira_create.rs`; existing `decisions.rs`, `writes.rs`, `upstream.rs`, `identity.rs` stay green

**Interfaces:**
- Consumes: Task 6 (`EditForm`, `WriteSummary`), Task 7 (`jira_body::wiki_text`), M3 `jira::resolve`, `unresolved`, `EnrichPurpose::{Enrich, Resolve}`, the M3 enrichment classification table (Task 22 "Algorithm notes" step 1 of the M3 plan), `edit::apply_edits`, `CONFLICT_DENY_PREFILL`.
- Produces: `enrich::run(engine, entry, rule, purpose_override) -> EnrichOutcome` looping `plan(ctx, answers)` → `Fetch(calls)` (each GET under the request cover, committed as `PREVIEW_FETCH {purpose}` exactly as M3 did per GET, classified by the M3 table; a direct failure ends enrichment as before; a gated failure → `EnrichmentError`) → … → `Judge` → `judge(ctx, answers)`; round 5 → `EnrichmentError` "internal" (fail closed). Refreshes (`purpose: refresh`) and edit re-runs (`purpose: enrich`) go through the same driver. Create rule (PD-48, PD-49): stage 1 `GET /rest/api/2/project` (resolve) → unresolved project → `Judge` early; stage 2 `GET /rest/api/2/issue/createmeta/{key}/issuetypes` (resolve) → unresolved issue type → `Judge`; stage 3 `GET /rest/api/2/issue/createmeta/{key}/issuetypes/{typeId}` (enrich; further `startAt` pages while `isLast == false`, ≤ 4) → `Judge`: `Preview` with `resolved {project_key, issuetype}`, `missing_fields`, Caution `missing_required_fields(list)` (PD-49 format), `summary` facts. `edit_form` for every write preview: one `EditInput` per schema param (from `params_schema_json`: string → `Text` (`LongText` for `description`/`body`/`comment`), integer → `Integer`, boolean → `Boolean`, object/array → `Json`), `read_only = target_params ∪ conflict_baselines` (L06), plus the pre-added `fields.<id>` inputs (PD-49). `deny_hint` `(MissingFields {include_allowed_values}, Some(Hold::Preview))` with a non-empty `missing_fields` → `{"code": "denied", "details": {"missing_fields": [...]}}` (§4.3 row); otherwise refused (`EditRejected`, nothing logged, M3 rule).

**Spec:** §5.4 step 2 (unresolved name, missing required fields, enrichment classification), step 4 (edit form, read-only targets), §4.3 `denied` rows, §6.3 Create, §7.3 `jira.issue.create`, §13 I-18, I-35, U-30, PD-48, PD-49, PD-62, L06, L25, L31.

- [ ] **Step 1: Failing tests** (`tests/jira_create.rs`, Jira harness + `common/jira.rs` mounts for projects, createmeta issuetypes and fields): `create_three_stage_enrichment_records` (events after `REQUEST_RECEIVED`: `PREVIEW_FETCH {resolve}` ×2, `{enrich}` ×1 in that order, each before the next GET hit); `i35_project_no_match_and_ambiguous` (`"Nope"` → `UnresolvedName {param: project, matches: 0}`, candidates ≤ 10; two projects named "Alpha" → matches 2; approve → `DECISION_INVALID {not_approvable}`; deny with `ResolutionFailed {include_candidates: false}` → `denied`, exit 3, `resolution_failed`, `details` without `candidates`; with `true` → with); `i35_issuetype_no_match_and_ambiguous`; `project_name_resolves_to_key` (`"Alpha Beta"` → body `fields.project == {"key": "ABC"}`); `i18_missing_fields_warning_approve_enabled` (createmeta marks `customfield_10200` required without default → Caution text exactly `missing required fields: Team (customfield_10200, option)`, approvable true, `edit_form` has a pre-added `fields.customfield_10200` `Choice` input with `["Platform"]`); `i18_edit_and_approve_preadded_input_sends_field` (`edit_preadded("fields.customfield_10200", {"value":"Platform"})` → enrichment re-runs (`PREVIEW_FETCH {enrich}` again), warning gone, approve → the wire body has the field; envelope `edited: true`, `edited_keys.added == ["fields.customfield_10200"]`); `i18_deny_missing_fields_allowed_values_only_when_ticked` (deny `MissingFields {false}` → `details.missing_fields[0] == {id, name, schema_type}` without `allowed_values`; `{true}` → with `["Platform"]`); `u30_create_added_field_value_not_delivered` (the added value `"Platform"` occurs nowhere in the delivered envelope); `missing_fields_hint_refused_without_missing_fields` (no missing field → `MissingFields` deny refused, nothing logged); `edit_form_read_only_targets` (`project` read-only, `summary` editable; an edit of `project` → `DECISION_INVALID {target_param_edit}` (M3)); `i23_enrichment_stage2_3xx_direct` (stage 2 answers 302 → `REQUEST_FAILED {upstream_unavailable}`, exit 6, direct, stage 3 never requested); `stage_failure_post_send_is_enrichment_failed` (stage 3 body truncated JSON → `EnrichmentError`, Approve disabled, deny `OutcomeHint` → `upstream_unavailable`); `enrich_round_limit_fails_closed` (a test-only rule whose plan always returns `Fetch` → `EnrichmentError` after 4 rounds, no fifth GET); `create_markdown_fault_rejected_before_stage1_get` (Task 7's ordering survives the rewrite: a `ConverterFault` on a create is rejected at validation with zero wiremock hits, not even the stage-1 project GET; Task 7's `create_markdown_description_converted_before_enrichment` must stay green too). Existing M3 tests for edit/transition/page update enrichment stay green unchanged (mechanical wrap).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite; clippy core with `testing`; `node ci/check-no-panic-macros.mjs`.
- [ ] **Step 4: Commit** `feat(core): staged enrichment; jira.issue.create with project and issue-type resolution, required fields, edit form and missing_fields deny details` (+ trailer).

---

### Task 13: `jira.issue.edit` complete: the `expected` check helper, edit diffs with `raw_only_diff`, the conflict card (I-36 Jira half, S-12 diff half)

**Model:** Opus (the `expected` conflict check and the stale baseline must agree).

**Files:**
- Modify: `crates/core/src/ops/jira.rs` (`field_values_equal` per PD-50 in `edit_judge`; enrichment fetches the current values of `fields`/`update`/`expected` ids (M3) plus `renderedFields` is **not** requested), `crates/core/src/ops/stale.rs` (`ISSUE_EDIT` uses `field_values_equal`), `crates/core/src/ops/jira_preview.rs` (`edit_preview`: `EditDiff` with rendered and raw diffs, `raw_only_changes`, Caution `raw_only_diff(n)`; the conflict body keeps M3's `PreviewBody::Conflict` with `diff_text` = the raw diff between the agent's `expected` and current, capped)
- Test: `crates/core/tests/jira_edit.rs`

**Interfaces:**
- Consumes: Task 5 `wiki_to_text`, Task 6 `line_diff`/`hunks`/`EditDiff`, Task 12 driver, M3 `EnrichVerdict.baseline` (current values of the edited ids), `CONFLICT_DENY_PREFILL`, `ipc::jcs::to_jcs_vec`.
- Produces: `pub(crate) fn field_values_equal(a: &Value, b: &Value) -> bool` (PD-50); `edit_preview` per PD-51 (current = `baseline`, outgoing = the request body's `fields.<id>`; `update` operations rendered as raw JSON lines); `describe` already recommends `expected` (M3 schema description); Task 13 asserts it.

**Spec:** §5.4 step 2 (conflict for `jira.issue.edit` with `expected`; deny pre-fill), step 5 stale rule for `jira.issue.edit`, §6.3 Edit/update and Conflict, §6.2 `raw_only_diff`, §7.3 `jira.issue.edit`, §13 I-36 (Jira half), S-12, PD-50, PD-51, L12.

- [ ] **Step 1: Failing tests** (`tests/jira_edit.rs`): `i36_edit_expected_conflict_not_approvable` (`expected.summary` ≠ mock → `Hold::Conflict`, Caution `conflict: fields changed since the agent read it: summary`, approve → `DECISION_INVALID {not_approvable}`, no `WRITE_APPROVED`; batch with a clean item → whole batch rejected (M3 L43)); `i36_conflict_deny_prefill_and_exit3` (deny with reason `CONFLICT_DENY_PREFILL` → `denied`, exit 3, `message` equals the text); `i36_expected_match_approvable` (equal values incl. an object `{"id": "3", "name": "Major"}` given with different key order → `Preview`, approve executes, 204 empty → `succeeded`, receipt `{}`); `expected_over_range_integer_is_conflict` (PD-50); `edit_preview_diffs` (description `"a\nb"` → `"a\nc"` → rendered and raw diffs each one Del + one Add, `raw_only_changes == 0`); `s12_raw_only_diff_flagged` (description change that only alters `{color:red}` styling or a trailing `\` escape → rendered diff empty, raw diff non-empty → `raw_only_changes == 1`, Caution `1 changes not visible in rendered diff`); `labels_update_shown_raw` (`update: {"labels":[{"add":"x"}]}` → raw lines only, sent verbatim); `stale_edit_uses_same_equality` (stale check sees the baseline value re-serialized with different key order → `Unchanged`; a changed value → `WRITE_STALE {changed}` with delta naming the id); `describe_recommends_expected` (`registry::describe(jira.issue.edit)` text mentions `expected` and `description`).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite; clippy.
- [ ] **Step 4: Commit** `feat(core): jira.issue.edit with the expected check helper, rendered and raw diffs and the raw-only warning` (+ trailer).

---

### Task 14: `jira.comment.add` and `jira.issue.transition` previews; transition name resolution tests (I-35 transition); I-28 with a Markdown body

**Model:** Sonnet (medium).

**Files:**
- Modify: `crates/core/src/ops/jira_preview.rs` (`comment_preview`: `WriteSummary` "comment on <key>" with rendered body, visibility row, constructs; `transition_preview`: `PreviewBody::Transition {from, to, fields}` from the verdict's `summary` facts), `crates/core/src/ops/jira.rs` (transition judge fills `WriteSummaryFacts {from_status, to_status}` from the two enrichment answers), `crates/core/src/ops/mod.rs` (previewers)
- Test: `crates/core/tests/jira_writes.rs`

**Interfaces:**
- Consumes: Tasks 5, 6, 7, 12.
- Produces: the two previewers; `WriteSummaryFacts { from_status: Option<String>, to_status: Option<String>, assignee_from: Option<String>, link_phrase: Option<String>, sprint: Option<(String, String)> }` (Δ4, filled by later tasks for their ops).

**Spec:** §6.3 Transition ("From → to status, plus fields set during transition"), Assign/link/…, §7.6 constructs list, §13 I-28, I-35, PD-47.

- [ ] **Step 1: Failing tests** (`tests/jira_writes.rs`): `comment_preview_lists_constructs` (`body_format: wiki`, body `{toc} [~jdoe] [link|https://x]` → `constructs.macros == ["toc"]`, `mentions == ["jdoe"]`, `links == ["https://x"]`; the rendered body has no `<a`); `comment_preview_markdown_rendered` (Markdown body → preview shows the converted wiki rendered, constructs empty); `transition_preview_from_to_and_fields` (resolved "Done" from "In Progress" with `fields.resolution` → `Transition {from: "In Progress", to: "Done", fields: [("resolution", …)]}`); `i35_transition_no_match_and_ambiguous` (`"Doen"` → 0 matches, candidates all names; two transitions named "Close" → ambiguous); `i28_markdown_comment_identity_call_stale` (anonymous identity call (M3 `XAuser::Anonymous` on `/myself`) → `WRITE_STALE {identity_mismatch}`, nothing sent, Approve disabled); `transition_comment_sent_verbatim` (PD-42: `comment: "{toc}"` arrives unchanged and is listed in constructs).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite; clippy.
- [ ] **Step 4: Commit** `feat(core): comment and transition previews with construct lists` (+ trailer).

---

### Task 15: `jira.issue.assign`: executor, assignable-user resolution, stale rule, preview (I-35 assignee, I-26 assign)

**Model:** Opus (name resolution under the username comparison, a new stale rule).

**Files:**
- Create: `crates/core/src/ops/jira_ext.rs` (`ISSUE_ASSIGN_ENRICH`, `issue_assign_executor`); Modify: `crates/core/src/ops/stale.rs` (`ISSUE_ASSIGN`), `crates/core/src/ops/mod.rs` (table row: executor, `previewer: jira_preview::assign_preview`, `stale_check: Some(&stale::ISSUE_ASSIGN)`, `enrich: Some(&jira_ext::ISSUE_ASSIGN_ENRICH)`, `enrich_keys: &["assignee"]`), `crates/core/src/ops/jira_preview.rs` (`assign_preview`: sentence "assign <key> to <user>" / "unassign <key>", rows from → to)
- Modify tests: `crates/core/tests/op_table.rs` (`u05_only_writes_have_stale_check` expected set gains `jira.issue.assign`; `not_in_this_build_writes` loses it)
- Test: `crates/core/tests/jira_writes_ext.rs`, `crates/core/tests/reconcile.rs` (add)

**Interfaces:**
- Consumes: Task 12 staged rules, M3 `atlassian::username_matches`, `jira::resolve` helpers, `common/jira.rs` (`mount_assignable`, `mount_issue`).
- Produces: per PD-52 (stage 1 resolve unless `assignee` is null; stage 2 current assignee; baseline `{assignee_key, assignee_name}`; body `{"name": <name>|null}`; stale rule compares `fields.assignee.key`).

**Spec:** §5.4 step 5 table (`jira.issue.assign`: current assignee equals the previewed one), §7.3 (`{"name": …}`; users: payloads use `name`, previews and audit record `name` and `key`), §6.3 Assign, §13 I-35 ("assignable user"), I-26, PD-52, PD-62, L29.

- [ ] **Step 1: Failing tests** (`tests/jira_writes_ext.rs`): `assign_happy_path` (resolve `jdoe` → body `{"name":"jdoe"}`, 204 empty → `succeeded`, receipt `{}`; events include `PREVIEW_FETCH {resolve}`, `{enrich}`, the identity call, `{stale_check}`); `assign_null_unassigns_without_resolution` (no assignable search hit; body `{"name":null}`); `i35_assignee_no_match_and_ambiguous` (0 results; 2 results with the same `displayName` and no `name` match → ambiguous; Approve disabled; deny hint candidates only when ticked); `assignee_matches_percent_encoded_and_case` (`JDoe` resolves `jdoe` via `username_matches`); `assign_stale_when_assignee_changed` (stale-check GET shows another assignee → `WRITE_STALE {changed}`, delta "assignee changed since review", nothing sent, refreshed); `assign_preview_from_to` (`Jane Doe (jdoe)` → `Bob (bob)`). `tests/reconcile.rs`: `i26_crash_after_stale_check_fetch_is_outcome_unknown_jira_assign` (same pattern as the M3 transition test: `HookPoint` after the stale-check `PREVIEW_FETCH` commit, crash, restart → `outcome_unknown`, exit 6, `retryable: false`, startup notice lists `ABC-1`).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite; clippy.
- [ ] **Step 4: Commit** `feat(core): jira.issue.assign with assignable-user resolution and the assignee stale rule` (+ trailer).

---

### Task 16: `jira.issuelink.create`: executor, link-type resolution, preview, declared empty success (I-25 op cases, I-35 link type and the all-kinds table)

**Model:** Opus (resolution, declared-success edge cases).

**Files:**
- Modify: `crates/core/src/ops/jira_ext.rs` (`ISSUELINK_CREATE_ENRICH`, `issuelink_create_executor`), `crates/core/src/ops/mod.rs` (row: `enrich_keys: &["type"]`, `stale_check: None` per spec), `crates/core/src/ops/jira_preview.rs` (`issuelink_preview`: PD-53 sentence, comment constructs)
- Modify tests: `crates/core/tests/op_table.rs` (`not_in_this_build_writes` loses it)
- Test: `crates/core/tests/jira_writes_ext.rs` (add)

**Interfaces:**
- Consumes: Task 12, `common/jira.rs` `mount_link_types`; M3 declared-success mapping (`SuccessExpectation` from `{[201], Empty}`).
- Produces: per PD-53.

**Spec:** §7.2 declared write success (`{[201], Empty}` for `jira.issuelink.create`; 201 empty on Jira 10 with `text/html`), §7.3, §6.3 link summary, §13 I-25, I-35, PD-53, PD-62.

- [ ] **Step 1: Failing tests:** `i25_issuelink_201_empty_html_succeeded_receipt_empty` (mock 201, empty body, `Content-Type: text/html` → `succeeded`, exit 0, `data.receipt == {}`, no `UiEvent::Attention` of kind `Failed`/`OutcomeUnknown` (capture hook)); `i25_issuelink_201_html_body_outcome_unknown`; `i25_comment_add_empty_200_outcome_unknown` (a `Json` op answered 200 empty → `outcome_unknown`, exit 6); `issuelink_body_and_sentence` (`type: "blocks"` resolves by outward phrase to `Blocks` → body `{"type":{"name":"Blocks"},"inwardIssue":{"key":"ABC-124"},"outwardIssue":{"key":"ABC-123"}}`, sentence `ABC-123 blocks ABC-124 (Blocks)`); `i35_link_type_no_match_and_ambiguous` (`"Relates"` vs types `Relates`/`relates` names → ambiguous on name; `"zzz"` → 0); `i35_jira_kinds_no_match_and_ambiguous_not_approvable` (table over project, issue type, transition, assignee, link type: for each kind a no-match and an ambiguous request; each is non-approvable individually; a batch of one such item with a clean `jira.comment.add` is rejected whole, nothing decided; deny with candidates only when ticked delivers `resolution_failed` exit 3).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite; clippy.
- [ ] **Step 4: Commit** `feat(core): jira.issuelink.create with link-type resolution and declared empty success` (+ trailer).

---

### Task 17: `jira.worklog.add`

**Model:** Sonnet (medium).

**Files:**
- Modify: `crates/core/src/ops/jira_ext.rs` (`worklog_add_executor`), `crates/core/src/ops/mod.rs` (row: no enrich, no stale rule), `crates/core/src/ops/jira_preview.rs` (`worklog_preview`: "log <time_spent> on <key>", rows started/comment)
- Modify tests: `crates/core/tests/op_table.rs`
- Test: `crates/core/tests/jira_writes_ext.rs` (add)

**Interfaces:** Consumes Tasks 6, 12 (wrapped rule shape). Produces per PD-55.

**Spec:** §7.3 `jira.worklog.add`, §5.4 step 5 (rule "none"), §6.3 worklog summary, PD-55.

- [ ] **Step 1: Failing tests:** `worklog_add_happy_path` (body `{"timeSpent":"2h","comment":"Investigation"}`, 201 JSON `{"id":"11001",…}` → `succeeded`, receipt `{"id":"11001"}`); `worklog_started_passed_verbatim`; `worklog_identity_call_runs` (pre-write identity call present although the stale rule is none; anonymous → `WRITE_STALE {identity_mismatch}`).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite; clippy.
- [ ] **Step 4: Commit** `feat(core): jira.worklog.add` (+ trailer).

---

### Task 18: `jira.sprint.move_issues` and `jira.backlog.move_issues` (U-02, I-06 move cases, RF-4 move seeding)

**Model:** Opus (similarity/batch interaction, a new stale rule, the closed-sprint hold).

**Files:**
- Modify: `crates/core/src/ops/jira_ext.rs` (`SPRINT_MOVE_ENRICH`, `sprint_move_executor`, `backlog_move_executor`), `crates/core/src/ops/stale.rs` (`SPRINT_MOVE`), `crates/core/src/ops/mod.rs` (rows: sprint move `stale_check: Some(&stale::SPRINT_MOVE)`, `enrich_keys: &[]` (the sprint id is a target param, the issues list re-renders only), backlog move no enrich, no stale rule), `crates/core/src/ops/jira_preview.rs` (`move_preview`: "move N issues to sprint <name> (<state>)" / "move N issues to the backlog", table of keys)
- Modify tests: `crates/core/tests/op_table.rs` (`not_in_this_build_writes` becomes empty for Jira; stale set gains `jira.sprint.move_issues`), `crates/core/tests/similarity.rs` (add the carried seeding test)
- Test: `crates/core/tests/jira_moves.rs`

**Interfaces:**
- Consumes: Task 12, M3 `validate::caps::move_limit` and its hint, M3 `SimilarityIndex::{seed, similar_to}` (move-key seeding code exists), M3 batch (`decide_batch`, L43), `common/jira.rs` `mount_sprint`.
- Produces: per PD-54; body `{"issues": [..]}` for both (agile 1.0), success `{[204], Empty}` (registry).

**Spec:** §7.3 move limit (static validation, hint verbatim), similarity `MoveIssues`, §5.4 step 5 (sprint state still `future` or `active`), §5.6 batch rules ("three opened `jira.sprint.move_issues` requests of disjoint ≤ 50-issue sets into one sprint are not flagged and batch-approve, while two moves sharing an issue key are flagged and their batch is rejected"), §13 U-02, I-06, RF-4 (seeding from decrypted `REQUEST_RECEIVED` of `MoveIssues` ops), PD-54, L13, L22, L45.

- [ ] **Step 1: Failing tests** (`tests/jira_moves.rs`): `u02_sprint_move_over_50_rejected` and `u02_backlog_move_over_50_rejected` (51 keys → `failed`, `validation`, exit 2, message/hint "split into requests of ≤ 50 issues; moves of disjoint issues can be batch-approved" verbatim, events `[REQUEST_RECEIVED, REQUEST_REJECTED]`, nothing queued); `sprint_move_happy_path` (active sprint → body `{"issues":["ABC-1","ABC-2"]}`, 204 → `succeeded`, receipt `{}`); `sprint_closed_not_approvable` (closed → `EnrichmentError` with the PD-54 text, approve → `not_approvable`, plain deny only (any hint refused)); `sprint_move_stale_when_sprint_closed` (state turns `closed` between approval and the stale check → `WRITE_STALE {changed}`, delta "sprint closed since review", nothing sent); `i06_three_disjoint_moves_batch_approve` (three opened requests into sprint 7 with disjoint keys → no "similar" flag, `decide_batch` approves all three, three `WRITE_EXECUTED`); `i06_moves_sharing_key_flagged_batch_rejected` (two requests sharing `ABC-2` → the second carries `similar_to`, a batch of both → `BatchRejected` with `batch_item_flagged`, nothing decided); `backlog_move_happy_path`. `tests/similarity.rs`: `rf4_seeding_reads_move_payloads` (submit a sprint move, crash and restart through `Harness::reopen_and_restart` (M4), resubmit a move sharing a key into the same sprint → Caution "similar to req_… " naming the first request; a backlog move sharing a key likewise).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite (incl. `batch.rs`, `similarity.rs`); clippy.
- [ ] **Step 4: Commit** `feat(core): sprint and backlog moves with sprint-state enrichment and stale rule (U-02, I-06 moves, RF-4 move seeding)` (+ trailer).

---

### Task 19: Identity and recheck sweep on the Jira paths: RF-5b, `recheck_failed` classes on every stale rule (I-23), the carried M3 T26 test gaps, PD-61

**Model:** Opus.

**Files:**
- Modify: `crates/core/src/identity.rs` (PD-61: a parsed Jira 200 without `name`/`key` → token failure; T26 review M-1: update the runtime table and refresh writes only after the keychain store succeeded; PD-65 (T26 M-6): a stale check against a `needs_token` instance records `WRITE_STALE {identity_mismatch}` instead of `recheck_failed {needs_token}`), `crates/core/src/engine/write.rs` (only where a T26 gap test shows a deviation; each change named in the report)
- Test: `crates/core/tests/jira_identity.rs`

**Interfaces:**
- Consumes: M3 `identity::{recheck, Effect, apply_rename}`, `XAuser`, `TestHooks`, every Jira write of Tasks 12–18.
- Produces: tests (and the PD-61 / M-1 / M-6 fixes). No new API.

**Spec:** §7.1 401 handling, token re-test, username rename; §7.2 identity check on responses, *Header lost*; §5.4 step 5 (identity mismatch, re-check failed); §11.2; RF-5 (b), V25, PD-58, PD-61.

- [ ] **Step 1: Failing tests** (`tests/jira_identity.rs`): `rf5b_jira_agile_header_absent` (`/myself` carries `X-AUSERNAME: jdoe`; `jira.board.list` and `jira.sprint.issues` answers carry none → each read `failed`, exit 6, `upstream_unavailable`, `retryable: true`, no `details.reason`, instance state stays `ok`, one `SYSTEM_FETCH {purpose: token_recheck}` start+result per read; the body is in `READ_FETCHED` only); `rf5b_search_post_header_absent` (same for `jira.search`); `rf5b_rechecks_coalesce_and_are_logged` (8 concurrent Agile reads → `token_recheck` count ≤ 8 and ≥ 1, every recheck GET passed the limiter (max 4 concurrent at the mock: `RawHttpServer::max_concurrent` or a counting responder), every recheck logged; no read is ever released); `i23_jira_stale_rules_recheck_failed_classes` (table over `jira.issue.edit`, `jira.issue.transition`, `jira.issue.assign`, `jira.sprint.move_issues`: the stale-check GET answers 503, 302, HTML 200, a 33 MiB JSON body, and a reset → `WRITE_STALE {recheck_failed, class}` with `http_503`, `redirect`, `non_json`, `too_large`, `network`; nothing sent; `candidate_rev` bumped; opened cleared; approvable again ("the user may approve again later")); `t26_stale_check_rename_reruns_once` (identity call returns the stored key with a new name and a matching header → `INSTANCE_STATE_CHANGED {user_renamed}`, the stale-check GET re-runs once, then the write executes); `t26_refresh_identity_failure_returns_identity_mismatch` (a refresh after `changed` whose identity check fails → `WRITE_STALE {identity_mismatch}`); `t26_header_class_write_stale` (instance enters `identity_header_missing` → `WRITE_STALE {identity_mismatch, class: identity_header_missing}`, Caution with the admin text, Approve disabled); `t26_inconclusive_stale_recheck_recheck_failed` (recheck answers 503 → `recheck_failed {identity_recheck}`); `t26_write_response_rename_stays_outcome_unknown` (write response `X-AUSERNAME` = renamed user → `WRITE_OUTCOME_UNKNOWN {identity_mismatch, server_user}`, no retry); `pd61_recheck_without_name_or_key_is_token_failure` (Jira `/myself` 200 `{}` → `needs_token`, `INSTANCE_STATE_CHANGED`); `t26_m1_rename_keychain_failure_no_table_update` (`MemKeyStore` set fails during the rename → the runtime name is unchanged and no second `user_renamed` record follows on the next response); `t26_m6_needs_token_stale_is_identity_mismatch`.
- [ ] **Step 2: Implement** the fixes the tests force.
- [ ] **Step 3: Run** the core suite (incl. `identity.rs`); clippy.
- [ ] **Step 4: Commit** `fix(core): Jira identity sweep (RF-5b, stale-rule recheck classes, M3 T26 gaps, recheck answer without name or key)` (+ trailer).

---

### Task 20: Write-scoped audit cover (Δ6, M3 final review M-18)

**Model:** Opus (audit-before-effect at type level).

**Files:**
- Modify: `crates/atlassian/src/cover.rs` (`WriteCover`, `CoverIssuer::for_write`, `CommitProbe::write_approved`), `crates/atlassian/src/client/write.rs` (`send_approved`, `send_approved_ctl` take `&WriteCover`), `crates/atlassian/src/lib.rs` (re-export), `crates/atlassian/src/testing/mod.rs` (`AllCommitted` answers `write_approved` true), `crates/core/src/audit_port.rs` (`StoreProbe` answers from the committed set; `commit_write_approved(request_id, counter)` marks after `append` returned `Ok`), `crates/core/src/engine/write.rs` (`execute` mints the cover with the approval's counter right before `send_approved_ctl`; a refusal → `WRITE_FAILED {internal}`, nothing sent), `ci/check-no-panic-macros.mjs` (cover-minting tripwire: `for_write(` only in `crates/core/src/engine/write.rs`; `WriteCover` constructors only in `cover.rs`) + its test
- Test: `crates/atlassian/tests/cover.rs`, `crates/core/tests/writes.rs` (add)

**Interfaces:** Δ6. `WriteCover` has a private constructor, is `!Clone`, and carries `request_id` + `candidate_counter`; `send_approved_ctl` compares nothing new on the wire (the M3 byte comparison stays).

**Spec:** §5.1 inv. 1 and inv. 3 ("execution of a write (`WRITE_APPROVED`)" is gated by its committed record), §7.2 audit guard, PD-56.

- [ ] **Step 1: Failing tests:** `crates/atlassian/tests/cover.rs`: `m18_write_cover_requires_committed_approval` (probe answers false → `for_write` is `Err(NotCommitted)`; true → `Ok`); `m18_stale_revision_cover_refused` (probe committed counter 3, ask 4 → `Err`); `request_cover_is_not_a_write_cover` (compile-fail doctest: passing an `AuditCover` to `send_approved` does not compile). `crates/core/tests/writes.rs`: `m18_execute_uses_write_cover` (a `FaultyAudit` that fails the `WRITE_APPROVED` append → no `send_approved` call (mock received nothing), `audit_failure`); `m18_superseded_approval_cannot_send` (approve rev 3, then a stale return and re-approve rev 5: the rev-3 execute task's cover request for counter 3 is refused once the approval moved on (the M3 approval binding plus the cover: nothing sent twice; exactly one write hit)). `ci/check-no-panic-macros.test.mjs` fixtures for the new tripwire.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the atlassian and core suites with `testing`; clippy both; `node ci/check-no-panic-macros.mjs && node --test "ci/*.test.mjs"`.
- [ ] **Step 4: Commit** `feat(atlassian,core): write-scoped audit cover minted only from a committed WRITE_APPROVED (M-18)` (+ trailer), pathspecs `crates/atlassian crates/core ci`.

---

### Task 21: M3 carry-overs: `READ_RELEASED.candidate_rev` and exact U-32, write opacity over enrichment results, unsent 2nd GET, 429 answers, one parse per page

**Model:** Sonnet (medium).

**Files:**
- Modify: `crates/core/src/payloads.rs` (PD-57: `candidate_rev` in `READ_RELEASED`/`SCRIPT_RELEASED`), `crates/core/src/engine/write.rs` + `crates/core/src/engine/cancel.rs` (T24 M-4: mark `sent` per GET, set `in_flight` only once the request was handed to the connection; use the `FetchControl` capture's `sent` flag per call), `crates/atlassian/src/client/send.rs` (T10 minor 3: keep the last 429 answer; a budget expiry or cancel in the retry wait returns it as `Failed4xx` for writes / the 429 response for reads), `crates/atlassian/src/client/paginate.rs` (T10 minor 9: `PageFacts` from a small `#[derive(Deserialize)]` struct with the items counted via `IgnoredAny`, no second full `Value` parse)
- Modify tests: `crates/core/tests/audit_props.rs`, `crates/core/tests/opacity.rs`, `crates/core/tests/cancel.rs`, `crates/atlassian/tests/writes.rs`, `crates/atlassian/tests/pagination.rs`

**Interfaces:** Consumes M3 `PREVIEW_SHOWN` payload (`candidate_rev`), `ScriptedApprover::{release_unopened, approve_unopened}`, M3 opacity helpers. Produces the payload key and the fixes; no API change.

**Spec:** §8.3 (`READ_RELEASED` payload), §13 U-32 ("every approve or release decision has a `PREVIEW_SHOWN` for the same request and `candidate_rev`"), I-07 (opacity), §4.4 (cancelled in flight: "a fetch that had already written an HTTP request"), §7.2 (429), PD-57; M3 `task-29-review.md` M-10, M-11, ruling 2; `task-24-review.md` M-4; `task-10-review.md` minors 3, 9.

- [ ] **Step 1: Failing tests:** `audit_props.rs`: `u32_released_candidate_rev_matches_preview_shown` (every `READ_RELEASED`/`SCRIPT_RELEASED` in the M3 flow property carries `candidate_rev` (an object, never null) equal to a preceding `PREVIEW_SHOWN.candidate_rev` of the same request, outcome releases included); `u32_unopened_attempts_rejected_then_property_holds` (flows try `release_unopened`/`approve_unopened` after an edit or a redaction, expect `Err(Invalid(NotOpened))`, then the property runs). `opacity.rs`: `i07_write_streams_identical_enrichment_conflict_vs_match` (two `jira.issue.edit`, one whose `expected` matches and one that conflicts, and a third whose enrichment GET answers 404: identical pending status streams until the decision). `cancel.rs`: `get2_cancel_before_send_not_recorded_in_flight` (a write whose 2nd enrichment GET is held in the connect phase (`pause_after_get` on GET 1, then a never-accepting address for GET 2 via the harness) is cancelled → no `PREVIEW_FETCH {cancelled_in_flight}` for GET 2; GET 1's record present). `atlassian/tests/writes.rs`: `write_429_then_budget_expiry_is_failed4xx`, `write_429_then_cancel_is_failed4xx` (status 429, the body kept). `atlassian/tests/pagination.rs`: `page_facts_read_once_large_page` (a counting allocator or a parse counter seam shows one full parse per page; existing pagination tests green).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the atlassian and core suites with `testing`; clippy.
- [ ] **Step 4: Commit** `fix(core,atlassian): M3 carry-overs (candidate_rev on releases, exact U-32, write opacity, unsent GET not in flight, 429 answers, one parse per page)` (+ trailer), pathspecs `crates/core crates/atlassian`.

---

### Task 22: X-09 Jira (every op once, generated from the registry), X-10 Jira gates, I-19 over the new flows

**Model:** Sonnet (medium).

**Files:**
- Create: `crates/core/tests/x09_jira.rs`; Modify: `crates/core/tests/common/jira.rs` (`mount_for_op(mock, spec, params)`), `crates/core/tests/common/flows.rs` (I-19 property gains: a Markdown comment add, a three-stage create, an assign, an issuelink, a sprint move, an issue get with `--comments`)
- Test: as above, plus the existing `crates/core/tests/audit_coverage.rs` :: `i19_every_hit_is_covered`

**Interfaces:**
- Consumes: `registry::all()` (Jira ops), `OperationSpec::{params_schema_json, result_example_json, success, endpoint}`, every Jira `OpImpl`, `jsonschema` (dev), the harness.
- Produces: tests only. Generation rule (no hand-written per-op fixture list): for each Jira spec, params = `params_schema_json()["examples"][0]`; the mock answers the op's endpoint (method + path with the example's placeholders filled) with the op's `result_example` as JSON (reads; paged reads get `{startAt: 0, maxResults, total: n}` from the example itself), or with the declared success (`{[204], Empty}` → 204 empty; `{[201], Empty}` → 201 empty `text/html`; `Json` → 201 with the registry receipt example); enrichment and stale-check GETs are mounted by `mount_for_op` from a small per-op table in `common/jira.rs` (projects, createmeta issuetypes + fields with no required field, transitions, issue fields, assignable users, link types, sprint `active`), each body taken from the corresponding Jira **read** op's `result_example` where one exists (`jira.project.list`, `jira.createmeta.issuetypes`, `jira.createmeta.fields`, `jira.transition.list`, `jira.user.assignable`, `jira.issuelinktype.list`), so the fixtures cannot drift from the registry. Reads are released, writes approved, through `ScriptedApprover`.

**Spec:** master plan Table 3 X-09 ("Every registry op runs once against wiremock with the scripted approver (generated from the registry, one case per op id)"), X-10 (version floors; `min_version` gate yields exit 2 `op_unsupported_by_instance {min_version}` and never the version string), I-19, V06 (Jira half, wiremock), §7.2 declared success.

- [ ] **Step 1: Failing tests:** `x09_jira_every_op_once` (iterates all 28 Jira ids; for each: submit → released/succeeded; exit 0; a read's released `result` validates against its `result_schema`; a write's `data.receipt` equals the registry `result_example` (receipt projection) and its declared success shape was the mock's; prints one line per op `X09 <op_id> ok`; fails listing every op that did not pass, not just the first); `x10_jira_createmeta_available_on_floor` (instance at 8.14.0: `ops describe jira.createmeta.fields --instance` → `available: true`; the envelope contains no version string); `i19_every_hit_is_covered` stays green with the extended flows (every wiremock hit, incl. the cache fill, stage GETs and comment pages, maps to a committed covering record and a response record; `User-Agent` on every hit).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite; clippy.
- [ ] **Step 4: Commit** `test(core): X-09 Jira generated from the registry, X-10 Jira gates, I-19 over the new flows` (+ trailer).

---

### Task 23: `jira_flows`: the real binaries on the new Jira paths

**Model:** Sonnet (medium).

**Files:**
- Create: `app/src-tauri/tests/jira_flows.rs` (`#![cfg(feature = "scripted-approver")]`; `#[path = "cli_flows/harness.rs"] pub mod harness;`; `#[path = "jira_flows/flows.rs"] mod flows;`), `app/src-tauri/tests/jira_flows/flows.rs`
- Modify: `app/src-tauri/src/testing/approver.rs` (two test-only directives: `edit-preadded` = open, fill every pre-added `fields.<id>` input with its first allowed value (else `"x"`), submit the edit, open the new revision, approve; `deny-hint` = deny with the hint applicable to the hold (`ResolutionFailed {include_candidates: false}`, `MissingFields {include_allowed_values: false}`, `OutcomeHint`, `UpstreamHttp {include_messages: false}`), reason `DENY_REASON`; both added to `directive_parsing_table`)
- No harness change unless a flow needs a helper; any helper added to `cli_flows/harness.rs` must keep every `cli_flows` test compiling and unchanged

**Interfaces:**
- Consumes: M4 `World` (`provision_store`, `cli`, `mock(alias)`, `audit_records`, `quit_app`, `opted_in`), `MockDc::{json, empty, html}`, Tasks 7–18.
- Produces: tests only. Every flow: `if !opted_in("<name>") { return Ok(()); }` first; `World::new` + `provision_store(&[("jira-main", Product::Jira)])`; extra mounts through `world.mock("jira-main")` (incl. `/rest/api/2/field` so the cache fill succeeds); CLI calls with `--reason atlas-test:<directive>`; assertions on exit codes, envelopes, the wire (`mock.received()`) and `audit_records()` after `quit_app`.

**Spec:** master plan M5 exit criterion (`cargo test -p atlas-duck-app --features scripted-approver --test jira_flows`), §4.1–§4.3, §13 I-18, I-36, I-25, U-02, PD-59.

- [ ] **Step 1: Write the flows** (`flows.rs`): `jira_flows_smoke` (`atlas-duck jira issue get ABC-1 --reason atlas-test:release` → exit 0, `released`); `md_comment_sent_as_wiki` (`jira comment add ABC-1 --body "**done** {toc}" --reason atlas-test:approve` → exit 0, receipt `{id}`; the received POST body's `body` is `*done* \{toc\}`); `i18_create_missing_field_edit_and_approve` (createmeta marks a required option field; `jira issue create --project ABC --type Bug --summary s --reason atlas-test:edit-preadded` → exit 0, `edited: true`, `edited_keys.added == ["fields.customfield_10200"]`, the received body has the field); `i36_edit_conflict_denied_exit3` (`jira issue edit ABC-1 --field summary='"new"' --expected '{"summary":"old"}' --reason atlas-test:deny` with the mock at another summary → exit 3, `denied`); `issue_get_comments_released` (`jira issue get ABC-1 --comments --reason atlas-test:release` → `data.result.fields.comment.comments` length as mounted); `issuelink_201_empty_succeeded` (`jira issuelink create --type Blocks --inward ABC-2 --outward ABC-1 --reason atlas-test:approve`, mock 201 empty `text/html` → exit 0, `data.receipt == {}`); `unresolved_transition_deny_hint_exit3` (`jira issue transition ABC-1 --transition Doen --reason atlas-test:deny-hint` → exit 3, `error.code == resolution_failed`, `details` has no `candidates`); `u02_move_51_issues_usage_exit2` (`jira sprint move-issues 7 --issues <51 keys>` → exit 2, `validation`, nothing queued: `requests list` empty).
- [ ] **Step 2: Run locally only what does not spawn:** `cargo test -p atlas-duck-app --features scripted-approver --locked --test jira_flows --no-run` and `cargo test -p atlas-duck-app --features scripted-approver --locked --lib` (the directive table); a plain `cargo test … --test jira_flows` run without `ATLAS_DUCK_CLI_FLOWS` prints one `skipped:` line per flow and passes (proves the opt-in guard; never set the variable locally). The flows themselves run in CI (Task 25).
- [ ] **Step 3: Commit** `test(app): jira_flows over the cli_flows harness; edit-preadded and deny-hint test directives` (+ trailer), pathspec `app/src-tauri`.

---

### Task 24: Live L-01 tests for the Jira §15 items (manual, env-gated)

**Model:** Sonnet (medium).

**Files:**
- Create: `crates/core/tests/live_jira.rs`

**Interfaces:**
- Modify: `crates/core/src/testing/harness.rs` (adds `HarnessBuilder::live(url, pat)`).
- Consumes: `core::testing::Harness` with that builder pointing at a real instance (https only, real `KeychainCredentials` over `MemKeyStore`, no `allow_http`), the CLI-free handler API.
- Produces: `#[ignore = "manual live run against a real Jira DC (L-01)"]` tests that return `Ok(())` immediately with a printed `skipped: live env not set` line unless the three variables are set (PD-60): `v05_max_results_clamp_labels_update_unassign` (prints the server's `maxResults` for `max` 500 and 1000 on `jira.search`; adds and removes a label via `update`; assigns then unassigns with `{"name": null}` in the scratch project and prints the observed result); `v06_jira_write_success_shapes` (each Jira write once in the scratch project; prints status, `Content-Type` and body emptiness per op and whether it matches the registry `success`); `v23_jira_sso_front_classification` (if `ATLAS_DUCK_LIVE_JIRA_SSO_URL` is set: a request through the SSO front prints the status and content type and the M3 classification); `v25_agile_and_search_send_xausername` (prints whether `X-AUSERNAME` is present on `/myself`, `POST /rest/api/2/search`, `/rest/agile/1.0/board`, and its exact bytes for the configured user); `m16_public_ca_with_custom_ca_connects` (connection test against `ATLAS_DUCK_LIVE_PUBLIC_URL` (a public-CA host) with an unrelated custom CA configured → passes).

**Spec:** §13 Live ("Env-gated tests against real DC instances … covering the §15 verification items"), V05, V06, V23, V25, M3 final review M-16, PD-60.

- [ ] **Step 1: Write the tests.** No secret is printed (the PAT never; usernames are printed only as `<configured user>` vs `<other>`).
- [ ] **Step 2: Run** `cargo test -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked --test live_jira -- --list` (compiles, all listed as ignored). Never run them with `--ignored`.
- [ ] **Step 3: Commit** `test(core): env-gated live Jira tests for V05, V06, V23, V25 and M-16 (manual)` (+ trailer).

---

### Task 25: CI wiring: M5 suites, `jira_flows` on every GitHub leg, feature-leak and checker updates

**Model:** Sonnet (medium); the reviewer is Opus.

**Files:**
- Modify: `.github/workflows/ci.yml`, `ci/cli-flows-linux.sh`, `.gitlab-ci.yml` (comment only: `jira_flows` runs on GitHub only, same reason as `cli_flows`)

**Interfaces:** Consumes the M4 CI structure (`rust` job legs, `rust-macos-x86_64-rosetta`, `core-suite-fedora`, `supply-chain`, `ci/check-no-skips.mjs`, the "Kill stray atlas-duck-app processes" `always()` step) and Tasks 1, 23.

**Spec:** §13 CI row, master plan M5 exit criterion, PD-59.

- [ ] **Step 1: `ci/cli-flows-linux.sh`:** `cargo_args=(test -p atlas-duck-app --features scripted-approver --locked --test "${CLI_FLOWS_TEST:-cli_flows}")`, log file `$TMPDIR/${CLI_FLOWS_TEST:-cli_flows}.log`; every message names the target; `bash -n` passes.
- [ ] **Step 2: `ci.yml` `rust` job:** after the M4 suite steps, "M5 suites": `cargo test -p atlas-duck-convert -p atlas-duck-preview --locked`, and the existing M3 core/atlassian `testing` step now covers the M5 core tests (no change beyond confirming the new test files are picked up: the step runs the whole package). New steps "M5 jira_flows (Linux)" = `CLI_FLOWS_TEST=jira_flows bash ci/cli-flows-linux.sh`; macOS and Windows: copies of the M4 `cli_flows` steps with `--test jira_flows` and their own log/list/ignored files and `node ci/check-no-skips.mjs`; the `rust-macos-x86_64-rosetta` job gains the same under `--target x86_64-apple-darwin`. The feature-leak step is unchanged (PD-64: no new test-only feature). `core-suite-fedora` collects the `atlas-duck-convert` test binaries too (add the package to its `cargo test --no-run` line).
- [ ] **Step 3: Local checks:** `bash -n ci/cli-flows-linux.sh` (Git Bash), `node ci/check-workspace.mjs && node --test "ci/*.test.mjs"`, a YAML parse of `ci.yml` with the existing checker or `node -e` + a YAML-free sanity grep (no new tool). Push is the lead's; record the CI run URL in the report after the lead pushes.
- [ ] **Step 4: Commit** `ci: M5 suites and jira_flows on every GitHub leg` (+ trailer), pathspecs `.github ci .gitlab-ci.yml`.

---

### Task 26: Exit-criterion run and evidence

**Model:** Sonnet (medium).

**Files:** none changed unless a gate fails (then fix in the owning task's files with a `fix(<crate>):` commit).

- [ ] **Step 1: Locally on Windows:**

```bash
cargo test -p atlas-duck-convert -p atlas-duck-preview --locked
cargo test -p atlas-duck-atlassian -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked
cargo test -p atlas-duck-convert -p atlas-duck-preview -p atlas-duck-core --locked
cargo test --workspace --locked
cargo test -p atlas-duck-app --features scripted-approver --locked --test jira_flows --no-run
cargo test -p atlas-duck-app --features scripted-approver --locked --lib
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy -p atlas-duck-atlassian -p atlas-duck-core --all-targets --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked -- -D warnings
node ci/check-workspace.mjs && node ci/check-no-panic-macros.mjs && node --test "ci/*.test.mjs"
cargo tree -p atlas-duck-app -e normal,build --target all --locked --format "{p} [{f}]" --prefix none
```

Expected: every command exits 0; the tree's bracketed feature lists contain none of `testing|insecure-test-http|test-paths|test-env|scripted-approver` (and the same command with `--features scripted-approver` shows them all). `cargo build -p atlas-duck-app --release --locked` once (record the time).
- [ ] **Step 2: CI** on GitHub (GitLab for the non-flow jobs): `rust` (Windows MSVC, macOS arm64, Ubuntu 22.04) green incl. M5 suites, `cli_flows` and `jira_flows` with no skips; `rust-macos-x86_64-rosetta`, `core-suite-fedora`, `supply-chain`, `ui`, `bundle` green. Record the run URLs, the commit SHA and the X09 lines (28 `X09 … ok`) in the task report and in `.superpowers/sdd/2026-10-13-atlas-duck-m05-jira-adapter/progress.md`.
- [ ] **Step 3: Live items:** list for the lead that `live_jira.rs` (V05, V06, V23, V25, M-16) awaits a human run (PD-60); the master-plan exit criterion's "env-gated live tests L-01 … run once against a real Jira DC" is not satisfiable by agents.
- [ ] **Step 4:** Ask the lead to update the master plan M5 `Status:` after the final review, and to apply the ledger entries.

---

### Task 27: Final whole-branch review

**Model:** Opus (read-only review; fixes go to a Sonnet/Opus fix round per finding).

**Scope:** `master..m5-jira-adapter`. Re-check Review Focus 1–5 against the code and their tests; §5.1 inv. 1 on every new GET (stage, resolution, stale, cache fill, comment pages) and the write cover; opacity of every new envelope path (no resolution facts, missing-field lists, sprint states or diffs outside chosen deny hints); determinism of the executors (`WRITE_APPROVED` hash vs wire); escaping and the hard check (try to construct a Markdown input that yields an unrecorded construct; read the proptest strategy for blind spots); that every fixed string is verbatim with its doc comment; that no new `tracing` field carries content; the traceability table (every row's tests exist and are not vacuous); the CI wiring (`jira_flows` on every leg, no-skip checks). Output `.superpowers/sdd/2026-10-13-atlas-duck-m05-jira-adapter/final-review.md` in the M3/M4 format (Evidence, Critical, Important, Minor, deferred-items decisions, verdict).

---

## Self-review checklist (run before handing the plan to implementers)

- Every row of the Traceability table names a task that lists that test in its Step 1. ✔ (U-02 T18/T23; U-23 T03/T05; U-24 T04/T07; U-27 T10; U-30 T12; U-33 T07; U-34 T10; I-06 moves T18; I-09 T11; I-18 T12/T23; I-22 T11; I-23 T19/T12; I-25 T16; I-26 T15; I-28 T14; I-35 T12/T14/T15/T16; I-36 T13/T23; X-09 T22; X-10 T22; S-12 T05/T10/T13; RF-5b T19; L-01 T24; jira_flows T23; M-18 T20; move seeding T18; T24 M-4 T21; T29 handoffs T21; T10 minors 3/4/9 T21/T11; T26 gaps + M-3 T19; M-16 T24; cache T08; `--comments` T09.)
- No task depends on a later task's code, except: Task 6's `edit_form: None` compile fix in core (filled by Task 12); Task 7 wires Task 4's faulty converter into core through a `testing`-only `ExecCtx.test_fault` (Task 4 only provides the converter); Task 12 wraps the M3 enrichment rules mechanically before any later rule is written in the staged form; Task 22's generated test needs every Jira `OpImpl` (Tasks 12–18).
- Contract deltas Δ1–Δ7 are applied to the master plan before Task 1; the ledger entries below are recorded before the tasks that implement them merge (T07: L84, L85; T09: L86; T08: L87; T12: L88, L89; T13: L90; T15: L91; T16: L92; T18: L93; T21: L94; T19: L95; T24: L96).
- Security-critical or complicated tasks run on Opus: T02, T03, T04, T07, T08, T09, T12, T13, T15, T16, T18, T19, T20 (+ every reviewer, + T27).
- Nothing asks an implementer to run an installer, download a tool, change an ACL, kill a process, write outside the repo/scratchpad, run the spawning `jira_flows`/`cli_flows` locally, or run the live tests.
- Existing M3/M4 behaviour is re-used, not rebuilt: `meta.page`, redaction/mirrors, move limit, `edited_keys`, `recheck_failed`, deny hints, similarity seeding, identity rechecks, the `World` harness (section "What exists for Jira").

---

## Handoffs (to later milestones)

- **M6:** render `Preview.edit_form` (pre-added inputs, read-only targets and baselines), the Jira preview bodies (`JiraIssue`, `Table`, `WriteSummary`, `EditDiff`, `Transition`) in the `srcdoc` iframe with `preview.css`; Settings field for `[limits] jira_comments_cap` (PD-63); the "Could not re-check target" and conflict cards already have their models. M3 M-4/M-5/M-6/M-14/M-15 stay M6.
- **M7:** the Confluence half of `convert` (`markdown_to_storage`, `hard_check_storage`, storage→Markdown, placeholder check) reuses Task 3's escaping helpers where they fit and `pulldown-cmark`'s `into_offset_iter`; flip `check_body_format` for Confluence; the staged `EnrichRule` (Δ3) is the shape for parent-page resolution and the attachment collision check; M3 T10 minors 7 (truncated Confluence version-conflict 400) and 8 (`_links.next` as an end signal) are Confluence work; ledger L81 (T15 launch-stub wait) stays with M7 if it touches the launch path, else M9.
- **M8:** M3 M-1 (`RunHandle::kill` must never block; kill outside the state lock) is untouched by M5; `SCRIPT_RELEASED.candidate_rev` (PD-57) is written from M5 on, the script U-32 rows use it.
- **Live (human):** run `crates/core/tests/live_jira.rs` once against a real Jira DC 9.12/10.x (PD-60) and hand the printed V05/V06/V23/V25/M16 lines to the lead for spec and ledger updates (possible changes: PD-52 unassign sentinel, PD-53 link body, PD-58 Agile exemption, declared success shapes).

---

## Ledger entries the lead adds (continuing after L83)

- **L84** (PD-42, §7.6, §7.3) Only `body_format`-bearing Jira params convert from Markdown (`jira.issue.create.description`, `jira.comment.add.body`); `comment` of transition/issuelink, `jira.worklog.add.comment` and every `fields`/`update` value are sent verbatim (wiki markup / plain text / REST shape); `ops describe` says so; previews list every construct.
- **L85** (PD-44, §7.6) The hard check also fails on images and attachment links in converted output; Markdown images become wiki links, raw HTML escaped text, `@name` text; `{include}`/`{excerpt-include}` count as includes.
- **L86** (PD-45, §7.3) `jira.issue.get --comments` is a composite read: issue GET + `jira.comment.list` pages up to the configurable cap (100), merged into `fields.comment {startAt, maxResults, total, comments}` and, with `rendered`, `renderedFields.comment.comments [{id, body}]`; beyond the cap an Info `truncated_by_cap`, no `meta.page`.
- **L87** (PD-46, §7.3, §8.3) The Jira field-name cache fills after a passing connection test, at start for `ok` Jira instances, and in the background when older than 1 h at a preview build; a preview never waits; display-only; unknown custom ids render as "customfield_N (unknown field)".
- **L88** (PD-48, §5.4 step 2) Project resolution for `jira.issue.create`: `id`, else key (case-insensitive), else name (case-insensitive) over `GET /rest/api/2/project`; the body uses the resolved key.
- **L89** (PD-49, §5.4 step 2, §6.2) The missing-required-fields Caution lists `<name> (<fieldId>, <schema.type>)` in createmeta order, at most 10 then "… and N more"; `jira.issue.create` re-runs enrichment on a `fields` edit.
- **L90** (PD-51, §6.3) Jira raw-only diff count: Σ over string fields of max(0, raw hunks − rendered hunks), rendered = `wiki_to_text` projection.
- **L91** (PD-52, §7.3, V05) `jira.issue.assign` with `assignee: null` sends `{"name": null}`; string assignees resolve over the assignable-user search (username comparison, then key, then a unique display name); pending the live V05 answer.
- **L92** (PD-53, §7.3) Link-type resolution: id, name, outward phrase, inward phrase (first unique rule wins); the body names the type by `name`.
- **L93** (PD-54, §5.4 step 2/5) A closed target sprint at enrichment holds the move non-approvable with "sprint <name> is closed; issues cannot be moved into a closed sprint"; no deny hint.
- **L94** (PD-57, §8.3) `READ_RELEASED` and `SCRIPT_RELEASED` payloads carry `candidate_rev`; U-32 compares it exactly.
- **L95** (PD-61, §7.1) A parsed Jira `/myself` 200 without `name` or `key` during a re-check is a confirmed token failure (aligns the M3 Inconclusive choice with §7.1).
- **L96** (PD-60, §13 Live, §15) The L-01 live tests are manual (no CI leg, no DC available to agents); V05, V06 (Jira), V23 (Jira), V25 (Agile/search) and M3 M-16 are design-resolved only until a human run.

---

## Spec-silent items for the lead (summary)

PD-42 (which params convert), PD-44 (hard check also on images/attachments), PD-45 (`--comments` merge shape), PD-46 (cache fill policy), PD-48 (project resolution rule), PD-49 (missing-fields text and edit-form shape), PD-51 (raw-only count), PD-52 (unassign sentinel; V05), PD-53 (link-type rule), PD-54 (closed sprint), PD-57 (`candidate_rev` on releases), PD-60 (live tests are manual), PD-61 (recheck answer without `name`/`key`).

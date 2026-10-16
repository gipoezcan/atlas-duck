# atlas-duck M7 (Confluence adapter + previews) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. One implementer subagent per task, one reviewer after each task. Each task below is self-contained: it names every file it touches, the interfaces it consumes from earlier tasks and the ones it must produce, and the tests with the assertions that matter.
>
> **Model policy for the executing agents (memory `subagent-model-preference`; only 5.5 models, never Fable):** each task header names its implementer and its reviewer. **Haiku (effort xhigh)** for easy, mechanical work (docs, checklists). **Sonnet (effort medium)** for normal tasks and their reviews. **Opus (effort medium)** only for the complicated or security-critical tasks (marked `Model: Opus`: the storage parser and both converters, the storage hard check and its fuzz, the preview renderer arms, the validation wiring of Confluence bodies, the read-shape and user-resolution engine work, RF-5a, `page.update`/`page.create`/`page.move`/`attachment.upload`, the identity and stale sweep) and for the reviews of those tasks and the final whole-branch review. Opus `xhigh` is reserved for the case where everything else failed.
>
> **Hard execution limits (corporate AV, memory `agent-execution-limits`):** no subagent downloads or runs executables, toolchains or installers, runs `cargo install`, `pip install`, `npm install -g` or any `npm install`/`npm ci`, changes ACLs or the registry, kills processes, or writes outside the repo and the session scratchpad (not `/tmp`, not `%TEMP%`). The one unlocked `cargo build` of Task 1 fetches crate *sources* from crates.io (as M5 did for `pulldown-cmark`); that is the only fetch, and no build script output is run by hand. **No agent starts `atlas-duck-app` (debug or release, with or without a webview) or `tauri-driver` locally.** `cli_flows`, `jira_flows`, the new `confluence_flows` and the `e2e` target spawn the real binaries and therefore run in GitHub CI only: implementers compile them (`--no-run`) and unit-test their pure helpers; a plain run without `ATLAS_DUCK_CLI_FLOWS` only prints `skipped:` lines (never set the variable locally). The live L-01 tests need a real Confluence DC (a Docker trial image would be a download): they are `#[ignore]` + env-gated and no agent runs them with `--ignored` (Task 25). Reading crates.io API metadata or docs.rs with WebFetch is allowed (Task 1).
>
> **Test time and memory (corporate laptop, memory `disk-usage-target-dir`):** exactly **one cargo process at a time** across all agents (the lead serializes; a reviewer that wants to run a test waits for the implementer's cargo to end); every cargo command passes `-j 4`; implementers build in the repo `target/`, every reviewer and debug agent reuses **one** shared scratch dir `<scratchpad>/m7-target` (`CARGO_TARGET_DIR`) and the lead deletes it at the end of the milestone; while iterating, run the task's own test files (`--test confluence_reads`), and the whole package suite once at the end of the task; record proptest runtimes. Local gates on the Windows dev machine are realistic only for: library crates (`convert`, `preview`, `registry`, `atlassian`, `core` with `testing`), `atlas-duck-app --lib`, the mock-runtime app tests, `--no-run` of every spawning target, `node ci/*.mjs` + `node --test`, and `npm --prefix app/ui run lint|test|build` with the toolchain already in `app/ui/node_modules`. Everything else (macOS/Linux legs, Fedora, Rosetta, the enforced `perf_sc3` release run, `cli_flows`/`jira_flows`/`confluence_flows`, `e2e`) is CI evidence.

**Goal:** Complete the 18 Confluence operations end to end: the storage parser, storage→Markdown with look-alike escaping and the committed `user_resolutions` map, the Markdown placeholder check, Markdown→storage with CDATA `]]>` splitting and the re-parse hard check, lossy-update detection, the `base_version` conflict state with the agent's base body, `format=markdown|storage|view` on `page.get`/`page.history`, Confluence previews (page, threaded comments, search with the effective CQL, lists, page create/update/move, comment, labels, attachment card), the six remaining Confluence write executors with their enrichment, parent resolution, collision handling and stale rules, the RF-5a decision for Confluence reads under the anonymous fallback, plus the M3/M5/M6 carry-overs M7 owns, all proved in-process against wiremock, generated per op from the registry (X-09), end to end through the real binaries (`confluence_flows`, CI) and with the two Confluence SC3 scenarios benchmarked.

**Architecture:** `convert` (pure, no I/O) gains a storage module: a `quick-xml` parser with an HTML named-entity resolver that is the single ground truth for the construct inventory, the hard check and the lossy count; `storage_to_markdown` (placeholders for `ac:`/`ri:` constructs, `htmd` for the remaining HTML, the CDATA-first fallback on XML failure); `markdown_to_storage` on the `pulldown-cmark` event stream (no `ac:`/`ri:` output except recorded code macros); the placeholder check over `into_offset_iter()` source spans; an in-house Markdown→preview-HTML renderer. `preview` gains the Confluence body variants and their `render` arms (`render3`). `core::ops::confluence` gets real executors, staged enrichment rules, stale rules and previewers; `core::engine::read` gets a Confluence body `ReadShape`, user resolution under the request cover with the committed map, `meta.conversion`, and the RF-5a identity step. `atlassian` changes only for the `_links.next` end signal. `registry` gets data corrections only. `app/src-tauri` gains the `confluence_flows` test target and the two P-01 scenarios in `e2e`. No new workspace crate, no new process, no IPC change, no new gate reason (StoreFailed stays deferred, lead ruling Q9).

**Tech Stack:** Rust 1.95.0 (edition 2024, MSRV 1.90). New in `convert`: `quick-xml =0.42.0` (already in `Cargo.lock` through `plist`), `htmd` (new; Task 1 picks the version per lead ruling Q6, `=0.5.5` is the master-plan placeholder). Existing pins otherwise (`pulldown-cmark =0.13.4`, `ammonia =4.2.3`, `sha2 =0.11.0`, `base64 =0.22.1`, `wiremock =0.6.5`, `proptest =1.11.0`, `jsonschema =0.58.6`). Full table in "Dependency pins".

**Spec:** `docs/superpowers/specs/2026-10-07-atlas-duck-design.md` (§1.4 SC3, §2.3, §4.2, §4.3, §5.1–§5.4, §5.6, §6.1–§6.4, §7.1, §7.2, §7.4, §7.5, §7.6, §8.3, §11.2, §11.3, §13 Unit/Integration/Security/Performance/Live rows, §14 M7, §15 V04/V06/V23/V25) + ledger `docs/superpowers/specs/2026-10-07-atlas-duck-review-ledger.md` (L07, L12, L13, L17, L22, L25, L29, L31; L99, L101, L103, L104, L105 M-4; L106, L107). **Master plan:** `docs/superpowers/plans/2026-10-07-atlas-duck-master-plan.md` (M7 entry; contracts C.1, C.4, C.5, C.6, C.7; Review Focus RF-5; Traceability Tables 1–3; X-09, X-10). **Earlier plans:** M5 (`2026-10-13-atlas-duck-m05-jira-adapter.md`: structure, PD-42..PD-65, "Handoffs → M7"), M6 (`2026-10-14-atlas-duck-m06-approvals-ui.md`: PD-66..PD-92, `preview::render`, `perf_sc3`, e2e P-01, "Handoffs → M7"). **Ledgers (git-ignored, `.superpowers/sdd/<plan>/`):** M5 `final-review.md` (M-4, M-5, deferred table: L101), M3 `task-10-review.md` (minors 7, 8), M6 `progress.md` and `task-22-report.md`/`task-22-review.md` (StoreFailed, deferred "LEAD/M7"), `task-10-review.md` (M-5: conflict card lacks the agent's intended change).

**Prerequisite:** M1–M6 merged on `master` (M6 is on `m6-approvals-ui` while this plan is written; the base commit is recorded by the lead at branch time); branch `m7-confluence-adapter`. Before Task 1 the lead (a) has answered every plan question (section "Lead rulings (2026-10-16)"; the task texts follow those rulings), (b) applies the contract deltas Δ1–Δ5 below to the master plan (C.1, C.5, C.6, C.7; Δ6 is dropped), and (c) records the ledger entries listed under "Ledger entries the lead adds" that early tasks need. **Numbering:** PD numbers continue after M6 (PD-66..PD-92) at **PD-93** (checked 2026-10-16: no PD-93 or higher in the spec, the ledger, the master plan or the M6 plan); new ledger entries start at **L136** (L120–L135 are taken by the M6 lead-docs commit `a8a6dc2`).

---

## What exists for Confluence on `master` and what M7 adds

Checked in `crates/registry/src/confluence/{reads,writes,schemas}.rs`, `crates/core/src/ops/{mod,confluence,generic,stale}.rs`, `crates/core/src/engine/{read,write,cache,script}.rs`, `crates/core/src/{identity,payloads,similarity}.rs`, `crates/core/src/validate/mod.rs`, `crates/atlassian/src/client/{send,write,paginate}.rs`, `crates/atlassian/src/testing/{mock_dc,fixtures}.rs`, `crates/convert/src/*`, `crates/preview/src/{model,render/*}.rs`, `crates/core/tests/*`, `app/src-tauri/tests/*`.

| Op | Registry spec (M3) | Executor | Enrichment / resolution | Stale rule | Previewer | M7 adds |
|---|---|---|---|---|---|---|
| `confluence.user.current` | complete | `generic::read_executor` | — | — | `generic::fallback_preview` | card/list preview (T12), RF-5a (T13), X-09 (T22) |
| `confluence.space.list`, `confluence.page.children` (paged), `confluence.space.get`, `confluence.page.find`, `confluence.label.list`, `confluence.attachment.list` | complete | generic | — | — | fallback | list tables (T12), I-22 `meta.page` + context path (T14) |
| `confluence.page.get` | complete; `format` enum present; **inert**: the endpoint always expands `body.storage` (registry comment "format=view swaps … (core)" not built) | generic | — | — | fallback | `format` handling and `meta.conversion` (T10), user resolution (T11), page preview (T12), RF-5a (T13) |
| `confluence.page.history` | complete (`alt_endpoint` with `version`); `format` inert | generic | — | — | fallback | `format` on the historical body (T10, T11) |
| `confluence.comment.list` | complete (paged, `depth=all`) | generic | — | — | fallback | threaded preview (T12) |
| `confluence.search` | complete | `confluence::search_executor` (CQL rewrite, M3) | — | — | `confluence::search_preview` (fallback + effective CQL) | §7.4 result pruning, table, `cql_broad` (T12) |
| `confluence.page.create` | complete | **`LATER_WRITE`** (`NotInThisBuild`) | — | none (spec) | fallback | everything (T16) |
| `confluence.page.update` | complete (`conflict_baselines: ["base_version"]`) | `page_update_executor` (storage only; Markdown refused at validation, M3 PD-09) | one round: current page; conflict text only (`confluence.rs:285`: "The agent's base body … and its diff are M7") | `stale::PAGE_UPDATE` | `generic::write_preview` | Markdown, stage-2 base body, diffs, lossy check (T15) |
| `confluence.page.move` | complete (`parent` is "the change itself") | **`LATER_WRITE`** | — | — (spec: version unchanged) | fallback | everything (T17) |
| `confluence.comment.add` | complete | **`LATER_WRITE`** | — | none | fallback | everything (T18) |
| `confluence.label.add`, `confluence.label.remove` | complete (`AgentLabels` receipt; remove `{[204], Empty}`) | **`LATER_WRITE`** | — | none | fallback | executors and cards (T19) |
| `confluence.attachment.upload` | complete (`upload_max_bytes` 10 MiB; registry comment says `replace` is a **PUT**, the spec says **POST** `…/{attachmentId}/data`) | **`LATER_WRITE`** | — | — (spec: replace = attachment version unchanged) | fallback | everything; the last write lands here and flips `WRITES_STILL_LATER` (T20) |

**Already built, only re-used (do not redo):**
- The CQL rewrite and its unit tests (`ops/confluence.rs::effective_cql`, `tests/op_table.rs::cql_*`, incl. `A OR B` precedence at `op_table.rs:600-605`), the removal and count of search results without `content` (`engine/read.rs::result_body`).
- `confluence.page.update`: `version.number = base_version + 1` (`page_update_sends_base_plus_one`), the conflict hold (`i06_page_update_conflict_not_approvable`), `stale::PAGE_UPDATE`, `VersionConflict` on 409 and on a 400 whose text names a version conflict (`atlassian/src/client/write.rs::is_version_conflict`, `writes.rs::page_update_version_conflict_returns_to_queue`), crash reconciliation (`reconcile.rs::i26_crash_after_stale_check_fetch_is_outcome_unknown_confluence_update`), the base-URL change (`identity.rs::i32_base_url_change_restales_pending_update`).
- Identity: the Confluence re-check judge (`identity.rs::judge_confluence`: `type == "known"` + `userKey`), the connection test (`instances/connection_test.rs::confluence_identity`, the applinks manifest, `x10_confluence_below_7_9_refused`, `confluence_manifest_not_json_is_version_unknown`), the pre-write identity call for Confluence writes (`engine/write.rs::identity_call`), `i28_confluence_stale_identity_failure_sets_needs_token`.
- Redaction: the canonical match form on a `confluence.search`-shaped fixture (`redact.rs::u28_falcon_mueller_canonical_match`).
- Pagination under the context path at the client level (`atlassian/tests/pagination.rs::u04_pagination_stays_under_context_path`).
- `payloads::read_fetched(.., user_resolutions)` and `payloads::script_call(.., user_resolutions)` already take the map (`payloads.rs:727`, `:983`); `engine/cache.rs` documents that a rebuild reads only the committed map.
- Similarity `Create` for `confluence.page.create` over `(space, parent, title)` (`similarity.rs:111-118`).
- The 10 MiB upload cap at validation (`validate/caps.rs`), the CLI's `--content-base64-file` raw-bytes reading (`cli/src/binding.rs:113`), `--format`, `--body-file`.
- `MockDc` Confluence fixtures (`CONFLUENCE_PAGE` id `65537`, `CONFLUENCE_SEARCH_PAGE`, `CONFLUENCE_PAGE_UPDATED`, `CONFLUENCE_VERSION_CONFLICT_409/400`, `CONFLUENCE_ERROR_400`, `confluence_space_page(..)` with the origin-relative `_links.next`), `Harness::confluence()` (context path `/wiki`), `Harness::both()`.
- **M5 final review M-5 / L104 is already closed in code:** `send_one` refuses `Target::Approved` (`atlassian/src/client/send.rs:226-231`, test `send_one_refuses_an_approved_write`). Task 21 only re-checks it and the lead closes L104 in the ledger.
- The edit form is generic over the params schema (`engine/write.rs::edit_form`): Confluence writes get one, with `id`/`space`/`content_id`/`label` and `base_version` read-only (target params and conflict baselines). Tasks 15–20 only assert it and add the `content_base64` rule (PD-110).

---

## Global Constraints

The master plan's "Global Constraints" apply verbatim; read them once before Task 1. The subset M7 touches most:

- **Dependency rule (§2.2, `node ci/check-workspace.mjs`):** `convert` depends on no workspace crate; its external allowlist grows from `["pulldown-cmark"]` to `["pulldown-cmark", "quick-xml", "htmd"]` (Task 1); never `reqwest`, never I/O. `preview` gains no dependency. `core` keeps its exact six edges; `atlassian` stays a leaf.
- **Audit-before-effect (§5.1 inv. 1):** every new GET runs under an `AuditCover` minted only after its covering record committed (`REQUEST_RECEIVED` for request GETs) and each response is recorded: enrichment and resolution stages (`PREVIEW_FETCH {purpose: enrich|resolve}`), user lookups during a read (`PREVIEW_FETCH {purpose: resolve}`, §7.6), the RF-5a identity GET (`PREVIEW_FETCH {purpose: identity}`, PD-93), stale checks, the historical base-body fetch (`PREVIEW_FETCH {purpose: enrich}`). `i19_every_hit_is_covered` is extended in Task 22.
- **Method guard (§5.1 inv. 3):** enrichment, resolution, stale checks and the identity GET are GET-only; `confluence.label.remove` is the only DELETE and is sent only as an approved write; every write is exactly one HTTP request (L13), the multipart upload included.
- **Opacity (§4.5):** before a decision only `pending`; no resolution result, collision, duplicate title, conflict text, lossy count or user lookup reaches an envelope, `details` or progress notification except through a deny hint the user chose.
- **Static validation (§2.3):** the placeholder check, the conversion and the storage hard check depend only on the params; nothing fetched influences pass/fail or error text. The user cache is display-only for previews and never feeds validation.
- **Determinism:** executors stay pure functions of `(params, verdict)` (`WRITE_APPROVED` hashes their output; `tests/op_table.rs::executors_deterministic`), including the multipart body and its boundary (PD-109). A read candidate is a pure function of the committed `READ_FETCHED` payload and the validated params (the cache contract, `engine/cache.rs:12-19`).
- **Text rules:** every Atlassian- or agent-derived string that reaches a preview, a Caution, a deny hint `message` or a dialog goes through `preview::invisible::escape_for_display`; preview HTML always passes `preview::sanitize_html`; links render as text, images only as `data:image/{png,jpeg,gif,webp};base64` (§6.4); server-rendered `body.view` HTML goes through the same sanitizer and is labelled a secondary view.
- **Lints and panics:** `clippy -D warnings`; `unwrap_used`/`expect_used` are errors in `core`, `atlassian`, `convert` (existing); `node ci/check-no-panic-macros.mjs` already scans `convert/src`.
- **Secrets and logs:** no CQL, params, titles, bodies, usernames, user keys, filenames or Atlassian error text in any `tracing` line; new diag events carry constants and ids only.
- **Fixed strings** are copied verbatim from the spec section that defines them, each constant with a `/// §x.y (verbatim)` doc comment; plan texts carry `/// plan text (PD-xx)`.
- **Tests:** integration tests in `crates/<crate>/tests/`; each file starts with `type TestResult = Result<(), Box<dyn std::error::Error>>;`; async tests `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]`; core tests run with `--features atlas-duck-atlassian/testing,atlas-duck-core/testing`; OS-only tests are `#[cfg]` modules, never runtime skips; `#[ignore]` reasons are a `const IGNORE: &str` naming the CI step or "manual live run".
- **Commits:** one commit per task (more where a task says so), message `<type>(<scope>): <summary>`, trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (Opus tasks `Claude Opus 5.5`, Haiku tasks `Claude Haiku 5.5`); explicit pathspecs (never `git add -A`); every cargo command uses `--locked` after Task 1's one unlocked build.

---

## Dependency pins

Existing pins are reused. Task 1 verifies the new pin with the crates.io API (`/api/v1/crates/<name>` and `/api/v1/crates/<name>/<version>/dependencies`, read with WebFetch; no download); a version must be at least 14 days old.

| Crate | Pin | Features | Added by | Used in | Why |
|---|---|---|---|---|---|
| `quick-xml` | `=0.42.0` (already in `Cargo.lock` via `plist`; master plan Tech Stack) | the feature that provides HTML5 named-entity resolution (`escape-html` in the 0.3x/0.4x line: Task 1 confirms the name and the function `quick_xml::escape::resolve_html5_entity` on docs.rs for 0.42.0), `default-features = false` otherwise | T01 | convert (storage parser) | §7.6 "parse with `quick-xml` with an HTML named-entity resolver" |
| `htmd` | the version whose `html5ever` matches one already in `Cargo.lock` (`0.39.0` via `dom_query`, `0.40.1` via `ammonia`), if one exists (lead ruling Q6; `=0.5.5` is only the master-plan placeholder; Task 1 checks publish date, license and the normal-dependency tree) | default | T01 | convert (remaining HTML → Markdown; also the CDATA-first fallback, whose HTML parse is `htmd`'s own `html5ever`, PD-94) | §7.6 "remaining HTML → Markdown via `htmd`", "html5ever-based conversion" |
| `pulldown-cmark` | `=0.13.4` (existing, `default-features = false`) | unchanged (no `html` feature, PD-94) | — | convert (md→storage, placeholder check with `into_offset_iter()`, md→preview-HTML) | §7.6 |
| `ammonia` | `=4.2.3` (existing) | — | — | preview (sanitizing every Confluence HTML) | §6.4 |
| `proptest` | `=1.11.0` (existing, dev) | — | T06 | convert (storage fuzz) | §13 U-24 "golden and fuzz tests" |
| `jsonschema`, `wiremock` | existing (dev) | — | T22 | core X-09 | |

`html5ever` is **not** added to `convert` directly: `ammonia` already brings `html5ever 0.40.1`, and the fallback runs through `htmd` (PD-94). After adding the pins, `cargo tree -p atlas-duck-convert -e normal --locked` must list only `pulldown-cmark`, `quick-xml`, `htmd` and their own dependencies; Task 1 stops and reports to the lead on anything network- or I/O-related or on a build script that downloads. **Lead ruling Q6:** pin the `htmd` version whose `html5ever`/`markup5ever` requirement is already satisfied by a copy in `Cargo.lock`, if one exists; otherwise a third copy is accepted only if the CI `supply-chain` job (`cargo deny --locked check`) passes with no new entry in `deny.toml`'s `ignore`, `skip` or `skip-tree` lists (`multiple-versions = "warn"` today), and the Task 1 report records the compile-time cost (the extra crates and the clean-build time of `atlas-duck-convert`). No in-house HTML→Markdown converter. `cargo deny check` and `cargo audit` run in CI (`supply-chain`), not locally.

**No new test-only feature.** The storage-side converter fault (U-24, "an unescaped `ri:user`") is injected in `core` under the existing `testing` feature (`TestHooks::converter_fault`, M5 PD-64), which gains the variants `RiUser`, `IncludeMacro`, `AcLink`; `convert` stays feature-free. The feature-leak check keeps its M4 pattern unchanged.

---

## Plan decisions and contract deltas

Tagged **(spec silent)** where the spec does not say; **(spec gap → ledger)** where the lead adds a ledger entry and, where named, a spec line before the task merges; **Δ C.x** = master-plan contract change the lead applies before Task 1. PD numbering continues after M6 (PD-66..PD-92).

**Contract deltas (applied before Task 1):**
- **Δ1 C.5 `convert` (Confluence half), names fixed.** Keeps the C.5 signatures `storage_to_markdown(storage: &str, users: &UserResolutions) -> (String, ConversionReport, UserResolutions)`, `markdown_to_storage(md: &str) -> (String, EmittedConstructs)`, `hard_check_storage(s: &str, e: &EmittedConstructs) -> Result<(), Unrecorded>`, `check_markdown_placeholders(md: &str) -> Result<(), Vec<PlaceholderHit>>`, `lossy_update(current_storage: &str, outgoing_storage: &str) -> LostCounts`, and fixes the types: `pub type UserResolutions = BTreeMap<String /* user key */, Option<String> /* username */>`; `pub struct ConversionReport { pub lossy: bool, pub lost: LostCounts, pub unknown_macros: Vec<String> /* names, document order, deduplicated */, pub unresolved_users: u64, pub fallback: bool /* XML parse failed, CDATA-first fallback ran */ }`; `pub struct LostCounts { pub macros: u64, pub images: u64, pub links: u64, pub layouts: u64 }` (serde field names = `meta.conversion.lost`, §4.2); `pub struct PlaceholderHit { pub kind: PlaceholderKind /* Link | Image | Macro | User, serde snake_case */, pub count: u64 }`. `ContainerKind` gains `CodeMacro` (the converter's `<ac:structured-macro ac:name="code">` with its CDATA body; `byte_range` from `<ac:structured-macro` through `</ac:structured-macro>`); `ConstructKind` gains `Link` (`ac:link`, `ri:page`, `ri:space`, `ri:content-entity`) and `Markup` (any element the converter never emits, PD-97). Additive functions: `pub fn storage_user_refs(storage: &str) -> StorageUsers` (`StorageUsers { pub keys: BTreeSet<String>, pub usernames: BTreeSet<String> }`, the `ri:user` references by `ri:userkey` and legacy `ri:username`; core resolves the keys before converting), `pub fn storage_constructs(storage: &str) -> WikiConstructs` (the same inventory type the Jira previews use: macros, mentions, includes, links, images, attachments), `pub fn storage_lines(storage: &str) -> Vec<&str>` (the raw-diff projection; concatenation equals the input, PD-104), `pub fn markdown_to_preview_html(md: &str) -> String` (PD-94). All pure, deterministic, no panics, no I/O.
- **Δ2 C.6 `preview` additions.** `PreviewBody` gains `ConfluencePage { title: String, space: String, version: Option<u64>, ancestors: Vec<String>, format: String /* "markdown" | "storage" | "view" */, body_html: String /* sanitized */, conversion: Option<ConversionFacts> }`, `ConfluenceComments { comments: Vec<ConfluenceComment>, count: Option<ItemCount> }` (`ConfluenceComment { id, author: Option<String>, created: Option<String>, location: Option<String> /* "inline" | "footer" as sent */, depth: u32, parent_id: Option<String>, body_html: String }`), `ContentWrite { sentence: String, rows: Vec<(String, String)>, body_html: Option<String>, constructs: Option<ConstructList>, requests: Vec<RequestView> }` (page create, comment add), `PageMove { page: String, from_path: Vec<String>, to_path: Vec<String>, requests: Vec<RequestView> }`, `AttachmentUpload { filename: String, size: u64, mime: String, sha256: String, thumbnail_data_uri: Option<String>, replaces_version: Option<u64>, existing: Option<String> /* "attachment already exists" facts for the collision hold */, comment: Option<String>, requests: Vec<RequestView> }`; `ConversionFacts { lossy: bool, macros: u64, images: u64, links: u64, layouts: u64, unresolved_users: u64, fallback: bool }`. `PreviewBody::Conflict` gains `intended: Vec<DiffLine>` (the agent's intended change: base → outgoing) and `requests: Vec<RequestView>` (M6 T10 review M-5; Jira fills `requests` from its write view and leaves `intended` empty, since its card already lists the differing `expected` fields: the Jira half of M-5 is recorded as a residual, not built). `WarningId` gains `DuplicateTitle` (Caution, PD-105). Every string display-escaped by core; every write body keeps its `requests` (§5.1 inv. 4). `PREVIEW_BUILDER_VERSION` becomes `pb2;render3;icu-17.0;emoji-17.0` with a new `RENDER_VERSIONS` entry (Task 8).
- **Δ3 C.7 `core` read shapes and resolution.** `engine::read::ReadShape` gains `ConfluenceBody { format: BodyFormat /* Markdown | Storage | View */, historical: bool }` (decided from the op id and the validated params alone, like `IssueWithComments`); `read::normalize` reads `payload["user_resolutions"]` for that shape and never the live cache. `ops::ReadView` gains `conversion: Option<ConversionReport>`; `release_meta` adds `meta.conversion = {lossy, lost}` (§4.2) for a released Markdown body. New `core::metadata::UserCache` (per instance, `user key → Option<username>`, PD-99). `EnrichPurpose` gains `Identity` (`as_str() == "identity"`, RF-5a, PD-93). `WriteSummaryFacts` gains `pub confluence: Option<ConfluenceFacts>` (`ConfluenceFacts { space_key, space_name, page: Option<PageRef>, parent: Option<PageRef>, from_path: Vec<String>, to_path: Vec<String>, container_type: Option<String>, existing_attachment: Option<ExistingAttachment>, duplicate_title: bool, current_labels: Vec<String> }`, `PageRef { id, title }`, `ExistingAttachment { id, version: u64, size: Option<u64> }`, all raw server text with redacting `Debug`). `testing::ConverterFault` gains `RiUser`, `IncludeMacro`, `AcLink`.
- **Δ4 C.1 registry data corrections (no new op).** (a) `parent` of `confluence.page.create` and `confluence.page.move` accepts a page id or a page title (schema: `{"type":"string","minLength":1,"maxLength":255}`, description "Parent page id or title (same space)") (lead ruling Q2: id or title; a title matching more than one page is the I-35 ambiguous case); (b) `Projection` gains `FirstResultFields(&'static [&'static str])` (the projection of `results[0]` when the answer is `{"results":[…]}`, else of the object itself) for `confluence.attachment.upload` (V06 confirms the answer shape live); (c) `confluence.search` `result_example`, `result_example_sparse`, `result_schema` and `redaction_rules.url_fields` follow the §7.4 release list (PD-101); (d) the registry comment on `ATTACHMENT_UPLOAD` says `POST …/{attachmentId}/data` (the spec), not PUT; (e) `describe` gains three Confluence texts (PD-112).
- **Δ5 §8.3 `PREVIEW_FETCH.purpose` += `identity`** (spec gap → ledger, RF-5a). No new event type.
- **Δ6 dropped** (lead ruling Q9): no `GateState::StoreFailed` in M7; the M6 T22 item stays deferred.

**Plan decisions:**
- **PD-93 RF-5a: Confluence reads under the anonymous fallback (master plan RF-5; lead ruling Q1 = option A → ledger).** Every direct Confluence read ends its fetch with one identity GET `GET /rest/api/user/current` under the request's cover, after its last content page and after its user lookups (PD-99), before `READ_FETCHED`; recorded `PREVIEW_FETCH {purpose: identity, …}` (Δ5). An answer that is not an identity match (`type != "known"`, or another `userKey`) is handled exactly like a failed Jira header check: the content bytes are audit-only (`READ_FETCHED {unavailable: identity_check}`), the M3 `identity::recheck` runs (`SYSTEM_FETCH {purpose: token_recheck}`, coalesced per instance epoch), and `identity::effect(Path::DirectRead, Trigger::HeaderCheck, ..)` decides: token failure → `READ_FAILED needs_token`, exit 9; an identity match on the re-check (a race) → `upstream_unavailable`, exit 6, `retryable: true`; a rename → one re-fetch; inconclusive → `upstream_unavailable`. An identity GET answered by a 3xx, a non-JSON 2xx or a non-JSON 401 is `upstream_unavailable` decided from status and headers (direct, exit 6); a JSON 401 triggers the re-check (`Trigger::Json401`). A body-decided failure of the identity GET (truncated JSON) is gated like every body-decided read failure (outcome item, §7.2). The identity GET also runs when the content answer is a JSON 4xx/5xx that would become an upstream-error card (that card is server content attributed to the user); it does not run when the read already ended directly (a status/header-decided answer, a connection failure, a confirmed token failure). *Why after the fetch:* a revoked or expired PAT does not become valid again, so a known identity *after* the last page proves the pages were fetched as the user; a check before the fetch leaves the revocation window open. *Cost:* one extra GET per Confluence read (through the 4-request limiter, inside the 120 s read budget). Writes keep the §5.4 step 5 pre-write identity call (unchanged). Script host calls get the same step in M8 (handoff). *Rejected alternatives:* (B) a documented §10.2 residual until V25 is answered; (C) a Jira-style per-response header check, which stays possible later only if the live V25 run shows Confluence DC sends `X-AUSERNAME` (or an equivalent) on content responses (a new lead decision then).
- **PD-94 Converter structure and dependencies (spec silent on the mechanics).** The storage parser (`convert::storage`) wraps the fragment in `<root xmlns:ac=… xmlns:ri=…>` and reads it with `quick-xml`, resolving HTML5 named entities (`&nbsp;`, `&uuml;`, …) and numeric references; it is the single parser behind `storage_user_refs`, `storage_constructs`, `hard_check_storage`, `lossy_update` and `storage_to_markdown`. `storage_to_markdown` handles `ac:`/`ri:` constructs itself and hands each run of plain HTML to `htmd`; when the XML parse fails it runs the §7.6 fallback: CDATA bodies are extracted first (each becomes a fenced code block), then the remaining text goes through `htmd` (whose parser is `html5ever`), `ConversionReport.fallback = true`, `lossy = true`. **Markdown → preview HTML** is an in-house renderer over the `pulldown-cmark` event stream (`markdown_to_preview_html`, like M5's `wiki_to_preview_html`: semantic elements only, links as text `text (url)`, images as text `[image: src]`, raw HTML as escaped text), so the `html` feature stays off and the Confluence preview never trusts converter output as markup; core always passes it through `preview::sanitize_html`.
- **PD-95 storage → Markdown mapping (§7.6; details spec silent → ledger).** `ac:structured-macro` → `[macro: <name> {<k>=<v>, …}]` (parameters sorted by key, values with `,`, `}`, `]`, `\` backslash-escaped; a rich-text body is converted and inlined after the placeholder on its own lines; `ac:plain-text-body` CDATA → a fenced code block, language from the `language` parameter when it matches `[A-Za-z0-9+#-]{1,32}`); the `code` and `noformat` macros → fenced code without a placeholder (counted neither lossy nor lost); `ac:link` + `ri:page` → `[<link body or title>](confluence:<space key or the page's own space>/<title, percent-encoded>)`; `ac:link` + `ri:attachment` → `[<file>](confluence:attachment/<file, percent-encoded>)`; `ac:image` + `ri:attachment` → `![<file>](confluence:attachment/<file>)`; `ac:image` + `ri:url` → `![image](confluence:url/<percent-encoded url>)` (plan text); `ri:user` → `@<username>` (from `ri:username` or the map), `@user:<key>` when the map holds `null` (key percent-encoded outside `[A-Za-z0-9._-]`); `ac:task-list`/`ac:task` → `- [ ] ` / `- [x] `; `ac:layout` → its cells' content in document order separated by blank lines (each layout counts in `lost.layouts`); `ac:emoticon` and every other `ac:`/`ri:` element → `[macro: <local-name> {}]` (counted in `lost.macros`, listed in `unknown_macros`). `lossy = lost` is non-zero or `fallback`. **Look-alike escaping:** source text that would match a placeholder (`[macro:` anywhere, `@user:` anywhere, `confluence:` at a link target) is emitted backslash-escaped (`\[macro:`, `\@user:`), and a genuine `<a href="confluence:…">` becomes escaped text, so genuine prose round-trips through the placeholder check (U-25). Known macros (no `unknown_macros` entry): `code`, `noformat`, `info`, `note`, `warning`, `tip`, `panel`, `expand`, `toc`, `status`, `anchor`, `excerpt`, `children`, `jira` (plan text; list in one const; provisional per lead ruling Q11: the Task 3 reviewer must challenge it).
- **PD-96 Markdown → storage mapping (§7.6; details spec silent → ledger).** Headings `<h1>`–`<h6>`, paragraphs `<p>`, `<em>`, `<strong>`, strikethrough `<s>` (V04 probe), `<ul>/<ol>/<li>`, tables `<table><tbody><tr><th>/<td>`, `<blockquote>`, `<hr/>`, hard break `<br/>`; inline code → `<code>` with XML-escaped text; fenced/indented code → `<ac:structured-macro ac:name="code">[<ac:parameter ac:name="language">lang</ac:parameter>]<ac:plain-text-body><![CDATA[…]]></ac:plain-text-body></ac:structured-macro>` with every `]]>` split as `]]]]><![CDATA[>` (§7.6), recorded in `EmittedConstructs` (`CodeMacro`); links → `<a href="…">text</a>` only for `http`, `https` and `mailto` destinations (attribute-escaped), any other destination (incl. `javascript:`) → the text followed by ` (<destination>)` as escaped text; Markdown images → links (never `ac:image`, like M5 PD-44); task-list items → plain list items with the literal `[ ] `/`[x] ` text (the converter emits no `ac:task`); raw HTML (inline and block) → escaped text; `@name` → text. Output escapes only `&`, `<`, `>`, `"` (attribute values) and uses numeric references for nothing else (storage is XHTML; no named HTML entities are emitted). Deterministic; ends without a trailing newline.
- **PD-97 Storage hard-check strictness (§7.6; spec gap → ledger, like M5 PD-44).** `hard_check_storage` re-parses the output with the PD-94 parser and fails on (a) any `ac:`/`ri:` element outside a recorded `CodeMacro` range (kinds: `ri:user` → `Mention`, an `include`/`excerpt-include` macro → `Include`, `ac:image` → `Image`, `ri:attachment` → `Attachment`, `ac:link`/`ri:page`/`ri:space` → `Link`, any other → `Macro`), (b) any element outside the converter's own element set (`Markup`: e.g. `<img>`, `<script>`, `<iframe>`, `<style>`, `<object>`), (c) an `<a>` whose `href` scheme is not `http`, `https` or `mailto` (`Link`), (d) a recorded code macro whose CDATA does not close where the record says. The error names the first failing kind and its count, never text or offsets.
- **PD-98 Placeholder grammar (§7.6; exact grammar spec silent → ledger).** On the `pulldown-cmark` event stream with `into_offset_iter()`: (1) a link or image destination whose scheme is `confluence:` (ASCII case-insensitive, after the parser's own unescaping) → `link`/`image`; (2) a Text event whose **source span** contains `[macro: ` + a name `[A-Za-z0-9_.-]{1,64}` + ` {` … `}]` on one line → `macro`; (3) a Text event whose source span contains `@user:` followed by at least one character of `[A-Za-z0-9._%-]` → `user`. Code spans and code blocks are never hits (their events are `Code`/`Text`-inside-code, skipped). A backslash-escaped form never matches because the source span keeps the backslash. Hits are counted per kind; `details.placeholders` lists only kinds with `count > 0`, in the order link, image, macro, user. Hint (verbatim §7.6): "fetch with `--format storage` and submit `body_format=storage`".
- **PD-99 User resolution (§7.6; the fetch policy is spec silent → ledger).** For `ReadShape::ConfluenceBody { format: Markdown, .. }` only. After the content page(s) answered 2xx JSON, core computes `storage_user_refs` of the body; each key not in the per-instance `UserCache` (`metadata::UserCache`: `user key → Option<username>`, TTL 1 h counted from the answer, at most 10 000 entries, LRU) is looked up with `GET /rest/api/user?key=<key>` under the request cover, recorded `PREVIEW_FETCH {purpose: resolve, method, path, status, full response}`; at most **50** fresh lookups per read (beyond → `null`, Info `unresolved_mention`); lookups share the instance limiter (max 4 concurrent), the read's `FetchControl` (a cancel records `PREVIEW_FETCH {cancelled_in_flight}` for the lookup in flight, before `CANCELLED`) and the read's 120 s budget; a lookup that is not a parsed 2xx JSON with a `username` → `null` (display only; never fails the read; a JSON 401 does not trigger a re-check here: the RF-5a identity GET that follows is the identity step). The map (cache hits included, every key of the body) is committed in `READ_FETCHED.user_resolutions`; `normalize` converts with the committed map only, so cache changes after the fetch never change a candidate (§5.2, I-37). The same pass runs on the script host-call path (`engine/script.rs`), committing the map in `SCRIPT_CALL` (exercised with the M3 fake runner here; the real runner is M8). `format=storage|view` and `confluence.comment.list` resolve nothing. Write previews render mentions as `@user:<key>` / `@<username>` from the body as sent, with no lookup (no extra enrichment GET).
- **PD-100 `format` on `page.get` and `page.history` (§7.4; view expand and history rule spec silent → ledger).** `markdown` (default): the request expands `body.storage,version,space,ancestors`; the released result replaces `body` with `{"format": "markdown", "value": <Markdown>}` (§4.2), and `meta.conversion = {lossy, lost}` is released with it. `storage`: unchanged. `view`: the request expands `body.view,version,space,ancestors` instead of `body.storage`; Caution `server_rendered_view` (§6.2 verbatim "server-rendered view: macros may include content from other pages"); the preview shows the sanitized server HTML labelled "server-rendered view (secondary)" (plan text). `page.history` without `version` returns the history summary and ignores `format` (no body; `ops describe` says so); with `version` the same three formats apply to the historical body (`expand=body.storage,version` or `body.view,version`).
- **PD-101 `confluence.search` release list (lead ruling Q7: prune; §7.4: "releases `totalSize` and per result `content.id`, `content.type`, `title`, `resultGlobalContainer.title`, `url`, `lastModified`, `excerpt?`").** Normalization keeps only those per-result keys (and `start`, `limit`, `size`, `totalSize`, `_links` at the top level, so paging metadata stays as sent); results without a `content` object are still removed and counted (existing). The registry example, schema and `url_fields` follow (Δ4 c). Deterministic in the payload, so rebuilds agree.
- **PD-102 `cql_broad` (§6.2 Info "CQL may enumerate many results"; trigger spec silent → ledger).** Raised when the agent's CQL (before the rewrite) names none of the fields `space`, `ancestor`, `parent`, `id`, `content`, `title`, `label`, `creator`, `contributor` as a word directly before an operator (tokens of the existing CQL tokenizer, case-insensitive). Info only. Provisional per lead ruling Q11: the Task 12 reviewer must challenge the trigger.
- **PD-103 Comments (§6.3 "Threaded list with author, date, inline/footer badge"; release form spec silent, lead ruling Q5: storage → ledger).** `confluence.comment.list` releases storage bodies verbatim (no conversion, no user resolution). The preview renders each body locally (`storage_to_markdown` with an empty map → `markdown_to_preview_html` → `sanitize_html`), threads by the last entry of `ancestors` (the parent comment), and shows `extensions.location` when the answer carries it, else "location not reported" (plan text; the live V04 probe tells whether `depth=all` answers include it without an extra `expand`).
- **PD-104 `page.update` (§5.4 step 2, §6.3 Edit/update and Conflict, §7.6 lossy; staged shape → ledger).** Staged enrichment (M5 Δ3): stage 1 `GET /rest/api/content/{id}?expand=body.storage,version,space,ancestors` (enrich); when `version.number == base_version`: judge; else stage 2 `GET /rest/api/content/{id}?version=<base_version>&status=historical&expand=body.storage` (enrich) → `Hold::Conflict` with the Caution "conflict: page changed since the agent read it (v<base> → v<current>)" (§6.2 verbatim), a diff base → current (raw and rendered) and the agent's intended change base → outgoing (`Conflict.intended`). A stage-2 failure follows the M3 enrichment classification table (an upstream error → "enrichment failed"; Approve disabled either way). Body: Markdown → storage (Task 9) or storage verbatim; title kept unless given; `version.number = base_version + 1` (existing). Diffs (`EditDiff`): rendered = `storage_to_markdown(current)` vs `storage_to_markdown(outgoing)` (empty map: mentions as keys on both sides), raw = `line_diff` over `storage_lines` of both; `raw_only_changes = max(0, hunks(raw) − hunks(rendered))` (single field; the M5 PD-51 invisible-change refinements are not ported, the raw view shows every byte; L90 residual applies) → Caution `raw_only_diff`. **Lossy (Markdown only):** `lossy_update(current, outgoing)` > 0 in any kind → Caution `lossy_update` with the §6.2 text "this update will remove N macros / M images / K links", plus ", L layouts" when `layouts > 0` (lead ruling Q10, §6.2 amendment); Approve stays enabled. `enrich_keys` stay `["body", "title"]`.
- **PD-105 `page.create` (§5.4 step 2 "duplicate-title check, parent resolution", §6.3 Create; rules spec silent → ledger).** Stage 1 `GET /rest/api/space/{space}` (resolve): 404 → `UnresolvedName {param: space, matches: 0}` ("no space '<v>'"). Stage 2, only with `parent`: an all-digit value → `GET /rest/api/content/{parent}?expand=space,ancestors` (resolve) must be a `page` in `space` (else unresolved, "no page '<v>' in space <KEY>"); any other value → `GET /rest/api/content?spaceKey=<space>&title=<v>&type=page&expand=ancestors&limit=2` (resolve): 0 → no match, ≥ 2 → ambiguous (candidates = the titles, ≤ 10): the I-35 ambiguous case (lead ruling Q2). Stage 3 `GET /rest/api/content?spaceKey=<space>&title=<title>&type=page&limit=1` (enrich): a hit → Caution `duplicate_title` "a page titled '<title>' already exists in <space>" (plan text; new `WarningId`, §6.2 amendment); Approve stays enabled (lead ruling Q3; Confluence refuses the create itself, `WRITE_FAILED`). Body `{"type":"page","title":…,"space":{"key":<resolved key>},"ancestors":[{"id":<resolved parent id>}] (only with parent),"body":{"storage":{"value":…,"representation":"storage"}}}`. `enrich_keys`: `["title", "body"]` (space and parent are target params, read-only, L06). Card: `ContentWrite` "Create page '<title>' in <space name> (<KEY>) under '<parent title>'" with the rendered body and the construct list.
- **PD-106 `page.move` (§7.4 "same space only; keeps title/body"; body shape spec silent, lead ruling Q4).** Stage 1 `GET /rest/api/content/{id}?expand=version,space,ancestors` (enrich); stage 2 parent resolution as PD-105 within the page's own space (a parent in another space is unresolved: "no page '<v>' in space <KEY>"; cross-space moves are a non-goal); a parent that is the page itself or has the page among its `ancestors` → `Hold::EnrichmentError` with the app text "a page cannot be moved under itself or one of its descendants" (plan text; plain deny only). Body `{"id","type":"page","title":<current title>,"version":{"number":<current + 1>},"ancestors":[{"id":<resolved parent id>}]}` — **no body** (lead ruling Q4; the live probe `v_page_move_keeps_body` (Task 25) decides, recorded as a §15 V-item the lead adds; if it shows DC needs `body`, the lead changes this to re-send the current storage from stage 1). Stale rule `stale::PAGE_MOVE`: current `version.number` equals the baseline. Card: `PageMove` with the old path (ancestor titles + page) and the new path (parent's ancestor titles + parent + page). `enrich_keys`: `[]` (`id` is the target; an edited `parent` re-runs enrichment: `["parent"]`).
- **PD-107 `comment.add` (§7.4 payload verbatim).** Stage 1 `GET /rest/api/content/{content_id}?expand=space` (enrich): `type` must be `page` or `blogpost` (the container type the body sends), else `EnrichVerdict::unusable()`; with `reply_to`, stage 2 `GET /rest/api/content/{reply_to}?expand=container` (resolve): a `comment` whose `container.id == content_id`, else `UnresolvedName {param: reply_to, matches: 0}` ("no comment <v> on content <id>"). Body (§7.4) `{"type":"comment","container":{"id":…,"type":<page|blogpost>},"ancestors":[{"id":<reply_to>}] (only with reply_to),"body":{"storage":{"value":…,"representation":"storage"}}}`. Card `ContentWrite` with the rendered body and constructs. No stale rule (spec).
- **PD-108 Labels.** `label.add`: `POST /rest/api/content/{id}/label` body `[{"prefix":"global","name":<label>}, …]` in the params' order; enrichment `GET /rest/api/content/{id}?expand=metadata.labels` (enrich) for the card only (title, labels already present); receipt `AgentLabels` (existing). `label.remove`: `DELETE /rest/api/content/{id}/label/{label}`, no body, success `{[204], Empty}` (existing), same enrichment. Cards `WriteSummary` "Add labels <l1>, <l2> to '<title>'" / "Remove label <l> from '<title>'", rows `Already present` / `Not present` (Info-free; plain rows). No stale rule (spec).
- **PD-109 `attachment.upload` (§7.4, §5.4 step 2, §6.3; multipart and replace mechanics spec silent → ledger).** Stage 1 `GET /rest/api/content/{id}/child/attachment?filename=<filename>&expand=version` (enrich). Without `replace`: a hit → `Hold::Collision` (existing hold) with the `AttachmentUpload` card carrying `existing` and the fixed line "attachment already exists" (§7.4 verbatim), Approve disabled, plain deny only (no hint applies); none → the request `POST /rest/api/content/{id}/child/attachment?allowDuplicated=false`. With `replace: true`: exactly one hit → `POST /rest/api/content/{id}/child/attachment/{attachmentId}/data` (spec), baseline `{attachment_id, version}`; none → `UnresolvedName {param: filename, matches: 0}` ("no attachment '<v>' on content <id>"). Stale rule `stale::ATTACHMENT_REPLACE` (replace only): the same attachment id and `version.number` unchanged. **Multipart body (deterministic):** boundary = `atlas-duck-` + the first 32 hex chars of SHA-256(file bytes); if that string occurs in the file bytes, the filename or the comment, append `-1`, `-2`, … until it does not (deterministic); parts: `file` (`Content-Disposition: form-data; name="file"; filename="<filename>"`, `Content-Type` = the sniffed type of PD-110 or `application/octet-stream`) and, when given, `comment` (`text/plain; charset=utf-8`); request `Content-Type: multipart/form-data; boundary=<b>` (so `request_set_hash` covers it). A filename containing `"`, CR, LF or another control character is refused at validation (`validation`, exit 2; executor `Invalid`). Receipt: `Projection::FirstResultFields(RECEIPT_FIELDS)` (Δ4 b).
- **PD-110 Attachment card and edit form (§6.3 "File name, size, MIME type, SHA-256, image thumbnail (local bytes only)").** MIME = sniffed from magic bytes for `png`, `jpeg`, `gif`, `webp`, `pdf`, `zip`; else `application/octet-stream` (the type the part is sent as, shown as such). Thumbnail: only for png/jpeg/gif/webp of at most 2 MiB (the 4 MiB `DOC_MAX_BYTES` render cap), as `data:image/<t>;base64,…` (kept by `sanitize_html`; never SVG); otherwise the text "no thumbnail (not an image, or larger than 2 MiB)" (plan text). "replaces existing attachment vN" (§6.3 verbatim) when `replace`. The edit form shows `content_base64` read-only with value `null` and the label "file content (<n> bytes, SHA-256 <8 hex>…): not editable here; deny and resubmit to change it" (plan text), so a 10 MiB base64 string never enters the preview DTO; Rust adds no new edit rule (a raw-JSON edit of `content_base64` is still re-validated, §5.4 step 4). The MIME rule and the 2 MiB thumbnail cap are provisional per lead ruling Q12: the Task 20 reviewer must challenge them.
- **PD-111 M3 T10 minor 7 (a Confluence 400 whose body read was incomplete).** Accepted and documented: such an answer stays `Failed4xx` → `WRITE_FAILED` (the write was refused; nothing was written), not `VersionConflict`; the user loses only the conflict UX. Test pins it. **Minor 8:** the absence of `_links.next` (presence only, never followed) ends Confluence paging, saving the extra empty page (§7.2 lists it as an end signal).
- **PD-112 `ops describe` texts (§7.4 "`ops describe` documents the rewrite", §7.6 "documents the check", "advises `body_format=storage`").** Three plan-text constants in `registry`: `CONFLUENCE_CQL_GUIDANCE` (search: "The CQL is sent as `(<your CQL>) AND type in (page,blogpost,comment,attachment)` plus your trailing ORDER BY; an ORDER BY elsewhere, an unterminated quote or unbalanced parentheses are rejected."), `CONFLUENCE_PLACEHOLDER_GUIDANCE` (page create/update, comment add: "A Markdown body that still contains `page get` placeholders (`[macro: …]`, `confluence:` links or images, `@user:<key>`) is rejected with `markdown_placeholders`: fetch with `--format storage` and submit `body_format=storage`." — the §12.4 onboarding sentence, verbatim), `CONFLUENCE_LOSSY_GUIDANCE` (page update: "If `page get` reported `meta.conversion.lossy = true`, edit with `body_format=storage`; a Markdown update that would remove macros, images or links is flagged to the approver."). 
- **PD-113 L101 (dropped re-check futures; M5 ledger says "M7 runner contract").** The sandbox runner is M8's; the hazard is in `core::identity::recheck`. Lead ruling Q8: M7 owns it. Task 21 runs each re-check's fetch in its own `tokio::spawn`ed task that owns the start and result records, so a dropped waiter can never leave a `token_recheck` start without its result; waiters await the shared `OnceCell`.
- **PD-114 Confluence list previews.** The M5 `jira_preview::list_preview` table logic moves to `generic::list_table` (items under the registry `items_key`, else an array root; columns = scalar keys of the first 50 items in first-seen order, nested `title`/`key`/`name` flattened one level) and both products call it; single objects keep the JSON tree.

Spec deltas the lead records (ledger entries at the end): PD-93, PD-95, PD-96, PD-97, PD-98, PD-99, PD-100, PD-101, PD-102, PD-103, PD-104 (lossy text), PD-105, PD-106, PD-109, PD-111, PD-113, and Δ5. PD-94, PD-107, PD-108, PD-110, PD-112, PD-114 are plan decisions only.

---

## Review Focus

Five failure modes most likely to bite users of M7's code; each has named tests the reviewer must see pass.

1. **(Tasks 05, 06, 09) Markdown can never produce a macro, `ri:user`, include, `ac:link`/`ac:image` or foreign markup in storage.** An escaping gap in `markdown_to_storage` (a `]]>` in a fenced block, `<` in a link title, an autolink with `javascript:`, raw HTML in a table cell, a CDATA split at a chunk boundary) silently lets an agent's Markdown run a Confluence macro on approval. The hard check must catch what escaping misses, with the same parser the lossy check and storage→Markdown use. Tests `u24_storage_fuzz_reparse_finds_nothing_unrecorded` (proptest ≥ 2 048), `u24_storage_code_body_containers`, `u24_storage_faulty_converter_detected`, `u24_storage_injected_fault_fails_validation_exit2`, `u23_md_to_storage_escapes_raw_html_and_xml_specials`.
2. **(Tasks 03, 04, 06, 09) Placeholders and look-alikes.** A `page get` Markdown body resubmitted as Markdown must be rejected before conversion (exit 2, per-kind counts), while prose that merely looks like a placeholder must escape, pass and round-trip. Tests `u25_placeholders_golden_rejected_with_counts`, `u25_markdown_placeholders_rejected_exit2_counts`, `u25_lookalike_round_trip`, `placeholders_in_code_are_not_hits`.
3. **(Tasks 10, 11) Candidate determinism with user resolution.** The released Markdown must be a pure function of the committed `READ_FETCHED` payload: the rebuild uses the committed map only, a cache change after the fetch never changes the hash, every lookup is covered and recorded. Tests `i37_confluence_markdown_rebuild_from_committed_map`, `i37_user_cache_change_does_not_change_hash`, `resolve_gets_are_preview_fetch_resolve_under_request`, `cancel_during_resolve_records_cancelled_in_flight`.
4. **(Tasks 15, 16, 17, 20) Approvability of Confluence write holds.** A `base_version` conflict, an attachment collision, an unresolved space/parent/reply-to and a move into the own subtree must leave Approve disabled in Rust (`DECISION_INVALID {not_approvable}`, no `WRITE_APPROVED`), individually and in a batch; a duplicate title and a lossy update must not. Tests `i36_page_update_base_behind_is_conflict_not_approvable`, `i36_page_update_409_returns_conflict_not_reapprovable`, `i06_attachment_collision_not_approvable_individual_and_batch`, `i06_page_update_conflict_batch_rejected`, `i35_parent_page_no_match_and_ambiguous`, `duplicate_title_caution_approve_enabled`, `lossy_update_caution_counts`.
5. **(Tasks 13, 21) Anonymous fallback.** A revoked Confluence PAT answered as anonymous must never make a release candidate (reads) or a sent write. Tests `rf5a_confluence_anonymous_read`, `rf5a_paged_read_checked_once_after_last_page`, `confluence_pre_write_identity_anonymous_is_write_stale`, `i23_confluence_stale_rules_recheck_failed_classes`.

Master-plan Review Focus (copied; owners per the master plan):
- **RF-1 Clock/retention** (M2) — not M7.
- **RF-2 Oracle** (M3) — not M7; the new stage, lookup and identity GETs reuse the M3 classification tables unchanged (`rf5a_identity_get_3xx_is_direct_upstream_unavailable`, Task 13; `stage2_historical_3xx_direct`, Task 15).
- **RF-3 Cross-host** (M2/M3/M6) — not M7.
- **RF-4 Crash reconciliation duplicate guard** (M3) — `confluence.page.create` is a `Create` op: the M3 seeding already covers it; Task 16 adds `rf4_page_create_after_crash_is_flagged`.
- **RF-5 Identity/anonymous** (M7 owns (a)): `rf5a_confluence_anonymous_read` (Task 13) pins PD-93 (lead ruling Q1 = A).

---

## §15 items resolved in M7

- **V04** (Confluence comment payload, `child/comment` `depth=all`/location, `?version=N&status=historical`, applinks manifest JSON under `Accept: application/json`, `excerpt=indexed` and `totalSize`, the rewritten CQL form, PUT version-conflict status 409 vs 400) → design: Tasks 12 (search/excerpt), 15 (historical body, 409/400), 18 (comment payload), 03/PD-103 (location); wiremock: their tests; live: Task 25 `v04_*` (manual).
- **V06 (Confluence half)** (declared write success shapes) → wiremock: Task 22 `x09_confluence_every_op_once` asserts each Confluence write's declared shape; live: Task 25 `v06_confluence_write_success_shapes` (incl. the upload answer shape behind Δ4 b and `label.remove` 204).
- **V23 (Confluence half, live)** → Task 25 `v23_confluence_sso_front_classification` (manual); the wiremock design stays M3's.
- **V25 (Confluence half)** → Task 13 (PD-93 design) and Task 25 `v25_confluence_anonymous_fallback_and_header` (manual: whether an invalid/revoked PAT falls back to anonymous, whether `X-AUSERNAME` or an equivalent header is sent on content responses, which would allow PD-93 option C).

---

**Ledger entries M7 depends on (master plan M7 "Ledger"):** L07 (no server-side preview render before approval: no `contentbody/convert` call anywhere, Tasks 12/15/16/18), L12 (`base_version` conflict, T15), L13 (one request per write, multipart included, T20), L17 (direct-read cap/budget outcomes gated: lookups and the identity GET share the read budget, T11/T13), L22 (per-op similarity: `page.create` `Create`, the rest `Target`, unchanged), L25 (post-send enrichment failures gated: every new stage, T15–T20), L29 (pre-write identity call for every new write, T16–T20; RF-5a for reads, T13), L31 (status/header- vs body-decided on stage, lookup and identity GETs, T11/T13/T15). Also touched: L99 (Confluence identity call vs re-check: both require `type == "known"` and the stored `userKey`, `engine/write.rs::identity_call` vs `identity.rs::judge_confluence`; Task 21 asserts they agree and the lead notes Confluence as aligned), L101 (PD-113), L104 (already closed, Task 21 re-checks), L105 M-4 (Task 05), L81 (launch-stub wait: M7 touches no launch path; lead ruling Q14: owner M9).

---

## Traceability (M7 exit criterion → task → test)

Every id in the M7 exit criterion (master plan, M7 entry) and every carried item maps to at least one named test; paths relative to the repo root. "Existing" = green on `master`, kept green, not rewritten.

| Id | What M7 must show | Task | Test(s) (file :: fn) |
|---|---|---|---|
| U-23 (storage half) | golden storage→md incl. CDATA, macros, entities, user mentions; md→storage incl. escaping of raw HTML and XML specials | T03, T05, T07 | `crates/convert/tests/storage_to_md.rs` :: `u23_storage_to_md_golden`, `u23_storage_entities_and_mentions`; `crates/convert/tests/md_to_storage.rs` :: `u23_md_to_storage_golden`, `u23_md_to_storage_escapes_raw_html_and_xml_specials`; `crates/convert/tests/md_preview.rs` :: `md_preview_html_golden` |
| U-24 | storage code bodies golden + fuzz incl. `]]>` in fenced and inline code; re-parse finds nothing unrecorded; injected fault (unescaped `ri:user`) → exit 2, nothing queued | T06, T09 | `crates/convert/tests/hard_check_storage.rs` :: `u24_storage_code_body_containers`, `u24_storage_cdata_split_in_fenced_and_inline_code`, `u24_storage_fuzz_reparse_finds_nothing_unrecorded`, `u24_storage_faulty_converter_detected`; `crates/core/tests/confluence_validate.rs` :: `u24_storage_injected_fault_fails_validation_exit2`; Jira half existing (`hard_check.rs`, `jira_validate.rs`) |
| U-25 | `page get` Markdown with `[macro: toc {}]`, a `confluence:` link, a `confluence:attachment/` image and `@user:<key>` resubmitted as Markdown → exit 2 `markdown_placeholders` + per-kind counts; prose look-alikes escape, pass and round-trip | T04, T06, T09 | `crates/convert/tests/placeholders.rs` :: `u25_placeholders_golden_rejected_with_counts`, `u25_escaped_lookalikes_pass`, `placeholders_in_code_are_not_hits`; `hard_check_storage.rs` :: `u25_lookalike_round_trip`; `confluence_validate.rs` :: `u25_markdown_placeholders_rejected_exit2_counts`, `placeholder_check_runs_before_conversion` |
| U-28 (`confluence.search`) | "Falcon Müller Plan" title mask redacts or drops the `url`, lists it under "also appears in", otherwise release stays blocked | T12 | `crates/core/tests/confluence_reads.rs` :: `u28_confluence_search_mask_reaches_url`; `crates/core/tests/redact.rs` :: `u28_falcon_mueller_canonical_match` (existing, fixture) |
| U-31 | quoted parens/`ORDER BY`, trailing `ORDER BY`, `A OR B` precedence, rejections | T12 | `crates/core/tests/op_table.rs` :: `cql_rewrite_wraps_and_keeps_order_by`, `cql_order_by_inside_parens_or_twice_rejected`, `cql_unterminated_quote_rejected`, `cql_paren_escape_attempt_rejected`, `cql_quoted_parens_and_order_by_are_text` (existing); `confluence_reads.rs` :: `u31_effective_cql_on_the_wire_and_in_preview`, `u31_rejections_exit2_nothing_queued`; `crates/registry/tests/describe.rs` :: `confluence_describe_documents_cql_placeholders_lossy` |
| U-34 (Confluence half) | a plain default `page.get` → zero Caution; `format=view` → exactly one (`server_rendered_view`); Info-only for `unknown_macros`, `unresolved_mention`, `cql_broad`; one level per id | T12, T08 | `confluence_reads.rs` :: `u34_default_page_get_zero_caution`, `u34_view_format_exactly_one_caution`, `u34_confluence_info_warnings_are_info`; `crates/preview/tests/warnings.rs` :: `every_warning_id_has_exactly_one_level` (existing, gains `duplicate_title`) |
| I-06 (conflict, collision) | individual and batch approvals of opened conflict-state `page.update` and attachment-collision items → `DECISION_INVALID {not_approvable}`, nothing decided, no `WRITE_APPROVED` | T15, T20 | `crates/core/tests/confluence_update.rs` :: `i06_page_update_conflict_batch_rejected`; `crates/core/tests/confluence_attachment.rs` :: `i06_attachment_collision_not_approvable_individual_and_batch`; `crates/core/tests/decisions.rs` :: `i06_page_update_conflict_not_approvable` (existing) |
| I-22 (context path) | base `…/wiki`, relative `_links.next` without the context path → page 2 at `/wiki/rest/api/…`, nothing outside; drops keep totals, `returned + items_dropped = fetched`, `next_start` from server arithmetic | T14 | `confluence_reads.rs` :: `i22_confluence_context_path_direct_read`, `i22_confluence_drops_keep_totals_and_next_start`; `crates/atlassian/tests/pagination.rs` :: `u04_pagination_stays_under_context_path` (existing), `links_next_absent_ends_paging` |
| I-26 (`confluence.page.update`; + move, replace) | crash after the stale-check fetch → `outcome_unknown`, exit 6, startup notice | T17, T20 | `crates/core/tests/reconcile.rs` :: `i26_crash_after_stale_check_fetch_is_outcome_unknown_confluence_update` (existing), `i26_crash_after_stale_check_fetch_is_outcome_unknown_confluence_move`, `i26_crash_after_stale_check_fetch_is_outcome_unknown_confluence_replace` |
| I-32 | base-URL change while a `page.update` is pending → `WRITE_STALE {instance_changed}`, re-render under the new origin, nothing at the old origin | T15 | `crates/core/tests/identity.rs` :: `i32_base_url_change_restales_pending_update` (existing, storage); `confluence_update.rs` :: `i32_markdown_update_rerendered_under_new_origin` |
| I-35 (parent page) | no-match and ambiguous parent disable Approve; deny with hint → `resolution_failed`, exit 3, candidates only when ticked | T16, T17 | `crates/core/tests/confluence_create.rs` :: `i35_parent_page_no_match_and_ambiguous`, `i35_parent_page_deny_hint_candidates_only_when_ticked`; `crates/core/tests/confluence_writes.rs` :: `i35_move_parent_no_match_and_ambiguous` |
| I-36 (`page.update`) | base v5 vs mock v6 → conflict, Approve disabled; missing `base_version` → exit 2; mock 409 → back to the queue in the conflict state, not re-approvable; sent `version.number = base_version + 1` | T15 | `confluence_update.rs` :: `i36_page_update_base_behind_is_conflict_not_approvable`, `i36_page_update_conflict_shows_base_to_current_diff`, `i36_page_update_without_base_version_exit2`, `i36_page_update_409_returns_conflict_not_reapprovable`, `i36_sent_version_is_base_plus_one` |
| I-37 (`user_resolutions`) | an evicted Confluence Markdown candidate whose mentions were all cache hits rebuilds to the same hash from the committed map; a cache change between fetch and rebuild does not affect the hash | T11 | `confluence_reads.rs` :: `i37_confluence_markdown_rebuild_from_committed_map`, `i37_user_cache_change_does_not_change_hash` |
| X-09 (Confluence) | every Confluence registry op once against wiremock with the scripted approver, generated from the registry | T22 | `crates/core/tests/x09_confluence.rs` :: `x09_confluence_every_op_once`, `x09_confluence_generator_covers_the_registry`, `x09_confluence_writes_wait_for_approval`, `x09_confluence_reads_hold_their_result_until_released` |
| X-10 (Confluence gates) | floor 7.9 refused; no op hidden on the floor; never a version string | T22 | `crates/core/tests/instances.rs` :: `x10_confluence_below_7_9_refused` (existing); `x09_confluence.rs` :: `x10_confluence_every_op_available_on_floor`, `x10_confluence_no_version_string_in_envelopes` |
| S-12 (Confluence previews) | remote images/scripts neutralized; invisible characters marked; raw-only diff flagged | T07, T12, T15 | `md_preview.rs` :: `s12_md_preview_neutralizes_remote_and_scripts`; `confluence_reads.rs` :: `s12_confluence_page_preview_neutralizes_remote_and_marks_invisible`, `s12_view_format_server_html_sanitized`; `confluence_update.rs` :: `s12_confluence_raw_only_diff_flagged` |
| RF-5a | `user/current {type: anonymous}` + `page.get` 200 → per PD-93 | T13 | `crates/core/tests/confluence_identity.rs` :: `rf5a_confluence_anonymous_read`, `rf5a_paged_read_checked_once_after_last_page`, `rf5a_identity_match_race_is_upstream_unavailable`, `rf5a_identity_get_3xx_is_direct_upstream_unavailable`, `rf5a_user_current_op_anonymous_is_token_failure`, `rf5a_upstream_error_read_is_identity_checked` |
| P-01 (Confluence scenarios) | ~5,000-word page and small `page.update` diff: Rust build + document within the P-01 bound; webview first screen ≤ 1 s (CI) | T23, T24 | `crates/core/tests/perf_sc3.rs` :: `p01_confluence_page_and_update_diff_under_budget`; `app/src-tauri/tests/e2e/flows.rs` :: `p01_first_screen_under_1s` (two scenarios added, CI only) |
| L-01 (Confluence) | env-gated live tests for V04, V06 (Confluence), V23 (Confluence), V25 (Confluence) | T25 | `crates/core/tests/live_confluence.rs` :: `v04_confluence_endpoints_and_cql_rewrite`, `v06_confluence_write_success_shapes`, `v23_confluence_sso_front_classification`, `v25_confluence_anonymous_fallback_and_header`, `v_storage_render_probes`, `v_page_move_keeps_body` (all `#[ignore]`, manual) |
| `confluence_flows` | the real binaries end to end on the Confluence paths (exit-criterion target) | T24 | `app/src-tauri/tests/confluence_flows/flows.rs` :: `confluence_flows_smoke`, `md_page_update_sent_as_storage`, `placeholders_rejected_exit2`, `page_update_conflict_denied_exit3`, `attachment_collision_denied_exit3`, `cql_rewrite_on_the_wire`, `page_get_markdown_released_with_conversion_meta`, `label_remove_204_succeeded` |
| `WRITES_STILL_LATER` flip | no write is `NotInThisBuild` any more; the tripwire is retired as documented | T20 | `crates/core/tests/handler.rs` :: `not_in_this_build_rejected_internal` (flag `false`), `crates/core/tests/op_table.rs` :: `not_in_this_build_writes` (`LATER_WRITES` empty), `u05_only_writes_have_stale_check` (gains `page.move`, `attachment.upload`) |
| U-33 (Confluence completion) | Markdown accepted for Confluence bodies | T09 | `confluence_validate.rs` :: `u33_confluence_markdown_body_format_accepted`; `crates/core/tests/jira_validate.rs` :: `u33_confluence_markdown_still_rejected` → renamed `u33_confluence_markdown_now_accepted` |
| M5 M-4 (L105) | Jira `link_target` encodes a `&` that starts a character reference | T05 | `crates/convert/tests/md_to_wiki.rs` :: `m4_link_target_encodes_character_references` |
| M3 T10 minor 7 | truncated Confluence conflict 400 stays `WRITE_FAILED` (PD-111) | T15 | `crates/atlassian/tests/writes.rs` :: `truncated_conflict_400_is_failed4xx` |
| M3 T10 minor 8 | a `_links` object without `next` ends paging; no `_links` object is no end signal | T14 | `pagination.rs` :: `links_next_absent_ends_paging`, `page_without_links_object_is_no_end_signal` |
| M6 T10 review M-5 | conflict card carries the agent's intended change | T08, T15 | `crates/preview/tests/render.rs` :: `conflict_card_shows_intended_change`; `confluence_update.rs` :: `i36_page_update_conflict_shows_base_to_current_diff` |
| L101 (lead ruling Q8: M7) | a dropped re-check waiter leaves no start without its result | T21 | `crates/core/tests/confluence_identity.rs` :: `l101_dropped_recheck_waiter_leaves_no_orphan_start` |
| L99 / L104 | Confluence identity call and re-check agree; `send_one` refuses an approved target | T21 | `confluence_identity.rs` :: `l99_confluence_identity_call_and_recheck_agree`; `crates/atlassian/src/client/send.rs` :: `send_one_refuses_an_approved_write` (existing) |
| I-19 | every hit (lookups, identity GET, stage GETs, historical body, multipart write) covered and recorded | T22 | `crates/core/tests/audit_coverage.rs` :: `i19_every_hit_is_covered` (existing, flows extended) |

No M7 task exists without a row here except Task 1 (pins, checker rules), Task 2 (the parser the rows' tests run on), Task 8 (the preview model and renderer), Tasks 18/19 (comment and labels: no §13 id of their own; their tests are in the tasks and X-09), Task 26 (dropped, a deferral note only), Task 27 (docs), Task 28 (CI) and Tasks 29/30 (exit run, final review).

---

## File Structure

New and modified files per crate (Create = new file; Modify = existing file).

### Workspace root and CI
- Modify `Cargo.toml` (`quick-xml`, `htmd` pins), `Cargo.lock` (T01).
- Modify `ci/check-workspace.mjs`, `ci/check-workspace.test.mjs` (T01: `CONVERT_EXTERNAL_ALLOW`).
- Modify `.github/workflows/ci.yml` (T28), `ci/cli-flows-linux.sh` only if a flag is needed (it already reads `CLI_FLOWS_TEST`), `.gitlab-ci.yml` (comment only).

### crates/convert
- Modify `Cargo.toml`, `src/lib.rs` (re-exports), `src/md_to_wiki.rs` (T05: M-4), `src/hard_check.rs` (T06: shared `Unrecorded`/`ConstructKind` additions), `src/wiki/mod.rs` (`ConstructKind` gains `Link`, `Markup`, T06).
- Create `src/storage/mod.rs`, `src/storage/parse.rs` (T02), `src/storage/to_md.rs` (T03), `src/placeholders.rs` (T04), `src/md_to_storage.rs`, `src/xml_escape.rs` (T05), `src/storage/hard_check.rs` (T06), `src/storage/lossy.rs`, `src/md_preview.rs` (T07).
- Create tests `tests/storage_parse.rs` (T02), `tests/storage_to_md.rs` (T03), `tests/placeholders.rs` (T04), `tests/md_to_storage.rs` (T05), `tests/hard_check_storage.rs` (T06), `tests/lossy.rs`, `tests/md_preview.rs` (T07); golden files `tests/golden/storage_to_md/*.xml` + `*.md`, `tests/golden/md_to_storage/*.md` + `*.xml`, `tests/golden/md_preview/*.md` + `*.html`, `tests/golden/placeholders/*.md`.

### crates/preview
- Modify `src/model.rs` (Δ2, `render3`), `src/warning.rs` (`DuplicateTitle`), `src/render/body.rs` (arms), `src/lib.rs`; Create golden files `tests/golden/render/confluence_*.html`; Modify tests `tests/render.rs`, `tests/warnings.rs`; Create `tests/model_confluence.rs` (T08).
- Modify `app/ui/public/preview.css` only if a new element needs a rule (then it is in the `render3` digest).

### crates/registry
- Modify `src/confluence/schemas.rs` (Δ4 a, c), `src/confluence/writes.rs` (Δ4 b, d), `src/model.rs` (`Projection::FirstResultFields`), `src/describe.rs`, `src/lib.rs` (PD-112 constants), tests `tests/describe.rs`, `tests/catalog.rs` (T09, T12, T16, T20).

### crates/atlassian
- Modify `src/client/paginate.rs` (T14: `_links.next` end signal); tests `tests/pagination.rs` (T14), `tests/writes.rs` (T15: minor 7 pin).
- Modify `src/testing/fixtures.rs`, `src/testing/mock_dc.rs` (Confluence fixtures as tasks need them: a page with macros/mentions, comments, attachments, `user?key=` answers, a 5,000-word page).

### crates/core
- Create `src/ops/confluence_body.rs` (T09), `src/ops/confluence_preview.rs` (T12, T15–T20), `src/ops/confluence_ext.rs` (T16–T20 executors and rules), `src/users.rs` (T11: `UserCache` and the lookup pass; re-exported under `metadata`).
- Modify `src/ops/mod.rs` (table rows, `ReadView.conversion`, `WriteSummaryFacts.confluence`, `EnrichPurpose::Identity`), `src/ops/confluence.rs` (T10, T12, T15), `src/ops/generic.rs` (T10 format endpoint, T12 `list_table`), `src/ops/jira_preview.rs` (T12: move `list_preview` body to `generic::list_table`), `src/ops/stale.rs` (T17, T20), `src/validate/mod.rs` (T09: `check_body_format`, placeholder check), `src/engine/read.rs` (T10, T11, T13), `src/engine/script.rs` (T11), `src/engine/write.rs` (T20: edit form rule), `src/engine/cache.rs` (only if the rebuild entry needs the shape), `src/identity.rs` (T13 trigger; T21 L101), `src/payloads.rs` (T13 `PreviewFetchPurpose::Identity`), `src/decision/*` (only where a new hold's deny offers need it), `src/testing/{harness,fault,approver}.rs`, `src/core.rs` (user cache start), `src/lib.rs`.
- Create tests `tests/confluence_validate.rs` (T09), `tests/confluence_reads.rs` (T10–T12, T14), `tests/confluence_identity.rs` (T13, T21), `tests/confluence_update.rs` (T15), `tests/confluence_create.rs` (T16), `tests/confluence_writes.rs` (T17–T19), `tests/confluence_attachment.rs` (T20), `tests/x09_confluence.rs` (T22), `tests/live_confluence.rs` (T25), `tests/common/confluence.rs` (T10: shared mounts `mount_page`, `mount_page_view`, `mount_history_version`, `mount_users`, `mount_comments`, `mount_space`, `mount_children`, `mount_attachments`, `mount_title_lookup`, `mount_for_op`); modify `tests/op_table.rs`, `tests/handler.rs`, `tests/reconcile.rs`, `tests/identity.rs` (only if a helper moves), `tests/jira_validate.rs`, `tests/validate.rs`, `tests/perf_sc3.rs`, `tests/audit_coverage.rs`, `tests/common/flows.rs`.

### app/src-tauri
- Create `tests/confluence_flows.rs` (`#![cfg(feature = "scripted-approver")]`, `#[path = "cli_flows/harness.rs"] pub mod harness;`), `tests/confluence_flows/flows.rs` (T24); modify `tests/e2e/flows.rs` (T24: P-01 scenarios), `tests/dto_fixtures.rs` and `app/ui/src/shared/ipc/fixtures/preview.json` (T08).

### docs
- Modify `docs/release/sc3-walkthrough.md`, `docs/release/macos-gui-checklist.md` (T27).

---

## Tasks

Phase A (Tasks 1–8): `convert` and `preview` foundations (pure, no I/O; all tests run locally on Windows). Phase B (Tasks 9–14): validation wiring and the read side. Phase C (Tasks 15–17): the stale-ruled and resolution-heavy writes. Phase D (Tasks 18–21): the remaining writes, the last-write flip, the identity sweep. Phase E (Tasks 22–30): generated catalog test, performance, flows, live tests, docs, CI, exit criterion, final review (Task 26 is dropped and kept as a numbered deferral note).

Shared conventions (every task): run commands from `C:/Code/atlas-duck` with `-j 4`; core test runs use `cargo test -j 4 -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked`; a Confluence harness is `core::testing::Harness::confluence()` (context path `/wiki`) or `Harness::both()`, with `MockDc` fixtures from `atlassian::testing` plus the `tests/common/confluence.rs` mounts (Task 10 creates them; later tasks add helpers there, never duplicate them); writes are decided through `core::testing::ScriptedApprover` (`open` before `approve`/`release`; `approve_unopened` only to prove the refusal).

### Task 1: Pins, `convert` allowlist, checker rules

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:**
- Modify: `Cargo.toml` (`quick-xml = { version = "=0.42.0", default-features = false, features = [<the entity feature>] }`, `htmd = "=<version chosen in Step 1>"`), `Cargo.lock`, `crates/convert/Cargo.toml`
- Modify: `ci/check-workspace.mjs` (`CONVERT_EXTERNAL_ALLOW = ["pulldown-cmark", "quick-xml", "htmd"]`), `ci/check-workspace.test.mjs`

**Interfaces:**
- Consumes: the M5 Task 1 checker structure (`CONVERT_EXTERNAL_ALLOW`, `ci/check-workspace.mjs:73`, `:228`).
- Produces: the pins and the widened allowlist; no Rust module yet (Task 2 adds the first).

**Spec:** §2.2, §7.6 ("parse with `quick-xml` with an HTML named-entity resolver", "remaining HTML → Markdown via `htmd`", "html5ever-based conversion"), PD-94.

- [ ] **Step 1: Verify the pins (WebFetch only).** For `htmd`: crates.io `/api/v1/crates/htmd` (versions, publish dates ≥ 14 days, license) and `/api/v1/crates/htmd/<v>/dependencies` (normal deps) for the candidate versions; choose per lead ruling Q6: the newest version whose `html5ever` (and `markup5ever`) requirement is satisfied by a copy already in `Cargo.lock` (`html5ever 0.39.0`/`markup5ever 0.39.0` via `dom_query`, `html5ever 0.40.1`/`markup5ever 0.40.0` via `ammonia`); only if no such version exists, the newest suitable version, accepting a third copy under the Q6 conditions ("Dependency pins"). For `quick-xml 0.42.0`: docs.rs feature list and that `quick_xml::escape::resolve_html5_entity` (or the 0.42 equivalent) exists. Record the choice and why in the report. Stop and report to the lead if `htmd` pulls a network/I/O crate or has a build script that fetches. No in-house converter replaces `htmd`.
- [ ] **Step 2: Failing test.** `ci/check-workspace.test.mjs`: `convert external dependency outside allowlist is rejected` keeps rejecting `reqwest`; `convert may depend on quick-xml and htmd` passes.
- [ ] **Step 3: Implement.** One unlocked `cargo build -j 4 -p atlas-duck-convert`, then `--locked` everywhere. `cargo tree -p atlas-duck-convert -e normal --locked` lists only the three crates and their own deps (record the list and any new `html5ever`/`markup5ever` copy in the report; with a new copy, also record the clean-build time of `atlas-duck-convert` and the extra crates, and mark the commit provisional until the lead's push shows the CI `supply-chain` job green with `deny.toml` unchanged).
- [ ] **Step 4: Run** `cargo test -j 4 -p atlas-duck-convert --locked`; `node ci/check-workspace.mjs && node ci/check-no-panic-macros.mjs && node --test "ci/*.test.mjs"`; `cargo build -j 4 --workspace --locked`.
- [ ] **Step 5: Commit** `build(convert): quick-xml and htmd pins, convert allowlist` (+ trailer), pathspecs `Cargo.toml Cargo.lock crates/convert ci`.

---

### Task 2: `convert::storage` parser, construct inventory, user references

**Model:** Opus (the parser is the ground truth of the hard check, the lossy count and the conversion). **Reviewer:** Opus (medium).

**Files:**
- Create: `crates/convert/src/storage/mod.rs`, `crates/convert/src/storage/parse.rs`; Modify: `crates/convert/src/lib.rs`
- Test: `crates/convert/tests/storage_parse.rs`

**Interfaces:**
- Consumes: Task 1 pins; the M5 `WikiConstructs` type (`convert::wiki`).
- Produces: `pub mod storage` with `pub fn parse(storage: &str) -> StorageDoc` (never fails: `StorageDoc { pub nodes: Vec<Node>, pub xml_ok: bool }`; on an XML error `xml_ok = false` and `nodes` holds what was read up to it); `Node` = `Element { ns: Ns /* Html | Ac | Ri | Other */, local: String, attrs: Vec<(String, String)> /* qualified names, values entity-decoded */, children: Vec<Node>, byte_range: Range<usize> }` | `Text(String)` (entity-decoded) | `CData { text: String, byte_range }`; the fragment is wrapped in a root declaring `ac:` and `ri:` (any URI) before parsing, ranges are reported relative to the original input; HTML5 named entities and numeric references are resolved, an unknown named entity is kept as literal text (`&foo;`) and does not fail the parse; depth bound 64 (deeper input: `xml_ok = false`). `pub fn storage_user_refs(storage: &str) -> StorageUsers` and `pub fn storage_constructs(storage: &str) -> WikiConstructs` (Δ1; macros = `ac:structured-macro` `ac:name` values incl. `include`/`excerpt-include` reported under `includes`; mentions = user keys and legacy usernames; links = `ri:page` titles (`<space>:<title>` when a space key is given) and `<a href>` values; images = `ri:attachment` filenames or `ri:url` values under `ac:image`; attachments = `ri:attachment` under `ac:link`). `pub(crate) fn construct_spans(doc: &StorageDoc) -> Vec<(ConstructKind, Range<usize>)>` for the hard check (Task 6).

**Spec:** §7.6 storage → Markdown (parser, entities, fallback), §7.6 hard check ("the storage parser above for Confluence"), PD-94, PD-97.

- [ ] **Step 1: Failing tests** (`tests/storage_parse.rs`): `parses_namespaced_fragment_with_entities` (`<p>a&nbsp;b &uuml; &#252; &amp;lt;</p>` → text `a\u{a0}b ü ü &lt;`; `xml_ok`); `macro_inventory_names_and_params` (`toc`, `code` with `language`, `info` with a rich-text body, `include` → `includes`); `user_refs_userkey_and_legacy_username` (`<ri:user ri:userkey="8a7f"/>` and `<ri:user ri:username="jdoe"/>`); `cdata_plain_text_body_is_opaque` (a CDATA holding `<ri:user ri:userkey="x"/>` and `]]]]><![CDATA[>` yields no construct and the joined text `…]]>…`); `links_images_attachments_inventory` (one of each kind in document order); `unknown_entity_kept_literal`; `invalid_xml_reports_fallback` (`<p>a<b>c</p>` → `xml_ok == false`); `ranges_slice_the_original_input` (every reported `byte_range` is on char boundaries of the input and slices exactly the element's source); `parse_never_panics_on_garbage` (proptest 1 000 cases over arbitrary `String` plus fragments biased to `<`, `>`, `&`, `]]>`, `ac:`, `ri:`, unbalanced tags).
- [ ] **Step 2: Implement** (event loop over `quick_xml::Reader` with the root wrapper; no `unwrap`; bounded recursion).
- [ ] **Step 3: Run** `cargo test -j 4 -p atlas-duck-convert --locked`; `cargo clippy -j 4 -p atlas-duck-convert --all-targets --locked -- -D warnings`.
- [ ] **Step 4: Commit** `feat(convert): Confluence storage parser with entity resolution and the construct inventory` (+ trailer).

---

### Task 3: `storage_to_markdown` with placeholders, look-alike escaping, `user_resolutions` and the fallback

**Model:** Opus. **Reviewer:** Opus (medium); must challenge the provisional PD-95 known-macro list (lead ruling Q11).

**Files:**
- Create: `crates/convert/src/storage/to_md.rs`; Modify: `crates/convert/src/lib.rs`, `crates/convert/src/storage/mod.rs`
- Test: `crates/convert/tests/storage_to_md.rs`, golden files `crates/convert/tests/golden/storage_to_md/{basics,macros,code_cdata,links_images,mentions,tasks_layouts,entities,lookalikes,fallback}.xml` + the expected `.md` beside each

**Interfaces:**
- Consumes: Task 2 `parse`; `htmd` (`htmd::convert` or the builder API of 0.5.5, Task 1 report).
- Produces: `pub fn storage_to_markdown(storage: &str, users: &UserResolutions) -> (String, ConversionReport, UserResolutions)` and the Δ1 types (`UserResolutions`, `ConversionReport`, `LostCounts`), mapping exactly per PD-95; the returned map holds every `ri:userkey` of the body (the given value, or `null` when the input map lacks it); legacy `ri:username` needs no entry. Look-alike escaping per PD-95. Fallback per PD-94 (`fallback: true`, `lossy: true`). Output deterministic, Markdown that `pulldown-cmark` parses back to the same text runs (the placeholder check of Task 4 sees placeholders exactly where the converter put them).

**Spec:** §7.6 storage → Markdown (incl. look-alike escaping, user resolution "pure function that takes an explicit map and returns the map it used"), §4.2 `meta.conversion`, §13 U-23 ("storage→md incl. CDATA, macros, entities, user mentions"), PD-95.

- [ ] **Step 1: Failing tests** (`tests/storage_to_md.rs`): `u23_storage_to_md_golden` (every pair byte-exact; a unified diff on failure); `u23_storage_entities_and_mentions` (`&uuml;`, `&#252;`, `&nbsp;` decoded; `ri:user` with a mapped key → `@jdoe`, with a `null` → `@user:8a7f`, legacy `ri:username` → `@asmith`); `users_map_returned_is_the_map_used` (an input map with an extra key and a missing key → the returned map has exactly the body's keys, missing ones `null`); `conversion_report_counts_lossy_constructs` (two unknown macros, one image, one `ac:link`, one layout → `lost {macros: 2, images: 1, links: 1, layouts: 1}`, `lossy: true`, `unknown_macros` names in order; a page with only `code` and `info` macros → `lossy` true for `info`, false for a code-only page); `code_macro_cdata_to_fenced_code` (language kept when it matches the pattern, dropped otherwise; a body holding `` ``` `` gets a longer fence); `u23_lookalikes_escaped` (prose `[macro: toc {}]`, `@user:abc`, a genuine `<a href="confluence:DOC/x">` → escaped forms); `html_fallback_on_xml_failure` (malformed storage with one CDATA code body → the code body as fenced code, `fallback: true`, `lossy: true`); `deterministic_and_never_panics` (proptest 1 000 cases over Task 2's strategy: same output twice, no panic).
- [ ] **Step 2: Implement.** Placeholders and code blocks are produced by this module, never by `htmd`; each run of plain HTML between them goes through `htmd` and its output is checked for look-alikes before it is appended (escape `[macro:` and `@user:` it produced from prose).
- [ ] **Step 3: Run** `cargo test -j 4 -p atlas-duck-convert --locked`; clippy as Task 2.
- [ ] **Step 4: Commit** `feat(convert): storage to Markdown with placeholders, look-alike escaping and user resolutions (U-23 storage)` (+ trailer).

---

### Task 4: `check_markdown_placeholders` (U-25 convert half)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:**
- Create: `crates/convert/src/placeholders.rs`; Modify: `crates/convert/src/lib.rs`
- Test: `crates/convert/tests/placeholders.rs`, golden inputs `crates/convert/tests/golden/placeholders/*.md`

**Interfaces:**
- Consumes: `pulldown-cmark` (`Parser::new_ext(md, ENABLE_TABLES | ENABLE_STRIKETHROUGH | ENABLE_TASKLISTS).into_offset_iter()`).
- Produces: `pub fn check_markdown_placeholders(md: &str) -> Result<(), Vec<PlaceholderHit>>` per PD-98 (Δ1 types); `PlaceholderKind::as_str()` = `link`, `image`, `macro`, `user`.

**Spec:** §7.6 Placeholder check (three detection rules, "by source span", "a backslash-escaped form never matches"), §4.3 exit 2 `markdown_placeholders`, §13 U-25, PD-98.

- [ ] **Step 1: Failing tests:** `u25_placeholders_golden_rejected_with_counts` (a `page get` Markdown body with one `[macro: toc {}]`, two `confluence:` links, one `confluence:attachment/` image and one `@user:8a7f` → `[{link, 2}, {image, 1}, {macro, 1}, {user, 1}]` in that order); `u25_escaped_lookalikes_pass` (`\[macro: toc {}]`, `\@user:abc`, a link whose text mentions `confluence:` but whose destination is `https://…` → `Ok`); `placeholders_in_code_are_not_hits` (the same placeholders in a code span and a fenced block → `Ok`); `scheme_is_case_insensitive` (`CONFLUENCE:x`); `placeholder_hits_carry_no_text` (`Debug` of the hits holds no byte of the input).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** `cargo test -j 4 -p atlas-duck-convert --locked`; clippy.
- [ ] **Step 4: Commit** `feat(convert): Markdown placeholder check by source span (U-25)` (+ trailer).

---

### Task 5: `markdown_to_storage` with XML escaping and the code-macro rule; shared escaping helpers; M5 M-4

**Model:** Opus (escaping is the primary defence; the hard check is the second). **Reviewer:** Opus (medium).

**Files:**
- Create: `crates/convert/src/md_to_storage.rs`, `crates/convert/src/xml_escape.rs`; Modify: `crates/convert/src/lib.rs`, `crates/convert/src/md_to_wiki.rs` (M-4: `link_target`), `crates/convert/src/escape.rs` (export the reference-start helper `entity_like` for both converters, `pub(crate)`)
- Test: `crates/convert/tests/md_to_storage.rs`, `crates/convert/tests/md_to_wiki.rs` (add), golden files `crates/convert/tests/golden/md_to_storage/{basics,lists,tables,code,links,html,specials,nested,tasks}.md` + the expected `.xml`

**Interfaces:**
- Consumes: `pulldown-cmark`; M5 `EmittedConstructs`/`EmittedCode`/`ContainerKind` (Δ1 adds `CodeMacro`).
- Produces: `pub fn markdown_to_storage(md: &str) -> (String, EmittedConstructs)` per PD-96; `xml_escape::{text, attr}`; every emitted code macro recorded with its byte range. In `md_to_wiki.rs::link_target`, a `&` that starts a character reference (per `escape::entity_like`) is percent-encoded as `%26`, like the other specials (M5 final review M-4, L105).

**Spec:** §7.6 Markdown → storage ("All raw HTML and wiki-special sequences … are escaped, so Markdown input can never produce macros, mentions or includes"; storage code bodies "`ac:plain-text-body` CDATA with every `]]>` split as `]]]]><![CDATA[>`"), §5.4 step 1, PD-96.

- [ ] **Step 1: Failing tests** (`tests/md_to_storage.rs`): `u23_md_to_storage_golden` (byte-exact, diff on failure); `u23_md_to_storage_escapes_raw_html_and_xml_specials` (`<script>x</script>`, `<ac:structured-macro ac:name="toc"/>`, `<ri:user ri:userkey="x"/>`, `&nbsp;`, `]]>` in prose, `"` in a link title → escaped; `storage::parse` of the output finds no `ac:`/`ri:` element); `u24_storage_cdata_split_in_fenced_and_inline_code` (a fenced block containing `]]>` twice and `]]]]>` → the split form; inline code with `]]>` → `<code>]]&gt;</code>`); `images_become_links_never_ac_image`; `links_only_safe_schemes` (`javascript:alert(1)` and `data:` destinations → text with the destination in parentheses, no `<a`); `task_items_are_plain_text`; `at_mention_stays_text`; `emitted_code_macro_ranges` (each recorded range slices exactly one `<ac:structured-macro ac:name="code">…</ac:structured-macro>`); `deterministic_output` (100 random inputs twice). `tests/md_to_wiki.rs`: `m4_link_target_encodes_character_references` (destination `https://x.example/?a=1&#123;b` → `…&#123;` never reaches the wiki output; `%26#123;` does).
- [ ] **Step 2: Implement** (explicit state machine over events; impossible states fall back to escaped text; no `unwrap`).
- [ ] **Step 3: Run** `cargo test -j 4 -p atlas-duck-convert --locked` (the M5 wiki tests stay green, `u24_fuzz_reparse_finds_nothing_unrecorded` included); clippy.
- [ ] **Step 4: Commit** `feat(convert): Markdown to storage with XML escaping and the code-macro rule; fix(convert): wiki link targets encode character references (M5 M-4)` (+ trailer).

---

### Task 6: `hard_check_storage`; U-24 storage golden and fuzz; U-25 round trip

**Model:** Opus. **Reviewer:** Opus (medium).

**Files:**
- Create: `crates/convert/src/storage/hard_check.rs`; Modify: `crates/convert/src/wiki/mod.rs` (`ConstructKind::{Link, Markup}`), `crates/convert/src/hard_check.rs` (match arms only), `crates/convert/src/lib.rs`
- Test: `crates/convert/tests/hard_check_storage.rs`

**Interfaces:**
- Consumes: Tasks 2, 3, 4, 5.
- Produces: `pub fn hard_check_storage(s: &str, e: &EmittedConstructs) -> Result<(), Unrecorded>` per PD-97; `ConstructKind::as_str()` gains `link`, `markup`.

**Spec:** §7.6 hard check, §13 U-24 ("golden and fuzz tests with `{code}`, `{noformat}`, both together, and `]]>` inside fenced blocks and inline code; for every generated Markdown input, re-parsing the md→wiki / md→storage output finds no macro, mention, include or `ri:user` the converter did not record, and a test-injected converter fault … fails validation"), §13 U-25 ("converts back to the same text"), PD-97.

- [ ] **Step 1: Failing tests** (`tests/hard_check_storage.rs`): `u24_storage_code_body_containers` (inputs with `{code}`, `{noformat}`, both, `]]>` in fenced and inline code, `<ac:structured-macro` inside a fenced block → `Ok`); `u24_storage_fuzz_reparse_finds_nothing_unrecorded` (proptest `ProptestConfig { cases: 2048, .. }`: Markdown built from fragments biased to `<`, `>`, `&`, `]]>`, `<![CDATA[`, `ac:`, `ri:`, `<ac:structured-macro ac:name="include">`, `<ri:user ri:userkey="x"/>`, entities, autolinks `<javascript:x>`, link titles with `"`, tables with raw HTML in cells, fences of every length, CR/LF mixes, U+202E, U+2028 → `hard_check_storage(&out, &emitted) == Ok(())` for every case; failures shrink); `u24_storage_faulty_converter_detected` (appending `<ri:user ri:userkey="x"/>`, `<ac:structured-macro ac:name="include"/>`, `<ac:link><ri:page ri:content-title="X"/></ac:link>`, `<img src="https://x"/>` to a real output in turn → `Err(Unrecorded {kind, count: 1})` with `Mention`, `Include`, `Link`, `Markup`); `hard_check_storage_counts_images_and_links`; `recorded_code_macro_passes` (a recorded code macro whose CDATA holds `<ri:user …>` → `Ok`); `unrecorded_error_has_no_text`; `u25_lookalike_round_trip` (storage prose holding the four look-alikes → `storage_to_markdown` → `check_markdown_placeholders` is `Ok` → `markdown_to_storage` → `storage_to_markdown` again gives the same Markdown text).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** `cargo test -j 4 -p atlas-duck-convert --locked`; clippy. Record the proptest case count and runtime in the report.
- [ ] **Step 4: Commit** `feat(convert): storage re-parse hard check with golden, fuzz and injected-fault tests (U-24 storage, U-25 round trip)` (+ trailer).

---

### Task 7: `lossy_update`, `storage_lines`, `markdown_to_preview_html`

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:**
- Create: `crates/convert/src/storage/lossy.rs`, `crates/convert/src/md_preview.rs`; Modify: `crates/convert/src/lib.rs`
- Test: `crates/convert/tests/lossy.rs`, `crates/convert/tests/md_preview.rs`, golden files `crates/convert/tests/golden/md_preview/*.md` + `*.html`

**Interfaces:**
- Consumes: Task 2 `parse`/`storage_constructs`.
- Produces: `pub fn lossy_update(current: &str, outgoing: &str) -> LostCounts` (per kind: `ac:structured-macro` other than `code`/`noformat` → macros; `ac:image` → images; `ac:link` and `ri:page`/`ri:attachment`/`ri:user` references → links; `ac:layout` → layouts; count in current minus count in outgoing, saturating at 0); `pub fn storage_lines(storage: &str) -> Vec<&str>` (a line ends after each closing tag of `p`, `h1`–`h6`, `li`, `tr`, `table`, `blockquote`, `pre`, `ac:structured-macro`, `ac:layout-section`, after `<br/>`/`<hr/>` and at every `\n`; never inside a CDATA section; the lines concatenate to the input); `pub fn markdown_to_preview_html(md: &str) -> String` per PD-94 (`<h1>`–`<h6>`, `<p>`, `<strong>`, `<em>`, `<del>`, lists, tables, `<blockquote>`, `<pre><code>` for code (text), links as text `text (url)`, images as text `[image: src]`, raw HTML as escaped text, task items with `☐`/`☑` text; all text HTML-escaped).

**Spec:** §7.6 Lossy updates, §6.3 Edit/update (raw native diff of storage XHTML), §6.3 Confluence page ("Rendered Markdown"), §6.4, §13 S-12, PD-94, PD-104.

- [ ] **Step 1: Failing tests:** `tests/lossy.rs`: `lossy_counts_macros_images_links_layouts`; `lossy_zero_for_identical_and_for_additions`; `code_macros_are_not_lossy`; `storage_lines_concatenate_to_input` (proptest 500 cases: `storage_lines(s).concat() == s`); `storage_lines_split_at_block_ends`. `tests/md_preview.rs`: `md_preview_html_golden`; `s12_md_preview_neutralizes_remote_and_scripts` (`![x](https://evil.example/a.png)`, `<script>alert(1)</script>`, `[a](javascript:alert(1))` → no `<img`, `<script`, `<a`, `href`, `src`, `on…=`); `deterministic_and_never_panics` (proptest 1 000).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** `cargo test -j 4 -p atlas-duck-convert --locked`; clippy.
- [ ] **Step 4: Commit** `feat(convert): lossy-update count, storage line projection and Markdown preview HTML` (+ trailer).

---

### Task 8: `preview` model and `render` arms for Confluence (Δ2, `render3`); DTO fixtures

**Model:** Opus (the renderer emits the HTML the approver trusts). **Reviewer:** Opus (medium).

**Files:**
- Modify: `crates/preview/src/model.rs`, `crates/preview/src/warning.rs`, `crates/preview/src/render/body.rs`, `crates/preview/src/lib.rs`; Create golden files `crates/preview/tests/golden/render/confluence_{page_markdown,page_view,comments,content_write,page_move,attachment_card,attachment_collision,conflict_intended}.html`
- Modify: `crates/core/src/**` only where a `PreviewBody::Conflict { .. }` literal needs the new fields (compile fix: Jira fills `requests` from its write view, `intended: Vec::new()`; Confluence's real values come in Task 15)
- Modify: `app/src-tauri/tests/dto_fixtures.rs` (`bodies()` gains one value per new variant), `app/ui/src/shared/ipc/fixtures/preview.json` (regenerated with `UPDATE_FIXTURES=1`)
- Test: `crates/preview/tests/model_confluence.rs`, `crates/preview/tests/render.rs` (add), `crates/preview/tests/warnings.rs` (add)

**Interfaces:**
- Consumes: M6 `render::document`, `iframe_document`, the `Doc` helpers in `render/body.rs`, `sanitize_html`, `DOC_MAX_*` caps.
- Produces: Δ2 exactly; render arms: `ConfluencePage` (header block title/space/version/ancestors as text, a "server-rendered view (secondary)" label for `format == "view"`, the body HTML inside the document as sanitized markup, the conversion facts as a fact table), `ConfluenceComments` (one section per comment, indented by `depth` with nested lists, author/date/location as text), `ContentWrite` (sentence, fact table, body HTML, construct list, requests), `PageMove` (two path lists, requests), `AttachmentUpload` (fact table, the thumbnail as `<img src="data:image/…;base64,…" alt="">` only when `thumbnail_data_uri` starts with `data:image/png|jpeg|gif|webp;base64,`, else the PD-110 text; "attachment already exists" line when `existing` is set; "replaces existing attachment vN" when `replaces_version`), `Conflict` (+ intended-change diff section and requests). `PREVIEW_BUILDER_VERSION` = `pb2;render3;icu-17.0;emoji-17.0`; `RENDER_VERSIONS` appends `("render3", <digest>)` (never edit `render1`/`render2`). `WarningId::DuplicateTitle` (`duplicate_title`, Caution). **Stylesheet (PD-92):** the new arms emit semantic elements only (no `class`, no `style`), so they render the same under the `<link>` delivery and under the PD-92 contingency (`preview.css` inlined as a head `<style>`); the renderer keeps its single stylesheet delivery point, and any `preview.css` rule M7 adds is part of the `render3` digest and of the inlined copy alike. **Thumbnail vs. S-08:** the attachment thumbnail is the first `<img>` the renderer ever emits; M6's `s08` sweep (`app/src-tauri/tests/e2e/flows.rs:909-925`) forbids every `img` and `[src]` in the document it opens. It opens a Jira issue, so it stays green; per lead ruling Q15 any future sweep over an attachment preview allows `img[src^="data:image/"]` (recorded in Task 24); no M7 e2e flow opens one.

**Spec:** §6.3 rows Confluence page, Confluence comments, Create issue/page, Page move, Attachment upload, Conflict (write); §6.4 (sanitizer, no `style`/`class`, data images only, links as text, bidi isolation); §6.2; PD-103, PD-110; M6 PD-67 (`render` contract), L106, L107.

- [ ] **Step 1: Failing tests:** `tests/model_confluence.rs`: `confluence_bodies_serialize_with_kind_tags` (`confluence_page`, `confluence_comments`, `content_write`, `page_move`, `attachment_upload`); `write_bodies_always_carry_requests`. `tests/render.rs`: `render_confluence_page_golden`, `render_page_view_labelled_secondary`, `render_comments_thread_golden`, `render_page_move_paths_golden`, `render_attachment_card_thumbnail_data_uri_only` (an `https:` or `data:image/svg+xml` thumbnail value renders as no `<img`), `render_attachment_collision_line`, `conflict_card_shows_intended_change`, `confluence_goldens_have_no_class_or_style` (the existing golden rule extended), `builder_version_names_the_render_version` (now `render3`), `render_output_change_bumps_the_render_version` (existing, with the new entry). `tests/warnings.rs`: `every_warning_id_has_exactly_one_level` (existing) includes `duplicate_title`.
- [ ] **Step 2: Implement**, then regenerate the DTO fixture: `UPDATE_FIXTURES=1 cargo test -j 4 -p atlas-duck-app --locked --test dto_fixtures`, then the same without the variable must pass; `npm --prefix app/ui run test` (the existing `fixtures.test.ts` parses the new bodies; `validate.ts` accepts any `kind` string, so no UI code change is expected — if a UI test fails, stop and report).
- [ ] **Step 3: Run** `cargo test -j 4 -p atlas-duck-preview --locked`; `cargo build -j 4 --workspace --locked`; the core suite (Jira conflict tests unchanged in meaning); clippy preview and core.
- [ ] **Step 4: Commit** `feat(preview): Confluence preview bodies and render arms (render3)` (+ trailer), pathspecs `crates/preview crates/core/src app/src-tauri/tests/dto_fixtures.rs app/ui/src/shared/ipc/fixtures/preview.json` (+ `app/ui/public/preview.css` if changed).

---

### Task 9: Confluence bodies at validation: placeholder check, conversion, hard check, injected fault; `describe` texts (U-24/U-25 core halves, U-33)

**Model:** Opus (validation path of the escaping defence). **Reviewer:** Opus (medium).

**Files:**
- Create: `crates/core/src/ops/confluence_body.rs`; Modify: `crates/core/src/ops/mod.rs`, `crates/core/src/ops/confluence.rs` (`page_update_executor` uses it), `crates/core/src/validate/mod.rs` (`check_body_format`; placeholder check), `crates/core/src/testing/fault.rs` (`ConverterFault::{RiUser, IncludeMacro, AcLink}`), `crates/registry/src/describe.rs`, `crates/registry/src/lib.rs` (PD-112 constants)
- Modify tests: `crates/core/tests/jira_validate.rs` (`u33_confluence_markdown_still_rejected` → `u33_confluence_markdown_now_accepted`), `crates/core/tests/validate.rs` (`u33_all_ops_compile_and_accept_their_example`: drop the Confluence `body_format` exception, M5 T7 review M-2), `crates/core/tests/handler.rs` (`pd09_markdown_body_rejected`, `handler.rs:143`, asserts the M3 refusal "markdown conversion is not available in this build": it becomes `pd09_markdown_body_converted_or_placeholder_rejected`, the same two param sets now pending and a placeholder body rejected with `markdown_placeholders`), `crates/core/tests/op_table.rs` (`executors_deterministic` gains the Markdown page update)
- Test: `crates/core/tests/confluence_validate.rs`, `crates/registry/tests/describe.rs` (add)

**Interfaces:**
- Consumes: Tasks 4, 5, 6; M5 `jira_body::wiki_text` pattern (PD-43), `ExecCtx.test_fault`, `validate::invalid`, `ErrorCode::MarkdownPlaceholders`.
- Produces: `pub(crate) fn confluence_body::storage_text(ctx: &ExecCtx<'_>) -> Result<String, ExecError>` (`body_format` `storage` → verbatim; `markdown`/absent → placeholder check first → `ExecError::Invalid(ValidationError { code: MarkdownPlaceholders, message: <§7.6 hint, verbatim>, details: {placeholders: [{kind, count}]} })`; then `markdown_to_storage` + (testing only) the fault appended + `hard_check_storage` → `ValidationError { code: Validation, message: "markdown conversion produced an unrecorded <kind>", details: {param: "body", construct, count} }`). The placeholder check therefore runs **before** conversion (§5.4 step 1) and both run in the validation dry executor call, so a failure is `REQUEST_REJECTED`, exit 2, nothing queued. `check_body_format` accepts Markdown for Confluence; every executor that takes a body (page create/update, comment add) calls `storage_text` before any `EnrichmentRequired` return. `describe` appends PD-112 texts: CQL to `confluence.search`; placeholders to the three body ops; lossy to `confluence.page.update`.

**Spec:** §5.4 step 1, §7.6 (placeholder check, hard check), §4.3 (`markdown_placeholders`, exit 2), §2.3 (`ops describe`), §12.4 (onboarding sentence), §13 U-24, U-25, PD-98, PD-112.

- [ ] **Step 1: Failing tests** (`tests/confluence_validate.rs`, Confluence harness): `u33_confluence_markdown_body_format_accepted` (`confluence.page.update` with a Markdown body → pending; the approved wire body's `body.storage.value` equals `markdown_to_storage(body)` and the `WRITE_APPROVED` bytes); `u25_markdown_placeholders_rejected_exit2_counts` (a body with the four placeholder kinds → `failed`, `markdown_placeholders`, exit 2, `retryable: false`, `details.placeholders == [{link,1},{image,1},{macro,1},{user,1}]`, message = the §7.6 hint, events `[REQUEST_RECEIVED, REQUEST_REJECTED]`, zero wiremock hits); `placeholder_check_runs_before_conversion` (a body with a placeholder **and** a converter fault configured → `markdown_placeholders`, not `validation`); `u24_storage_injected_fault_fails_validation_exit2` (`TestHooks { converter_fault: Some(ConverterFault::RiUser) }` → `validation`, exit 2, `details.construct == "mention"`; repeat `IncludeMacro` → `include`, `AcLink` → `link`; nothing queued, zero hits); `storage_body_format_is_verbatim` (`body_format: storage` with `<ac:structured-macro ac:name="toc"/>` → sent unchanged); `comment_add_markdown_rejected_before_enrichment` (a placeholder in a `confluence.comment.add` body → rejected with zero hits, not even the container GET). `crates/registry/tests/describe.rs`: `confluence_describe_documents_cql_placeholders_lossy` (the three texts on exactly the ops PD-112 names).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite (the changed M3/M5 tests keep their intent: say which in the report); `cargo test -j 4 -p atlas-duck-registry --locked`; clippy core with `testing`.
- [ ] **Step 4: Commit** `feat(core): Confluence Markdown bodies with the placeholder check and the storage hard check at validation` (+ trailer), pathspecs `crates/core crates/registry`.

---

### Task 10: `page.get`/`page.history` formats, the Confluence body `ReadShape`, `meta.conversion`

**Model:** Opus (read engine, candidate determinism). **Reviewer:** Opus (medium).

**Files:**
- Modify: `crates/core/src/engine/read.rs` (`ReadShape::ConfluenceBody`, `result_value`, `normalize_with_drops` reads `payload["user_resolutions"]`, `ReadState.conversion`, `release_meta` adds `conversion`), `crates/core/src/ops/mod.rs` (`ReadView.conversion`), `crates/core/src/ops/confluence.rs` (`page_get_executor`, `page_history_executor`: the format's expand), `crates/core/src/ops/generic.rs` (only if `read_plan` needs a query override hook), `crates/core/src/engine/cache.rs` (only if the rebuild entry needs the shape)
- Create: `crates/core/tests/common/confluence.rs` (mounts listed in "File Structure")
- Test: `crates/core/tests/confluence_reads.rs`

**Interfaces:**
- Consumes: Task 3 `storage_to_markdown`; M5 `ReadShape` pattern (decided from op id + validated params only); `payloads::read_fetched(.., user_resolutions)`.
- Produces: per PD-100. `ReadShape::of` returns `ConfluenceBody { format, historical }` for `confluence.page.get` and for `confluence.page.history` **with** `version`. For `Markdown` the normalization converts `body.storage.value` with the committed map (until Task 11 the map is empty: every `ri:userkey` becomes `@user:<key>`, and `user_resolutions` is committed as `{}`) and replaces `body` with `{"format": "markdown", "value": …}`; `ReadState.conversion` = the report; `meta.conversion = {"lossy", "lost": {macros, images, links, layouts}}` is stored in `READ_RELEASED` (release metadata) and delivered. `View` swaps the expand to `body.view,…` (no conversion; Caution in Task 12). A page whose `body.storage` is missing (e.g. a non-page content id) normalizes to the raw answer (no failure; `conversion: None`).

**Spec:** §7.4 `page.get` (`format`), `page.history` ("`format` as `page.get`"), §4.2 (`data.result` exception; `meta.conversion`), §5.2 steps 3–4 (map committed before the candidate hash), §5.2 memory budget (rebuild), PD-100.

- [ ] **Step 1: Failing tests** (`tests/confluence_reads.rs`): `page_get_markdown_replaces_body_and_reports_conversion` (a page with one `info` macro → released `body == {"format":"markdown","value":…}`, `meta.conversion == {"lossy": true, "lost": {"macros": 1, "images": 0, "links": 0, "layouts": 0}}`; the request had `expand=body.storage,version,space,ancestors`); `page_get_storage_releases_storage` (no `meta.conversion`); `page_get_view_expands_body_view` (`expand=body.view,version,space,ancestors`; released `body.view` as sent); `page_history_version_markdown` (`version: 2` → the alt endpoint with `expand=body.storage,version`, converted); `page_history_summary_ignores_format`; `markdown_candidate_rebuild_hash_stable` (evict, reopen → no mock hit, same `candidate_hash`); `read_fetched_carries_user_resolutions` (the record's payload has `user_resolutions` as an object).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite (incl. `budget.rs`, `reads.rs`, `cancel.rs`); clippy.
- [ ] **Step 4: Commit** `feat(core): Confluence page formats with Markdown conversion and meta.conversion` (+ trailer).

---

### Task 11: User resolution: per-instance cache, lookups under the request cover, committed map, script host-call path (I-37 Confluence)

**Model:** Opus (a new PAT-bearing path inside reads; determinism). **Reviewer:** Opus (medium).

**Files:**
- Create: `crates/core/src/users.rs` (`UserCache`, the lookup pass); Modify: `crates/core/src/engine/read.rs` (run the pass inside `Fetching` after the content pages, before `READ_FETCHED`), `crates/core/src/engine/script.rs` (the same pass on a host call of the shape; map in `SCRIPT_CALL`), `crates/core/src/core.rs` (cache construction), `crates/core/src/lib.rs`, `crates/core/src/testing/harness.rs` (`Harness::user_cache_set(alias, key, Option<&str>)` for I-37), `crates/core/tests/common/confluence.rs` (`mount_users`)
- Test: `crates/core/tests/confluence_reads.rs` (add), `crates/core/tests/scripts.rs` (add one case)

**Interfaces:**
- Consumes: Task 2 `storage_user_refs`, Task 10 shape; M3 `InstanceClient::get_ctl`, the request cover, `payloads::preview_fetch` with `PreviewFetchPurpose::Resolve`, the limiter, `FetchControl`, the read budget; M3 fake `ScriptRunner` (`core::testing::runner`).
- Produces: per PD-99. `pub(crate) struct UserCache` (per instance: `HashMap<key, (Option<String>, UtcInstant)>` + LRU order, `get(instance, key) -> Option<Option<String>>` never awaits, `put(..)`); `pub(crate) async fn resolve_users(engine, entry, keys) -> Result<UserResolutions, Cancelled>` (cache hits first; up to 50 fresh `GET /rest/api/user?key=` lookups; each recorded `PREVIEW_FETCH {purpose: resolve}`; a non-usable answer → `null`). The committed map is the one `normalize` uses; the preview's Info `unresolved_mention` comes from `ConversionReport.unresolved_users > 0` (Task 12).

**Spec:** §7.6 User resolution ("filled during the fetch from the per-instance cache and, for misses, `GET /rest/api/user?key=` (logged as `PREVIEW_FETCH {purpose: resolve}` under the request id, also inside script runs) … committed … before the candidate hash is computed: in `READ_FETCHED` for direct reads … and in the `SCRIPT_CALL` of a script host call. The §5.2 rebuild uses only the committed map"), §5.2 step 3, §5.1 inv. 1, §13 I-37 ("an evicted Confluence Markdown candidate whose `ri:user` mentions were all user-cache hits rebuilds to the same hash from its committed `user_resolutions`, and a cache entry changed between fetch and rebuild does not affect the hash"), PD-99.

- [ ] **Step 1: Failing tests** (`tests/confluence_reads.rs`): `resolve_gets_are_preview_fetch_resolve_under_request` (two unknown keys → two `GET /wiki/rest/api/user?key=…` hits, each after its covering `REQUEST_RECEIVED` commit and with a `PREVIEW_FETCH {purpose: resolve}` record, all before `READ_FETCHED`; the released Markdown says `@jdoe`, `@asmith`); `user_resolutions_committed_in_read_fetched` (the map has both keys); `cache_hits_need_no_lookup` (second read of the same page: zero `user?key` hits; the map still lists both keys); `unresolvable_user_is_null_and_info` (lookup 404 → `null`, `@user:<key>`, the read succeeds); `resolve_lookups_capped_per_read` (60 distinct keys → exactly 50 lookups, 10 `null`); `i37_confluence_markdown_rebuild_from_committed_map` (all mentions cache hits, candidate evicted via `Harness::evict_candidate`, reopened → no mock hit, same `candidate_hash`); `i37_user_cache_change_does_not_change_hash` (after the fetch, `Harness::user_cache_set` changes a username; rebuild → same hash, released text keeps the committed name); `cancel_during_resolve_records_cancelled_in_flight` (a lookup held by the mock's delay; `cancel` → `PREVIEW_FETCH {purpose: resolve, outcome: cancelled_in_flight}` and `READ_FETCHED {outcome: cancelled_in_flight}` holding the content page already received (§5.2 step 3 "every byte received"), both before `CANCELLED`, envelope identical to a cancel in `AwaitingRelease`); `storage_format_resolves_nothing`. `tests/scripts.rs`: `script_host_call_commits_user_resolutions` (fake runner calls `confluence.page.get` → the `SCRIPT_CALL` payload has `user_resolutions`; the host-call result is the converted Markdown).
- [ ] **Step 2: Implement.** No lock held across an `.await`; the cache read never awaits; lookups go through the same `InstanceClient` with the request cover.
- [ ] **Step 3: Run** the core suite (incl. `audit_coverage.rs`, `budget.rs`, `cancel.rs`, `scripts.rs`); clippy; `node ci/check-no-panic-macros.mjs`.
- [ ] **Step 4: Commit** `feat(core): Confluence user resolution with a per-instance cache and the committed map (I-37)` (+ trailer).

---

### Task 12: Confluence read previews; search release list and `cql_broad`; U-28, U-31, U-34 (Confluence), S-12 (reads)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium); must challenge the provisional PD-102 `cql_broad` trigger (lead ruling Q11).

**Files:**
- Create: `crates/core/src/ops/confluence_preview.rs` (`page_preview`, `comments_preview`, `search_table`); Modify: `crates/core/src/ops/mod.rs` (previewers of every Confluence read), `crates/core/src/ops/confluence.rs` (`search_preview` builds on `search_table`; `cql_broad`), `crates/core/src/ops/generic.rs` (`list_table`, PD-114), `crates/core/src/ops/jira_preview.rs` (`list_preview` calls `generic::list_table`; no behaviour change), `crates/core/src/engine/read.rs` (`result_body`: PD-101 pruning for `confluence.search`)
- Modify: `crates/registry/src/confluence/schemas.rs`, `crates/registry/src/confluence/reads.rs` (Δ4 c)
- Test: `crates/core/tests/confluence_reads.rs` (add); existing `jira_reads.rs` list tests stay green; `crates/registry/tests/catalog.rs` (examples still validate)

**Interfaces:**
- Consumes: Tasks 3, 7, 8, 10, 11; M3 `escape_for_display`, `sanitize_html`, `count_value`, `invisible_warnings`, mixed-script helpers; the existing effective-CQL preview.
- Produces: `page_preview` → `PreviewBody::ConfluencePage` (`markdown`: `sanitize_html(markdown_to_preview_html(markdown))`; `storage`: rendered locally from storage with an empty map, labelled "rendered locally from storage" (plan text); `view`: `sanitize_html(body.view.value)` + Caution `server_rendered_view`); Info `unknown_macros` when `ConversionReport.unknown_macros` is non-empty, Info `unresolved_mention` when `unresolved_users > 0`; header counts over the full candidate. `comments_preview` → `ConfluenceComments` per PD-103. `search_table` → `Table` with columns `title`, `space`, `type`, `last modified`, `excerpt` (only when `excerpt=indexed`), count "N of totalSize", `PreviewModel.query` = effective CQL (existing) and Info `cql_broad` per PD-102. List ops → `generic::list_table`; `user.current`/`space.get`/history summary → JSON tree.

**Spec:** §6.3 rows Confluence page, Confluence comments, Confluence search, Lists; §6.2 (`server_rendered_view` Caution; Info `unknown_macros`, `unresolved_mention`, `cql_broad`); §6.4; §7.4 search release list; §13 U-28, U-31, U-34, S-12; PD-100, PD-101, PD-102, PD-103, PD-114.

- [ ] **Step 1: Failing tests** (`tests/confluence_reads.rs`): `u34_default_page_get_zero_caution` (a plain page, no macros, no mentions, no invisible chars → zero `Level::Caution`); `u34_view_format_exactly_one_caution` (`format: view` → exactly one Caution, `server_rendered_view`, text verbatim); `u34_confluence_info_warnings_are_info` (`unknown_macros`, `unresolved_mention`, `cql_broad` each `Level::Info`); `u28_confluence_search_mask_reaches_url` (mock search answer with title "Falcon Müller Plan", `url` `/display/LEGAL/Falcon+M%C3%BCller+Plan`, and `%20`, lower-case-hex and `&#252;`/`&uuml;` variants in other released fields; an every-occurrence mask of the title → the `url` is `[REDACTED]` (or dropped and listed in `fields_dropped` with `UrlMode::Drop`), `also_appears_in` lists it; without the URL handling the release stays blocked); `u31_effective_cql_on_the_wire_and_in_preview` (`space = DOC OR label = x ORDER BY title` → the wiremock request's `cql` query is `(space = DOC OR label = x) AND type in (page,blogpost,comment,attachment) ORDER BY title`, the preview header query shows it display-escaped); `u31_rejections_exit2_nothing_queued` (mid-query `ORDER BY`, an unterminated quote, `space=A) OR (type=space` → exit 2 `validation`, `details.param == "cql"`, no CQL echoed, zero hits); `search_results_pruned_to_spec_fields` (an answer with extra keys per result → released results carry only the §7.4 keys; `totalSize` unchanged; a result without `content` removed and counted); `cql_broad_info_rule` (`text ~ "x"` raises it; `space = DOC AND text ~ "x"` does not); `comments_preview_threaded` (three comments, one reply → depths 0, 0, 1; location from `extensions.location` or "location not reported"); `lists_preview_tables` (`space.list`, `page.children`, `label.list`, `attachment.list` → `Table`); `s12_confluence_page_preview_neutralizes_remote_and_marks_invisible` (storage with `<img src="https://evil.example/x.png"/>`, an `ac:image` with `ri:url`, `<script>` text, U+202E → no `<img`, `<script`, `href`, `src=` except `data:`; header bidi count 1; Caution `bidi_controls`); `s12_view_format_server_html_sanitized` (`body.view` with `<img src=https://…>`, `<a href>`, `style=` → none survive).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite; `cargo test -j 4 -p atlas-duck-registry --locked`; clippy.
- [ ] **Step 4: Commit** `feat(core): Confluence read previews, search release list and cql_broad (U-28, U-31, U-34, S-12)` (+ trailer), pathspecs `crates/core crates/registry`.

---

### Task 13: RF-5a: the identity step of Confluence reads (PD-93)

**Model:** Opus (identity; a new PAT-bearing GET inside reads). **Reviewer:** Opus (medium).

**Files:**
- Modify: `crates/core/src/engine/read.rs` (the identity GET after the last page and the lookups; `fetched_trigger` learns the Confluence trigger), `crates/core/src/identity.rs` (a `Trigger` from a non-matching `user/current` answer; no new effect), `crates/core/src/payloads.rs` (`PreviewFetchPurpose::Identity`, `as_str() == "identity"`), `crates/core/src/ops/mod.rs` (`EnrichPurpose::Identity`)
- Test: `crates/core/tests/confluence_identity.rs`

**Interfaces:**
- Consumes: M3 `identity::{recheck, effect, judge_confluence, Path::DirectRead}`, `identity_classified`, `Direct::needs_token`, `split_answer`; Task 11 (order: pages → lookups → identity GET).
- Produces: per PD-93 (lead ruling Q1 = A). For a Confluence direct read: `GET /rest/api/user/current` under the request cover, recorded `PREVIEW_FETCH {purpose: identity}`; `judge_confluence` on its answer against the stored identity: `IdentityMatch` → the read settles as before; anything else → the content answer is audit-only and the M3 re-check/effect table decides. The step runs once per read (paged reads included) and also for `confluence.user.current` itself (whose own answer is the content: an anonymous answer is the token-failure path).

**Spec:** §7.1 (identity match: `type == "known"` + stored `userKey`; 401 handling), §7.2 (identity check on responses; "Confluence responses are not header-checked until §15 confirms an equivalent header"), §5.2 step 6 (direct failures), master plan RF-5 (a), §15 V25, PD-93, L29, L31.

- [ ] **Step 1: Failing tests** (`tests/confluence_identity.rs`): `rf5a_confluence_anonymous_read` (wiremock `user/current {type: anonymous}` after the instance was set up as `jdoe`, `page.get` 200 → `failed`, `needs_token`, exit 9, no release item, the page body only in `READ_FETCHED {unavailable: identity_check}`, one `SYSTEM_FETCH {purpose: token_recheck}` start + result, `INSTANCE_STATE_CHANGED {needs_token}`); `rf5a_paged_read_checked_once_after_last_page` (`space.list` over three pages → exactly one `user/current` hit, after the third page hit); `rf5a_identity_match_race_is_upstream_unavailable` (first `user/current` anonymous, the re-check known → `upstream_unavailable`, exit 6, `retryable: true`, state `ok`); `rf5a_identity_get_3xx_is_direct_upstream_unavailable` (`user/current` 302 → exit 6 direct, the page body audit-only); `rf5a_identity_get_truncated_json_is_gated` (an outcome item, never `READ_FAILED`); `rf5a_user_current_op_anonymous_is_token_failure`; `rf5a_known_identity_releases_normally` (record order `PREVIEW_FETCH {identity}` before `READ_FETCHED`); `rf5a_identity_get_counts_in_read_budget` (`TestHooks::read_budget` exhausted during the identity GET → the read-budget outcome item); `rf5a_upstream_error_read_is_identity_checked` (`page.get` answers a JSON 404 and `user/current` anonymous → `needs_token`, no upstream-error card); `rf5a_direct_failure_runs_no_identity_get` (`page.get` answers 302 → exit 6 direct, zero `user/current` hits).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite (incl. `identity.rs`, `upstream.rs`, `opacity.rs`, `audit_coverage.rs`); clippy.
- [ ] **Step 4: Commit** `feat(core): identity step for Confluence reads under the anonymous fallback (RF-5a)` (+ trailer).

---

### Task 14: Confluence paging: `_links.next` as an end signal (M3 T10 minor 8), I-22 context path and `meta.page`

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:**
- Modify: `crates/atlassian/src/client/paginate.rs` (an answer whose `_links` is an object **without** `next` ends paging; an answer with no `_links` object at all is no end signal (an endpoint that omits `_links` must not stop after page 1); the value of `next` is never read as a URL)
- Test: `crates/atlassian/tests/pagination.rs` (add), `crates/core/tests/confluence_reads.rs` (add)

**Interfaces:**
- Consumes: M3 `read_paginated_ctl`, `PageFacts`, `PageEnd`, the existing end signals; `MockDc::confluence_space_page(..)`.
- Produces: the end-signal change (presence only); tests.

**Spec:** §7.2 Pagination ("An absent `_links.next` … serve only as end-of-results signals. `_links.next` is never followed as a URL"), §7.5 (normative `meta.page`), §13 I-22 ("with base URL `https://mock/confluence` and a relative `_links.next` without the context path … page 2 of a direct read … is requested at `/confluence/rest/api/…` and nothing is requested outside `/confluence`"), PD-111.

- [ ] **Step 1: Failing tests:** `pagination.rs`: `links_next_absent_ends_paging` (two full pages, the second with a `_links` object without `next`, no `total` → exactly two requests, `next_start: None`); `page_without_links_object_is_no_end_signal` (full pages with no `_links` key at all → paging continues to the short page, as before); `links_next_present_never_followed` (a `_links.next` pointing elsewhere → the next request is rebuilt from the template under the context path). `confluence_reads.rs`: `i22_confluence_context_path_direct_read` (`confluence.space.list` with `max: 50` over the harness instance at `/wiki` with `_links.next` `/rest/api/space?limit=25&start=25` → page 2 requested at `/wiki/rest/api/space?…start=25…`; every hit's path starts with `/wiki/`); `i22_confluence_drops_keep_totals_and_next_start` (`page.children` max 10 over 25 children: release with 2 dropped → `meta.page {start: 0, returned: 8, total: null, truncated: true, next_start: 10}`, `items_dropped == 2`); `i22_confluence_next_start_loop_rerequests_no_dropped_item`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the atlassian and core suites with `testing`; clippy.
- [ ] **Step 4: Commit** `fix(atlassian): absent _links.next ends Confluence paging; test(core): I-22 Confluence context path and meta.page` (+ trailer), pathspecs `crates/atlassian crates/core`.

---

### Task 15: `confluence.page.update` complete: base body, diffs, lossy check, conflict card (I-36, I-06 conflict, I-32 Markdown, S-12 diff)

**Model:** Opus (the conflict state and the stale baseline must agree). **Reviewer:** Opus (medium).

**Files:**
- Modify: `crates/core/src/ops/confluence.rs` (`PAGE_UPDATE_ENRICH` as two stages; the judge fills `WriteSummaryFacts.confluence`, the conflict diff and the lossy counts; `page_update_executor` uses Task 9), `crates/core/src/ops/confluence_preview.rs` (`update_preview` → `EditDiff`; conflict → `Conflict` with `intended` and `requests`), `crates/core/src/ops/mod.rs` (previewer row)
- Test: `crates/core/tests/confluence_update.rs`, `crates/atlassian/tests/writes.rs` (minor 7 pin)

**Interfaces:**
- Consumes: Tasks 3, 7, 8, 9; M5 staged driver (`engine/enrich.rs`), `preview::diff::{line_diff, hunks}`, `CONFLICT_DENY_PREFILL`, `warning::conflict`, `stale::PAGE_UPDATE` (unchanged).
- Produces: per PD-104 and PD-111. The verdict's `baseline` stays `{version, title, space_key}` (the stale rule reads it).

**Spec:** §5.4 step 2 (conflict incl. "the agent's base version body (`GET /rest/api/content/{id}?version=<base_version>&status=historical&expand=body.storage`)"), step 4 (baselines read-only), step 6 (409/400 → `WRITE_STALE {version_conflict}` → conflict state), §6.2 (`conflict`, `lossy_update`, `raw_only_diff`), §6.3 Edit/update and Conflict, §7.4 `page.update`, §7.6 lossy updates, §13 I-36, I-06, I-32, S-12, PD-104, PD-111, L12.

- [ ] **Step 1: Failing tests** (`tests/confluence_update.rs`): `i36_page_update_base_behind_is_conflict_not_approvable` (base 5, mock at 6 → `Hold::Conflict`, Caution text exactly `conflict: page changed since the agent read it (v5 → v6)`, approve → `DECISION_INVALID {not_approvable}`, no `WRITE_APPROVED`; events show `PREVIEW_FETCH {enrich}` ×2, the second for `?version=5&status=historical&expand=body.storage`); `i36_page_update_conflict_shows_base_to_current_diff` (the `Conflict` body's diff is base → current and `intended` is base → outgoing; `requests` present); `i36_page_update_without_base_version_exit2`; `i36_page_update_409_returns_conflict_not_reapprovable` (approve at v5, mock answers 409 → `WRITE_STALE {version_conflict}`, the refresh sees v6 → conflict, approve → `not_approvable`); `i36_sent_version_is_base_plus_one` (Markdown body; wire `version.number == 6` for base 5); `i06_page_update_conflict_batch_rejected` (batch of the conflict item with a clean `confluence.label.add` → whole batch rejected, nothing decided); `lossy_update_caution_counts` (current storage with two macros and an image, a Markdown update without them → Caution `this update will remove 2 macros / 1 images / 0 links`; a layout → `, 1 layouts` suffix; Approve enabled); `storage_update_has_no_lossy_check`; `page_update_rendered_and_raw_diffs` (rendered diff over the Markdown projections, raw over `storage_lines`); `s12_confluence_raw_only_diff_flagged` (a storage update that changes only an attribute's quoting → rendered diff empty, raw non-empty → Caution `raw_only_diff`); `title_kept_unless_given`; `edit_form_base_version_read_only` (`base_version` and `id` read-only; an edit of `base_version` → `DECISION_INVALID {target_param_edit}`); `stage2_historical_3xx_direct` (stage 2 answers 302 → `REQUEST_FAILED {upstream_unavailable}`, exit 6); `i32_markdown_update_rerendered_under_new_origin` (the M3 I-32 flow with a Markdown body: after the confirmed change and a new PAT, the re-rendered request carries the new origin and the same converted body; nothing reaches the old origin). `crates/atlassian/tests/writes.rs`: `truncated_conflict_400_is_failed4xx` (a Confluence 400 whose body is cut mid-JSON → `WriteOutcome::Failed4xx`).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core and atlassian suites (incl. `decisions.rs`, `writes.rs`, `identity.rs`, `reconcile.rs`); clippy.
- [ ] **Step 4: Commit** `feat(core): confluence.page.update with the base body, diffs, lossy check and conflict card (I-36)` (+ trailer), pathspecs `crates/core crates/atlassian`.

---

### Task 16: `confluence.page.create`: space and parent resolution, duplicate title, create card (I-35 parent)

**Model:** Opus (name resolution and approvability). **Reviewer:** Opus (medium).

**Files:**
- Create: `crates/core/src/ops/confluence_ext.rs` (`PAGE_CREATE_ENRICH`, `page_create_executor`, the shared `resolve_parent`); Modify: `crates/core/src/ops/mod.rs` (row: `enrich_keys: &["title", "body"]`, no stale rule), `crates/core/src/ops/confluence_preview.rs` (`create_preview` → `ContentWrite`), `crates/preview/src/warning.rs` (the `duplicate_title` text constant, plan text)
- Modify: `crates/registry/src/confluence/schemas.rs` (Δ4 a, lead ruling Q2)
- Modify tests: `crates/core/tests/op_table.rs` (`LATER_WRITES` loses `confluence.page.create`), `crates/core/tests/similarity.rs` (add)
- Test: `crates/core/tests/confluence_create.rs`

**Interfaces:**
- Consumes: Tasks 8, 9; M5 staged rules (Δ3), M3 `UnresolvedName` hold and `resolution_message`, `DenyDetails::ResolutionFailed`.
- Produces: per PD-105.

**Spec:** §5.4 step 2 (parent page resolution, Confluence duplicate-title check, unresolved name), §6.3 Create ("duplicate-title warning (Confluence)"), §7.4 `page.create`, §13 I-35 ("parent page"), RF-4, PD-105.

- [ ] **Step 1: Failing tests** (`tests/confluence_create.rs`): `page_create_markdown_converted_and_sent` (body `{"type":"page","title","space":{"key":"DOC"},"ancestors":[{"id":"123400"}],"body":{"storage":{…}}}`, receipt `{id, type, status, version, _links.webui}`); `i35_parent_page_no_match_and_ambiguous` (id 404 → 0 matches; title with two results → ambiguous, candidates the two titles; each `not_approvable`); `i35_parent_page_deny_hint_candidates_only_when_ticked` (`resolution_failed`, exit 3); `parent_in_other_space_unresolved`; `parent_by_title_resolves_to_id`; `parent_schema_accepts_id_and_title` (registry: `"123400"` and `"Release notes"` both validate, `""` does not); `space_unresolved` (404 → `UnresolvedName {param: space}`); `duplicate_title_caution_approve_enabled` (Caution `duplicate_title`, approvable true; the 400 Confluence then sends → `WRITE_FAILED`); `page_create_card_resolved_names` (sentence with space name and parent title; rendered body; construct list empty for a Markdown body); `title_edit_reruns_enrichment`. `tests/similarity.rs`: `rf4_page_create_after_crash_is_flagged` (create, crash after `WRITE_APPROVED`, restart via `Harness::crash_and_restart`, resubmit the same create → Caution "similar to req_… outcome unknown", Approve enabled).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite; `cargo test -j 4 -p atlas-duck-registry --locked`; clippy.
- [ ] **Step 4: Commit** `feat(core): confluence.page.create with space and parent resolution and the duplicate-title warning` (+ trailer), pathspecs `crates/core crates/registry crates/preview`.

---

### Task 17: `confluence.page.move`: parent resolution in the same space, cycle hold, stale rule, path card (I-35 move, I-26 move)

**Model:** Opus (a new stale rule, resolution, a hold). **Reviewer:** Opus (medium).

**Files:**
- Modify: `crates/core/src/ops/confluence_ext.rs` (`PAGE_MOVE_ENRICH`, `page_move_executor`), `crates/core/src/ops/stale.rs` (`PAGE_MOVE`), `crates/core/src/ops/mod.rs` (row: `stale_check: Some(&stale::PAGE_MOVE)`, `enrich_keys: &["parent"]`), `crates/core/src/ops/confluence_preview.rs` (`move_preview` → `PageMove`)
- Modify tests: `crates/core/tests/op_table.rs` (`LATER_WRITES`, `u05_only_writes_have_stale_check`)
- Test: `crates/core/tests/confluence_writes.rs`, `crates/core/tests/reconcile.rs` (add)

**Interfaces:**
- Consumes: Task 16 `resolve_parent`; M3 `content_version`, reconcile hook points.
- Produces: per PD-106.

**Spec:** §7.4 `page.move` ("same space only; keeps title/body"), §5.4 step 5 (`version.number` unchanged), §6.3 Page move ("Old ancestor path → new ancestor path"), §1.3 (cross-space moves non-goal), §13 I-35, I-26, PD-106.

- [ ] **Step 1: Failing tests** (`tests/confluence_writes.rs`): `page_move_sends_ancestors_and_version_plus_one` (wire body `{"id","type":"page","title":<current>,"version":{"number":4},"ancestors":[{"id":"123400"}]}`, no `body` key; 200 JSON → receipt); `i35_move_parent_no_match_and_ambiguous`; `page_move_into_own_subtree_held` (parent's ancestors include the page → `EnrichmentError`, the PD-106 text, plain deny only); `page_move_cross_space_refused` (parent in another space → unresolved); `page_move_stale_when_version_changed` (stale-check GET at a newer version → `WRITE_STALE {changed}`, nothing sent); `page_move_preview_old_and_new_paths`. `tests/reconcile.rs`: `i26_crash_after_stale_check_fetch_is_outcome_unknown_confluence_move` (pattern of the existing transition/update tests).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite; clippy.
- [ ] **Step 4: Commit** `feat(core): confluence.page.move with parent resolution, the version stale rule and the path card` (+ trailer).

---

### Task 18: `confluence.comment.add`

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:**
- Modify: `crates/core/src/ops/confluence_ext.rs` (`COMMENT_ADD_ENRICH`, `comment_add_executor`), `crates/core/src/ops/mod.rs` (row: no stale rule, `enrich_keys: &["body"]`), `crates/core/src/ops/confluence_preview.rs` (`comment_preview` → `ContentWrite`)
- Modify tests: `crates/core/tests/op_table.rs`
- Test: `crates/core/tests/confluence_writes.rs` (add)

**Interfaces:** Consumes Tasks 8, 9, 16 (staged rule shape). Produces per PD-107.

**Spec:** §7.4 `comment.add` (payload verbatim), §5.4 step 5 (rule "none"; the identity call still runs), §6.3, PD-107.

- [ ] **Step 1: Failing tests:** `comment_add_container_type_from_enrichment` (container `blogpost` → `"type":"blogpost"` in the body); `comment_add_reply_to_sets_ancestors`; `comment_add_reply_to_other_content_held` (`UnresolvedName {param: reply_to}`); `comment_add_markdown_converted_constructs_listed` (Markdown body → the card's constructs empty; a storage body with a `toc` macro → `constructs.macros == ["toc"]`); `comment_add_identity_call_runs` (anonymous `user/current` at the pre-write call → `WRITE_STALE {identity_mismatch}`, nothing sent).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite; clippy.
- [ ] **Step 4: Commit** `feat(core): confluence.comment.add` (+ trailer).

---

### Task 19: `confluence.label.add` and `confluence.label.remove`

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:**
- Modify: `crates/core/src/ops/confluence_ext.rs` (`LABELS_ENRICH`, `label_add_executor`, `label_remove_executor`), `crates/core/src/ops/mod.rs` (rows), `crates/core/src/ops/confluence_preview.rs` (`labels_preview` → `WriteSummary`)
- Modify tests: `crates/core/tests/op_table.rs`
- Test: `crates/core/tests/confluence_writes.rs` (add)

**Interfaces:** Consumes Task 8. Produces per PD-108.

**Spec:** §7.4 labels, §1.3 (the only DELETE), §4.2 (labels receipt: only the agent's labels), §7.2 declared success (`label.remove` `{[204], Empty}`), §6.3 labels, PD-108.

- [ ] **Step 1: Failing tests:** `label_add_body_and_receipt_agent_labels` (body `[{"prefix":"global","name":"release"},{"prefix":"global","name":"docs"}]`; receipt `{"labels":["release","docs"]}` even when the server answers with more labels); `label_remove_204_empty_receipt` (DELETE sent only after approval; method guard: no DELETE before `WRITE_APPROVED`); `label_remove_html_body_outcome_unknown` (204 with an HTML body → `outcome_unknown`); `label_cards` (sentences and the already-present/not-present rows).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite; clippy.
- [ ] **Step 4: Commit** `feat(core): confluence.label.add and confluence.label.remove` (+ trailer).

---

### Task 20: `confluence.attachment.upload`: collision hold, replace, deterministic multipart, card; the last write (`WRITES_STILL_LATER` flip)

**Model:** Opus (a binary body under the request-set hash, a hold, a new stale rule). **Reviewer:** Opus (medium); must challenge the provisional PD-110 MIME rule and 2 MiB thumbnail cap (lead ruling Q12).

**Files:**
- Modify: `crates/core/src/ops/confluence_ext.rs` (`ATTACHMENT_ENRICH`, `attachment_upload_executor`, `multipart`, `sniff_mime`), `crates/core/src/ops/stale.rs` (`ATTACHMENT_REPLACE`), `crates/core/src/ops/mod.rs` (row: `stale_check: Some(&stale::ATTACHMENT_REPLACE)` effective only with `replace`, `enrich_keys: &["filename", "replace"]`), `crates/core/src/ops/confluence_preview.rs` (`attachment_preview` → `AttachmentUpload`), `crates/core/src/engine/write.rs` (`edit_form`: the PD-110 `content_base64` rule; receipt projection for `Projection::FirstResultFields`), `crates/core/src/ops/generic.rs` (receipt projection, if it lives there)
- Modify: `crates/registry/src/model.rs`, `crates/registry/src/confluence/writes.rs` (Δ4 b, d)
- Modify tests: `crates/core/tests/op_table.rs` (`LATER_WRITES` becomes empty; `not_in_this_build_writes` asserts it; `u05_only_writes_have_stale_check` gains `confluence.attachment.upload` and `confluence.page.move`), `crates/core/tests/handler.rs` (`WRITES_STILL_LATER = false` as its doc comment prescribes: the picker finds none and the test passes as documented), `crates/core/tests/reconcile.rs` (add)
- Test: `crates/core/tests/confluence_attachment.rs`

**Interfaces:**
- Consumes: Task 8; M3 `Hold::Collision` (the hold exists in the state machine, `lifecycle/model.rs:28`, and keeps its request list, `generic.rs:535`), `validate/caps.rs` (10 MiB), `sha2`, `base64`.
- Produces: per PD-109 and PD-110.

**Spec:** §7.4 `attachment.upload` (new and `replace=true` endpoints, `allowDuplicated=false`, collision → "attachment already exists" preview with Approve disabled, max 10 MiB), §5.4 step 4 ("multipart and binary bodies are stored as base64" in `WRITE_APPROVED`), step 5 (attachment `version.number` unchanged with `replace`), §6.3 Attachment upload, §13 I-06 ("attachment-collision … items … `DECISION_INVALID {not_approvable}`"), PD-109, PD-110.

- [ ] **Step 1: Failing tests** (`tests/confluence_attachment.rs`): `upload_new_multipart_body_deterministic` (two renders of the same params are byte-equal; `content_type == "multipart/form-data; boundary=atlas-duck-<32 hex>"`; the `file` part holds exactly the decoded bytes; URL has `allowDuplicated=false`; `WRITE_APPROVED` stores the body base64 and its `request_set_hash` matches the wire bytes); `upload_boundary_not_in_content` (content that contains the first boundary candidate → `-1` suffix); `upload_filename_with_quote_rejected_exit2`; `i06_attachment_collision_not_approvable_individual_and_batch` (an existing `notes.txt` without `replace` → `Hold::Collision`, card line "attachment already exists", approve → `not_approvable`, a batch with a clean label add → rejected whole, deny → plain `denied` exit 3 (every hint refused)); `upload_replace_uses_attachment_id_data_endpoint` (`POST …/child/attachment/att3001/data`); `upload_replace_without_existing_is_unresolved`; `upload_replace_stale_when_attachment_version_changed` (nothing sent, `WRITE_STALE {changed}`); `upload_card_size_mime_sha256_thumbnail` (a 1×1 PNG → `mime image/png`, SHA-256 hex, a `data:image/png;base64,` thumbnail; a text file → `application/octet-stream`, no thumbnail; a 3 MiB PNG → no thumbnail, the PD-110 text); `upload_receipt_projects_first_result` (answer `{"results":[{…}],"size":1}` → receipt from `results[0]`); `edit_form_content_not_inlined` (the preview's `content_base64` input is read-only with value `null`; the serialized preview holds no base64 of the content); `upload_over_10mib_rejected_exit2` (existing validate test referenced, plus the end-to-end envelope). `tests/reconcile.rs`: `i26_crash_after_stale_check_fetch_is_outcome_unknown_confluence_replace`. `tests/handler.rs`: `not_in_this_build_rejected_internal` with `WRITES_STILL_LATER = false`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite (incl. `handler.rs`, `op_table.rs`, `writes.rs`, `audit_port.rs`); `cargo test -j 4 -p atlas-duck-registry --locked`; clippy.
- [ ] **Step 4: Commit** `feat(core): confluence.attachment.upload with collision hold, replace and a deterministic multipart body; the last Confluence write` (+ trailer), pathspecs `crates/core crates/registry`.

---

### Task 21: Confluence identity and stale sweep; L101; L99/L104 checks

**Model:** Opus. **Reviewer:** Opus (medium).

**Files:**
- Modify: `crates/core/src/identity.rs` (PD-113, L101; lead ruling Q8), `crates/core/src/engine/write.rs` (only where a sweep test shows a deviation; each change named in the report)
- Test: `crates/core/tests/confluence_identity.rs` (add)

**Interfaces:**
- Consumes: M3 `identity::{recheck, Gates}`, `engine/write.rs::identity_call`, `recheck_failed` classes; every Confluence write of Tasks 15–20.
- Produces: tests and the PD-113 change. No new API.

**Spec:** §5.4 step 5 (identity check, re-check failed classes), §7.1, §7.2 origin guard, L99, L101, L104, PD-113.

- [ ] **Step 1: Failing tests:** `i23_confluence_stale_rules_recheck_failed_classes` (table over `page.update`, `page.move`, `attachment.upload` with `replace`: the stale-check GET answers 503, 302, HTML 200, a 33 MiB JSON body and a reset → `WRITE_STALE {recheck_failed, class}` with `http_503`, `redirect`, `non_json`, `too_large`, `network`; nothing sent; `candidate_rev` bumped; approvable again); `confluence_pre_write_identity_anonymous_is_write_stale` (every Confluence write op incl. the rule-"none" ones: anonymous `user/current` at the identity call → `WRITE_STALE {identity_mismatch}`, nothing sent, Approve disabled); `confluence_write_origin_guard_refused_is_recheck_failed_origin_mismatch`; `l99_confluence_identity_call_and_recheck_agree` (the same `user/current` answers — known/same key, known/other key, anonymous, known without `userKey` — give the same verdict through the pre-write identity call and through `identity::judge(Product::Confluence, ..)`); `l101_dropped_recheck_waiter_leaves_no_orphan_start` (a read whose task is aborted while its re-check is in flight → the `token_recheck` start record still gets its result record; a second trigger does not start a second fetch for the same epoch). Re-run `send_one_refuses_an_approved_write` and report it green (L104).
- [ ] **Step 2: Implement** the PD-113 change and any fix a test forces.
- [ ] **Step 3: Run** the core suite (incl. `identity.rs`, `jira_identity.rs`); the atlassian suite; clippy.
- [ ] **Step 4: Commit** `fix(core): Confluence identity and stale sweep; re-check fetches survive dropped waiters (L101)` (+ trailer).

---

### Task 22: X-09 Confluence (generated from the registry), X-10 Confluence gates, I-19 over the new flows

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:**
- Create: `crates/core/tests/x09_confluence.rs`; Modify: `crates/core/tests/common/confluence.rs` (`mount_for_op(mock, spec, params)` with a per-op `Aux` table), `crates/core/tests/common/flows.rs` (I-19 property gains: a Markdown page get with two lookups and the identity GET, a page update with stage 2, a page move, an attachment upload, a label remove)
- Test: as above, plus `crates/core/tests/audit_coverage.rs` :: `i19_every_hit_is_covered` (existing)

**Interfaces:**
- Consumes: `registry::all()` (Confluence ops), `OperationSpec::{params_schema_json, result_example_json, success, endpoint}`, every Confluence `OpImpl`, `jsonschema` (dev), the M5 `x09_jira.rs` structure (`Case`, `SPEC_ENDPOINTS` oracle, `aux_gets` refusal of unknown ops).
- Produces: tests only. Generation rule as M5 T22: params = `examples[0]` (plus variants the first example does not reach: `page.get` with `format: storage` and `format: view`, `page.history` with `version`, `attachment.upload` with `replace: true`, `page.create` with `parent`); the op's endpoint answers its `result_example` (reads) or its declared success (`{[204], Empty}` → 204 empty; `Json` → 200/201 with the receipt example; the upload answer wrapped as `{"results":[…]}`); enrichment, lookup, identity and stale GETs answer bodies taken from the matching **read** op's `result_example` where one exists (`confluence.page.get` for content GETs, `confluence.attachment.list` for the attachment lookup, `confluence.user.current` for the identity GET, `confluence.label.list` for labels), so fixtures cannot drift. A `SPEC_ENDPOINTS` table transcribes §7.4 (18 rows) as the independent oracle.

**Spec:** master plan Table 3 X-09, X-10; §7.2 declared success; §13 I-19 ("Audit coverage"); V06 (Confluence half, wiremock).

- [ ] **Step 1: Failing tests:** `x09_confluence_every_op_once` (all 18 ids + variants; reads released and their `result` validates against `result_schema` (the Markdown body variant validates against the documented exception shape); writes approved, `data.receipt` equals the registry example projection, the declared success shape was the mock's; prints `X09 <op_id> ok` per case; lists every failing case); `x09_confluence_generator_covers_the_registry`; `x09_confluence_writes_wait_for_approval`; `x09_confluence_reads_hold_their_result_until_released`; `x10_confluence_every_op_available_on_floor` (instance at 7.9.0: every Confluence op `available: true`); `x10_confluence_no_version_string_in_envelopes`; `i19_every_hit_is_covered` stays green over the extended flows (lookups, identity GET, stage 2, multipart write: each hit maps to a committed covering record and a response record; `User-Agent` on every hit).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** the core suite; clippy.
- [ ] **Step 4: Commit** `test(core): X-09 Confluence generated from the registry, X-10 Confluence gates, I-19 over the Confluence flows` (+ trailer).

---

### Task 23: SC3 Rust half: the two Confluence scenarios in `perf_sc3`

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:**
- Modify: `crates/core/tests/perf_sc3.rs`, `crates/atlassian/src/testing/fixtures.rs` (a ~5,000-word storage page with headings, lists, a table, two code macros, four mentions and an image; generated from a fixed seed, no file I/O)

**Interfaces:** Consumes M6 `perf_sc3.rs` (`P01_BUDGET` 300 ms, `enforced()`, `within`, `build_and_render`), Tasks 10–12, 15.

**Spec:** §1.4 SC3 ("a ~5,000-word Confluence page", "a small `confluence.page.update` diff"), §13 Performance (P-01), master plan M7 Placements.

- [ ] **Step 1: Write the test** `p01_confluence_page_and_update_diff_under_budget`: `Harness::confluence()`; `confluence.page.get` (default Markdown, users mounted) of the 5,000-word page → `build_and_render(.., "confluence.page.get 5000 words")` (preview build and `render::document` each within `P01_BUDGET` when enforced); `confluence.page.update` with a Markdown body that changes two paragraphs of a short page (`base_version` current) → `build_and_render(.., "confluence.page.update small diff")`; asserts the document shows the page title and the diff's changed line. Debug run prints the numbers.
- [ ] **Step 2: Run locally (debug, not enforced):** `cargo test -j 4 -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked --test perf_sc3 -- --nocapture --test-threads=1` (4 passed). The enforced release run is CI (Task 28).
- [ ] **Step 3: Commit** `test(core): P-01 Confluence page and update-diff scenarios` (+ trailer), pathspecs `crates/core/tests/perf_sc3.rs crates/atlassian/src/testing`.

---

### Task 24: `confluence_flows` over the `cli_flows` harness; the two P-01 webview scenarios

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:**
- Create: `app/src-tauri/tests/confluence_flows.rs` (`#![cfg(feature = "scripted-approver")]`; `#[path = "cli_flows/harness.rs"] pub mod harness;`; `#[path = "confluence_flows/flows.rs"] mod flows;`), `app/src-tauri/tests/confluence_flows/flows.rs`
- Modify: `app/src-tauri/tests/e2e/flows.rs` (`p01`: two more scenarios on a world with a Confluence instance; the helper that provisions it)
- No harness change unless a flow needs a helper; any helper added to `cli_flows/harness.rs` keeps every `cli_flows`/`jira_flows` test compiling and unchanged. No new approver directive is expected (`release`, `approve`, `deny`, `deny-hint` exist); if one is needed, add it to `directive_parsing_table`.

**Interfaces:** Consumes M4 `World` (`provision_store`, `cli`, `mock(alias)`, `audit_records`, `quit_app`, `opted_in`), `MockDc`, Tasks 9–20.

**Spec:** master plan M7 exit criterion (`cargo test -p atlas-duck-app --features scripted-approver --test confluence_flows`), §4.1–§4.3, §13 U-25, I-36, I-06, U-31; §13 Performance (webview half); M6 PD for the e2e P-01 flow.

- [ ] **Step 1: Write the flows** (`flows.rs`, every flow `if !opted_in("<name>") { return Ok(()); }` first; `provision_store(&[("wiki", Product::Confluence)])`; mounts incl. `user/current` known and the user lookups): `confluence_flows_smoke` (`atlas-duck confluence page get 65537 --reason atlas-test:release` → exit 0, `released`, `data.result.body.format == "markdown"`); `md_page_update_sent_as_storage` (`confluence page update 65537 --base-version 3 --body "**done**" --reason atlas-test:approve` → exit 0; the received PUT body's storage value is `<p><strong>done</strong></p>` and `version.number == 4`); `placeholders_rejected_exit2` (`--body "[macro: toc {}]"` → exit 2, `error.code == markdown_placeholders`, nothing queued: `requests list` empty); `page_update_conflict_denied_exit3` (mock at v4, `--base-version 3`, `atlas-test:deny` → exit 3, `denied`); `attachment_collision_denied_exit3` (existing filename, `--content-base64-file <scratch file>` → exit 3); `cql_rewrite_on_the_wire` (`confluence search "space = DOC ORDER BY title" --reason atlas-test:release` → the received `cql` is the rewritten form); `page_get_markdown_released_with_conversion_meta` (`meta.conversion.lossy` present); `label_remove_204_succeeded` (`confluence label remove 65537 --label release` → exit 0, `data.receipt == {}`). E2E `p01`: scenarios `confluence_page_5000_words` (`confluence page get <id>`) and `confluence_page_update_diff`, printed as `P01 <scenario> <ms>`, same budget and rules as the three Jira scenarios. **S-08 rule (lead ruling Q15):** the M6 `s08` sweep (`e2e/flows.rs:909-925`) stays unchanged in M7 (it opens a Jira issue); any future sweep over an attachment preview allows `img[src^="data:image/"]` (the local thumbnail, §6.3/§6.4) and still forbids every other `img` and `[src]`; write that rule as a comment above the `s08` selector list.
- [ ] **Step 2: Run locally only what does not spawn:** `cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --test confluence_flows --no-run`; `cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --test e2e --no-run`; `cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --lib`; a plain `cargo test … --test confluence_flows` without `ATLAS_DUCK_CLI_FLOWS` prints one `skipped:` line per flow and passes. The flows run in CI (Task 28).
- [ ] **Step 3: Commit** `test(app): confluence_flows over the cli_flows harness; P-01 Confluence webview scenarios` (+ trailer), pathspec `app/src-tauri/tests`.

---

### Task 25: Live L-01 tests for the Confluence §15 items (manual, env-gated)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:**
- Create: `crates/core/tests/live_confluence.rs`; Modify: `crates/core/src/testing/harness.rs` (`HarnessBuilder::live` takes the product, or a sibling `live_confluence(url, pat)`; https only, as M5)

**Interfaces:** Consumes `core::testing::Harness` pointing at a real instance (https only, `KeychainCredentials` over `MemKeyStore`, no `allow_http`), the CLI-free handler API.

**Spec:** §13 Live, §15 V04, V06, V23, V25, PD-60 analog (manual; no CI leg), PD-93, PD-95–PD-110 (each probe names the PD it can overturn).

- [ ] **Step 1: Write the tests.** Each is `#[ignore = "manual live run against a real Confluence DC (L-01)"]` and returns `Ok(())` with a printed `skipped: live env not set` unless `ATLAS_DUCK_LIVE_CONFLUENCE_URL` (https), `ATLAS_DUCK_LIVE_CONFLUENCE_PAT` and `ATLAS_DUCK_LIVE_CONFLUENCE_SPACE` (a scratch space) are set; writes only into that space; prints finding lines, never a secret (the PAT never; users as `<configured user>`/`<other>`): `v04_confluence_endpoints_and_cql_rewrite` (comment create payload with `container.type` and reply `ancestors`; `child/comment?depth=all` and whether `extensions.location` arrives without an extra expand (PD-103); `?version=N&status=historical`; the applinks manifest's `Content-Type` under `Accept: application/json`; `excerpt=indexed` and `totalSize`; the rewritten CQL accepted incl. a trailing `ORDER BY`; a PUT with a stale version: 409 or 400 and its message (PD-111, `is_version_conflict`)); `v06_confluence_write_success_shapes` (each Confluence write once: status, `Content-Type`, body emptiness, the upload answer shape `{results: […]}` vs object (Δ4 b), `label.remove` 204 empty; whether `X-AUSERNAME` is present); `v23_confluence_sso_front_classification` (if `ATLAS_DUCK_LIVE_CONFLUENCE_SSO_URL` is set); `v25_confluence_anonymous_fallback_and_header` (with `ATLAS_DUCK_LIVE_CONFLUENCE_BAD_PAT` (a revoked token) set: `user/current` answer type and status, a public page read's status, whether content responses carry `X-AUSERNAME` or another user header — decides PD-93 option C); `v_storage_render_probes` (one scratch page per probe, read back as `body.view`: the PD-95 look-alike escapes render as text; `<s>` renders as strikethrough (PD-96); a code macro whose CDATA holds `]]]]><![CDATA[>` shows `]]>`); `v_page_move_keeps_body` (PD-106: a move without `body` keeps title and body; prints the result); `v_parent_title_lookup` (PD-105: `content?spaceKey&title` matching exact vs case-insensitive); `v_upload_allow_duplicated_and_replace` (PD-109).
- [ ] **Step 2: Run** `cargo test -j 4 -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked --test live_confluence -- --list` (compiles, all listed as ignored). Never run them with `--ignored`.
- [ ] **Step 3: Commit** `test(core): env-gated live Confluence tests for V04, V06, V23, V25 and the converter probes (manual)` (+ trailer).

---

### Task 26: dropped (deferral note only)

Lead ruling Q9: no `GateState::StoreFailed` in M7. The M6 T22 item ("DEFERRED LEAD/M7": agents get no `store_unavailable` answer after a failed store start) stays deferred with no M7 owner; no code, no test, no commit. The number is kept so Tasks 27–30 keep their ids.

---

### Task 27: Docs: SC3 walkthrough and the macOS checklist gain the Confluence scenarios

**Model:** Haiku (effort xhigh). **Reviewer:** Sonnet (medium).

**Files:**
- Modify: `docs/release/sc3-walkthrough.md` (the ~5,000-word page and the small `page.update` diff: what the reviewer opens, which tab, what decides), `docs/release/macos-gui-checklist.md` (one Confluence line per arch: `confluence page get` → release with a redaction; `confluence page update` Markdown → approve; attachment collision → deny)

**Spec:** §1.4 SC3, §13 UI (macOS checklist), M6 T35 structure.

- [ ] **Step 1: Edit** both files in their existing table format; every command spelled out with `--reason`; no product claims beyond the spec.
- [ ] **Step 2: Commit** `docs(release): Confluence scenarios in the SC3 walkthrough and the macOS checklist` (+ trailer `Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>`), pathspec `docs/release`.

---

### Task 28: CI wiring: `confluence_flows` on every GitHub leg, `perf_sc3` count, convert in the Fedora list

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:**
- Modify: `.github/workflows/ci.yml`, `.gitlab-ci.yml` (comment only: `confluence_flows` runs on GitHub only, same reason as `cli_flows`)

**Interfaces:** Consumes the M5 CI structure (`ci/cli-flows-linux.sh` reads `CLI_FLOWS_TEST`; the macOS/Windows `jira_flows` steps at `ci.yml:236-267`; the Rosetta step at `:815-824`; `ci/check-no-skips.mjs`; the "Kill stray atlas-duck-app processes" `always()` steps) and the M6 `perf_sc3` step (`ci.yml:300-309`, which requires `test result: ok\. 3 passed`).

**Spec:** §13 CI row, master plan M7 exit criterion.

- [ ] **Step 1:** New steps "M7 confluence_flows (Linux)" = `CLI_FLOWS_TEST=confluence_flows bash ci/cli-flows-linux.sh`; macOS and Windows copies of the M5 `jira_flows` steps with `--test confluence_flows`, their own log/list/ignored files and `node ci/check-no-skips.mjs … confluence_flows`; the `rust-macos-x86_64-rosetta` job gains the same under `--target x86_64-apple-darwin`. The `perf_sc3` step expects `4 passed`. `core-suite-fedora`'s `cargo test --no-run` line already covers `atlas-duck-convert` (M5); confirm. The feature-leak step is unchanged (no new feature).
- [ ] **Step 2: Local checks:** `bash -n ci/cli-flows-linux.sh` (Git Bash), `node ci/check-workspace.mjs && node --test "ci/*.test.mjs"`, a YAML sanity check with the existing tooling (no new tool). The push is the lead's; record the CI run URL in the report after the lead pushes.
- [ ] **Step 3: Commit** `ci: M7 confluence_flows on every GitHub leg; perf_sc3 Confluence scenarios` (+ trailer), pathspecs `.github .gitlab-ci.yml`.

---

### Task 29: Exit-criterion run and evidence

**Model:** Sonnet (medium). **Reviewer:** none (evidence task; the final review reads it).

**Files:** none changed unless a gate fails (then fix in the owning task's files with a `fix(<crate>):` commit).

- [ ] **Step 1: Locally on Windows** (one command at a time, `-j 4`):

```bash
cargo test -j 4 -p atlas-duck-convert -p atlas-duck-preview -p atlas-duck-registry --locked
cargo test -j 4 -p atlas-duck-atlassian -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked
cargo test -j 4 -p atlas-duck-convert -p atlas-duck-core --locked
cargo test -j 4 --workspace --locked
cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --test confluence_flows --no-run
cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --test jira_flows --no-run
cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --test cli_flows --no-run
cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --test e2e --no-run
cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --lib
cargo test -j 4 -p atlas-duck-app --locked --test dto_fixtures
cargo clippy -j 4 --workspace --all-targets --locked -- -D warnings
cargo clippy -j 4 -p atlas-duck-atlassian -p atlas-duck-core --all-targets --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked -- -D warnings
node ci/check-workspace.mjs && node ci/check-no-panic-macros.mjs && node --test "ci/*.test.mjs"
npm --prefix app/ui run lint && npm --prefix app/ui run test && npm --prefix app/ui run build
cargo tree -p atlas-duck-app -e normal,build --target all --locked --format "{p} [{f}]" --prefix none
```

Expected: every command exits 0; the tree's bracketed feature lists contain none of `testing|insecure-test-http|test-paths|test-env|scripted-approver`. `cargo build -j 4 -p atlas-duck-app --release --locked` once (record the time; the binary is not run).
- [ ] **Step 2: CI** on GitHub (GitLab for the non-flow jobs): `rust` (Windows MSVC, macOS arm64, Ubuntu 22.04) green incl. `cli_flows`, `jira_flows` and `confluence_flows` with no skips; the enforced `perf_sc3` run (`4 passed`); `rust-macos-x86_64-rosetta`, `core-suite-fedora`, `supply-chain` (`cargo deny`/`cargo audit` over the new `quick-xml`/`htmd` tree), `ui`, `bundle`, `e2e` (P-01 lines for the five scenarios) green. Record run URLs, the commit SHA, the 18 `X09 … ok` lines and the `P01 …` lines in the task report and in `.superpowers/sdd/2026-10-16-atlas-duck-m07-confluence-adapter/progress.md`.
- [ ] **Step 3: Live items:** list for the lead that `live_confluence.rs` (V04, V06, V23, V25 and the probes) awaits a human run; the exit criterion's live L-01 part is not satisfiable by agents (L96 analog).
- [ ] **Step 4:** Ask the lead to update the master plan M7 `Status:` after the final review and to apply the ledger entries.

---

### Task 30: Final whole-branch review

**Model:** Opus (medium; read-only review; fixes go to a Sonnet/Opus fix round per finding).

**Scope:** `master..m7-confluence-adapter`. Re-check Review Focus 1–5 against the code and their tests; §5.1 inv. 1 on every new GET (stages, lookups, identity, historical body) and on the multipart write; opacity of every new envelope path (no resolution facts, collision facts, duplicate titles, lossy counts or user names outside chosen deny hints and released results); determinism of executors (`WRITE_APPROVED` hash vs wire, incl. the multipart boundary) and of read candidates (rebuild from the committed map); escaping and both checks (try to construct a Markdown input that yields an unrecorded construct in storage, or a look-alike that fails the round trip; read the proptest strategy for blind spots); the RF-5a step as built against PD-93 (lead ruling Q1 = A); every fixed string verbatim with its doc comment; no new `tracing` field with content; the traceability table (every row's tests exist and are not vacuous); the CI wiring (`confluence_flows` on every leg, no-skip checks, the perf count). Output `.superpowers/sdd/2026-10-16-atlas-duck-m07-confluence-adapter/final-review.md` in the M5/M6 format (Evidence, Critical, Important, Minor, deferred-items decisions, verdict).

---

## Execution order and dependencies

All cargo work is sequential (one cargo process at a time); tasks marked "parallel-safe" may be implemented while another task's cargo runs only if they edit disjoint files and wait for the cargo slot before compiling.

```
T1 ─► T2 ─► T3 ─┬─► T4 ─┐
                └─► T5 ─┴─► T6 ─► T7
T8 (preview; needs only T1 for the workspace build; parallel-safe with T2–T7)
T4,T5,T6 ─► T9
T3,T8 ─► T10 ─► T11 ─► T12 ─► T13
T14 (atlassian paginate + core tests; parallel-safe after T10 created tests/common/confluence.rs)
T7,T8,T9 ─► T15
T8,T9 ─► T16 ─► T17 (resolve_parent)
T9,T16 ─► T18
T8 ─► T19
T15..T19 ─► T20 (the last write: flips WRITES_STILL_LATER)
T13,T20 ─► T21
T11,T13,T20 ─► T22
T12,T15 ─► T23
T20 ─► T24 ─► T28
T20 ─► T25
T26 (dropped, lead ruling Q9)
T23,T24 ─► T27 (docs; no cargo)
all ─► T29 ─► T30
```

No task waits on a lead answer (all settled in "Lead rulings (2026-10-16)"). Two items stay open for live evidence only: the `page.move` body (V-item, Task 25 `v_page_move_keeps_body`) and the htmd duplicate condition (CI `supply-chain` after Task 1, only if a new `html5ever` copy is needed).

---

## Self-review checklist (run before handing the plan to implementers)

- Every row of the Traceability table names a task that lists that test in its Step 1 (U-23 T03/T05/T07; U-24 T06/T09; U-25 T04/T06/T09; U-28 T12; U-31 T12 + existing; U-34 T12/T08; I-06 T15/T20; I-22 T14; I-26 T17/T20 + existing; I-32 T15 + existing; I-35 T16/T17; I-36 T15; I-37 T11; X-09/X-10 T22; S-12 T07/T12/T15; RF-5a T13; P-01 T23/T24; L-01 T25; `confluence_flows` T24; flip T20; U-33 T09; M-4 T05; minors 7/8 T15/T14; M6 M-5 T08/T15; L101 T21; L99/L104 T21; I-19 T22).
- No task depends on a later task's code, except: Task 8's compile fix of `Conflict` literals in core (filled with real values by Task 15 for Confluence); Task 10 commits an empty `user_resolutions` map until Task 11 fills it (the rebuild contract holds at each step); Task 12's `unresolved_mention` Info is exercised once Task 11 exists (Task 12 runs after Task 11).
- Contract deltas Δ1–Δ5 are applied to the master plan before Task 1 (Δ6 dropped, Q9); the ledger entries are recorded before the tasks that implement them merge (T03: PD-95 entry; T05: PD-96; T06: PD-97; T04: PD-98; T11: PD-99; T10: PD-100; T12: PD-101, PD-102, PD-103; T13: PD-93, Δ5; T15: PD-104, PD-111; T16: PD-105; T17: PD-106; T20: PD-109; T21: PD-113; T25: the live-status entry).
- Security-critical or complicated tasks run on Opus with Opus reviewers: T02, T03, T05, T06, T08, T09, T10, T11, T13, T15, T16, T17, T20, T21 (+ T30).
- Nothing asks an implementer to run an installer, download a tool or executable, change an ACL or the registry, kill a process, write outside the repo/scratchpad, start the app or `tauri-driver`, run the spawning `cli_flows`/`jira_flows`/`confluence_flows`/`e2e` flows locally, or run the live tests.
- Existing M3/M5/M6 behaviour is re-used, not rebuilt (section "What exists for Confluence"): CQL rewrite, `version.number = base + 1`, `VersionConflict`, the Confluence identity judge and pre-write identity call, the canonical match form, client-level context-path paging, the staged enrichment driver, `Hold::Collision`, the generic edit form, `preview::render`, `perf_sc3`, the `cli_flows` harness, `send_one`'s refusal (L104).
- Every PD that the spec leaves open is either a ledger entry or settled under "Lead rulings (2026-10-16)"; the provisional texts (PD-95 known-macro list, PD-102 `cql_broad`, PD-110 MIME and thumbnail cap) are challenged by the reviewers of Tasks 3, 12 and 20; no PD invents a fact about Confluence DC behaviour without naming the live probe that confirms it (Task 25).

---

## Handoffs (to later milestones)

- **M8:** the script host-call path already resolves users and commits the map in `SCRIPT_CALL` (Task 11, fake runner); M8 runs it with the real runner and adds the RF-5a identity step for Confluence host calls (PD-93: once per host call, or once per run before `SCRIPT_FINISHED` — M8 decides, ledger first); `k` is measured on Confluence storage-body fixtures: the Task 23 5,000-word page and the Task 3 goldens are the inputs; I-37 scripts half; M3 M-1 and M5 M-13 unchanged (L101 is closed in M7, Q8).
- **M9:** one MCP tool per registry op includes the 18 Confluence ops (`confluence_page_get`, …); L81 (launch-stub wait) moves to M9 as the next owner of the launch path (lead ruling Q14).
- **M10:** the canary sweep covers the Confluence channels (user lookups, the identity GET, Markdown conversion, multipart bodies in `WRITE_APPROVED`); the onboarding page carries the PD-112 sentences (the §12.4 placeholder sentence is already verbatim there).
- **Live (human):** run `crates/core/tests/live_confluence.rs` once against a real Confluence DC 8.5/9.x and hand the printed V04/V06/V23/V25 and probe lines to the lead (possible changes: PD-93 option C (a new lead decision), PD-103 location expand, PD-105 title matching, PD-106 move body (the V-item of Q4), PD-109 upload answer and `allowDuplicated`, PD-111 conflict status, PD-96 `<s>`).

---

## Ledger entries the lead adds (from L136; L120–L135 are taken by `a8a6dc2`)

- **L136** (PD-93, RF-5a, §7.2, §15 V25; lead ruling Q1 = A) Confluence direct reads end with one `GET /rest/api/user/current` under the request cover, after the last page and the user lookups, recorded `PREVIEW_FETCH {purpose: identity}` (§8.3 purpose added); a non-match is handled like a failed Jira header check (body audit-only, `token_recheck`, effect table: `needs_token` exit 9 / `upstream_unavailable` exit 6). A header check (option C) needs a new lead decision if the live V25 run finds an equivalent header.
- **L137** (PD-95, §7.6) storage→Markdown mapping: placeholder grammar `[macro: <name> {k=v, …}]`, `confluence:<space>/<title>`, `confluence:attachment/<file>`, `confluence:url/<url>` for `ri:url` images, `@user:<key>`, layouts flattened and counted, unknown `ac:`/`ri:` elements as macro placeholders; the known-macro list; look-alike escaping of `[macro:` and `@user:` anywhere.
- **L138** (PD-96, §7.6) Markdown→storage: element set, code macro with CDATA split, links only for http/https/mailto, images as links, task items as plain text, no named entities.
- **L139** (PD-97, §7.6) The storage hard check also fails on any `ac:`/`ri:` element outside a recorded code macro, any element outside the converter's set, and an `<a href>` with another scheme; `ConstructKind` gains `link` and `markup`.
- **L140** (PD-98, §7.6) Placeholder grammar and the order of `details.placeholders`.
- **L141** (PD-99, §7.6) User resolution: per-instance cache (1 h, 10 000 entries), at most 50 fresh lookups per read, lookups share the limiter, control and read budget, a failed lookup is `null` and never fails the read, no resolution for `storage`/`view`/comments/write previews.
- **L142** (PD-100, §7.4) `format=view` expands `body.view` with the Caution; `page.history` ignores `format` without `version`.
- **L143** (PD-101, §7.4; lead ruling Q7) `confluence.search` results are pruned to the §7.4 release list (registry example and schema follow).
- **L144** (PD-102, §6.2) `cql_broad` trigger rule (provisional until the Task 12 review, Q11).
- **L145** (PD-103, §6.3; lead ruling Q5) `comment.list` releases storage; the preview renders locally and threads by `ancestors`; location from `extensions.location` when sent.
- **L146** (PD-104, §6.2, §7.6; lead ruling Q10) `page.update` stage-2 base body; the lossy Caution text gains ", L layouts" when layouts are lost (§6.2 amendment); raw-only count over `storage_lines` without the M5 invisible-change refinements (L90 residual).
- **L147** (PD-105, §5.4 step 2, §6.2; lead rulings Q2, Q3) Space and parent resolution for `page.create` (parent by id or title; a title matching more than one page is the I-35 ambiguous case); duplicate title is the new Caution `duplicate_title` "a page titled '<title>' already exists in <space>" with Approve enabled.
- **L148** (PD-106, §7.4; lead ruling Q4) `page.move` sends title, version + 1 and ancestors without the body; the live probe `v_page_move_keeps_body` decides (a §15 V-item the lead adds); a move under the own subtree is held; parent outside the page's space is unresolved.
- **L149** (PD-109, PD-110, §7.4, §6.3) Attachment upload: collision = `Hold::Collision`, plain deny; `replace` needs exactly one existing attachment (`/data` endpoint, version stale rule); deterministic multipart boundary from the content hash; refused filename characters; MIME by magic bytes; thumbnail ≤ 2 MiB images only (MIME rule and cap provisional until the Task 20 review, Q12); `content_base64` not inlined in the edit form; receipt from `results[0]`.
- **L150** (PD-111, M3 T10 minors 7, 8) A truncated Confluence 400 stays `WRITE_FAILED`; an absent `_links.next` ends paging.
- **L151** (PD-113, L101; lead ruling Q8) Re-check fetches run in their own task; a dropped waiter cannot orphan a `token_recheck` start. Closes L101 in M7.
- **L152** (L104) Closed: `send_one` refuses `Target::Approved` (M5 fix round; re-checked in M7 T21).
- **L153** (L99) Confluence's pre-write identity call and re-check apply the same rule (`type == "known"` + stored `userKey`); only the Jira key-only case remains open.
- **L154** (§13 Live, §15) The Confluence L-01 tests are manual; V04, V06 (Confluence), V23 (Confluence), V25 (Confluence) and the `page.move` body V-item are design-resolved only until a human run.

Updates to existing entries: **L81** owner → M9 (lead ruling Q14). The M6 T22 StoreFailed item stays deferred with no M7 entry (Q9).

---

## Spec-silent items for the lead (summary)

PD-93 (RF-5a), PD-95 (storage→Markdown mapping details), PD-96 (Markdown→storage mapping), PD-97 (hard-check strictness), PD-98 (placeholder grammar), PD-99 (user-resolution fetch policy), PD-100 (`view` expand, history without `version`), PD-101 (search pruning), PD-102 (`cql_broad` rule), PD-103 (comments release form), PD-104 (lossy text with layouts), PD-105 (parent by title, `duplicate_title` level and text), PD-106 (move body), PD-109 (multipart, replace semantics), PD-110 (MIME, thumbnail cap, edit-form rule), PD-111 (minor 7 accepted), PD-113 (L101 in M7), Δ5 (`identity` purpose). All are settled by the rulings below except the provisional texts of Q11/Q12 and the live V-items.

---

## Lead rulings (2026-10-16)

The lead answered the fifteen plan questions on 2026-10-16; the task texts above follow these rulings.

1. **RF-5a:** option A. One `GET /rest/api/user/current` after each read fetch, recorded (`PREVIEW_FETCH {purpose: identity}`). PD-93, Task 13, L136.
2. **`parent` by id or title:** both accepted; an ambiguous title is the I-35 ambiguous case. Δ4 a, PD-105, Tasks 16/17, L147.
3. **`duplicate_title`:** a Caution; Approve stays enabled. PD-105, L147.
4. **`page.move` body:** sent without `body`; the live probe `v_page_move_keeps_body` decides, recorded as a §15 V-item. PD-106, Task 25, L148.
5. **`comment.list`:** releases storage. PD-103, L145.
6. **`htmd`:** Task 1 pins the `htmd` version whose `html5ever` matches one already in `Cargo.lock`, if one exists; otherwise the duplicate is accepted only if `cargo deny` passes with no new ignores, and the compile-time cost is noted. No in-house converter. "Dependency pins", Task 1.
7. **Search:** pruned to the §7.4 release list. PD-101, L143.
8. **L101:** M7 owns it (re-check fetches are spawned). PD-113, Task 21, L151.
9. **StoreFailed:** not in M7. Task 26 is a deferral note only; Δ6 dropped.
10. **Lossy text:** append ", L layouts". PD-104, L146.
11. **`cql_broad` trigger and the known-macro list:** the plan texts stay provisional; the reviewers of Tasks 12 and 3 must challenge them.
12. **Attachment MIME and thumbnail cap:** the plan texts stay provisional; the Task 20 reviewer must challenge them.
13. **Reviewer models:** the default holds: Opus reviews Opus tasks, Sonnet reviews the rest.
14. **L81:** owner M9.
15. **S-08 and the thumbnail:** accepted. Future sweeps over an attachment preview allow `img[src^="data:image/"]`; noted in Task 24 (and Task 8).

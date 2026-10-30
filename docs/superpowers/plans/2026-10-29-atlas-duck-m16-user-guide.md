# atlas-duck M16 (User guide) Implementation Plan

> **Draft status:** draft, written 2026-10-29 against the M15 branch `m15-german-ui` (worktree `C:\Code\atlas-duck-m15`), to be rebased on `master` after M15 merges; not yet reviewed. Numbering: M15 claims PD-291..PD-320 and L291–L310; M16 claims **PD-321..PD-340** and ledger entries **L311–L325**.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. One implementer subagent per task, one reviewer after each task.
>
> **Model policy (memory `subagent-model-preference`; never Fable):** Sonnet for every task and reviewer; Opus only for the final whole-branch review (Task 12).
>
> **Hard execution limits (memory `agent-execution-limits`):** no agent downloads or runs executables or installers, runs `npm install`/`npm ci`/`cargo install`, or starts `atlas-duck-app`/`atlas-duck-server`. Locally allowed: `npx vitest run`, `npx tsc --noEmit`, `npx eslint`, `node ci/*.mjs`, `node --test`, `cargo check|clippy|test|run -p atlas-duck-docgen --locked -j 4` (the generator is our own workspace bin, built from source; one cargo process at a time, shared scratch `CARGO_TARGET_DIR`, memory `disk-usage-target-dir`). Worktrees: junction `node_modules` per memory `ui-gates-in-worktree`.
>
> **Shell:** PowerShell; edit with the Edit/Write tools, never `Get-Content | Set-Content` (memory `powershell-utf8-rewrite`); German guide text has umlauts, every file stays BOM-less UTF-8. Commit with `git commit -F <file>`.

**Goal:** Ship the **User guide** (CONTEXT.md) in English and German: written once as Markdown, generated into a desktop set (opened offline in its own Help window) and a server set (public under `/docs/<lang>/…`), with search, a language switch on every page, "?" links from every UI page, and CI that proves both languages, the error reference and all links are consistent.

**Architecture:** Sources in `docs/user-guide/{en,de}/**/*.md` with front matter. A new workspace bin crate `crates/docgen` (`atlas-duck-docgen`, depends only on the existing `pulldown-cmark`) renders them into static HTML plus one generated `search-index.js` per set and language, into committed output directories `app/ui/public/help/` (desktop; Vite copies `public/` into `dist/`) and `app/ui/public-server/docs/` (server; `vite.server.config.ts` gets `publicDir: 'public-server'`). Output is committed so neither the Tauri build nor the Dockerfile's node-only `ui` stage needs cargo; CI runs `atlas-duck-docgen --check` (regenerate in memory, byte-compare). The page JS (`help.js`: search, language switch, anchor scroll) and CSS are static files beside the HTML, no inline script or style. Desktop: an eighth window label `help` with a capability that grants no app command; a new command `help_open { page, anchor }` granted to the seven existing labels opens/focuses it. Server: a fixed, validated route `/docs/{lang}/{page}` plus `/docs/{lang}/assets/{name}` in `static_files.rs`, public (no session), same CSP, `Cache-Control: no-cache`.

**Tech Stack:** Rust 1.95.0, pulldown-cmark 0.13.5 (existing), axum 0.8.9, Tauri 2 (existing), React 19.3.0, TypeScript 5.9.3, Vite 8.3.3, Vitest 5.0.3, node `ci/*.mjs`. **No new npm package and no new `[[package]]` in `Cargo.lock`** (the new crate is a workspace member, not a registry package).

**Spec:** master plan `docs/superpowers/plans/2026-10-07-atlas-duck-master-plan.md` "### M16 — User guide" (design interview 2026-10-28, decisions final). Glossary `CONTEXT.md` ("User guide", "Operations docs"); German terms `GLOSSARY.md` / `app/ui/src/shared/i18n/de/terms.ts` (M15). Earlier plans: M6 (window registry PD-72, CSP), M12/M14 (static files PD-220, server pages), M15 (i18n, language settings, `check-i18n.mjs`).

---

## What exists (survey of `m15-german-ui`)

| Area | Now | M16 |
|---|---|---|
| Desktop assets | `app/src-tauri/tauri.conf.json` `frontendDist: ../ui/dist`, CSP `default-src 'self'; script-src 'self'; style-src 'self' 'sha256-…' …; connect-src ipc: http://ipc.localhost` (checked by `ci/check-csp.mjs`) | help pages under `dist/help/<lang>/`; `connect-src` does **not** allow `fetch` of a JSON file, so the search index is a generated `.js` loaded by `<script src>` (PD-324) |
| Windows | `app/src-tauri/src/windows.rs`: seven fixed labels, `TITLES: [(Label, T); 7]`, Rust builds every window; one capability file per label in `app/src-tauri/capabilities/*.json`; `ci/check-commands.mjs` pins `LABELS` and the command surface | label `help`, `capabilities/help.json`, command `help_open` (T5) |
| Server static | `crates/server/src/static_files.rs`: fixed `PAGES` table, `/assets/{name}` with `valid_asset_name`, `CSP` (PD-220), `no-store` HTML, `immutable` assets; routed in `crates/server/src/web/mod.rs:243-308` | `/docs/{lang}/{page}` + `/docs/{lang}/assets/{name}` (T6) |
| Server image | `crates/server/Dockerfile`: `ui` stage `npm run build:server` → `COPY --from=ui /src/app/ui/dist-server/ /app/web/`; GitLab `server:image` (kaniko) | `dist-server/docs/` rides along unchanged; chart unchanged |
| UI builds | `app/ui/vite.config.ts` (desktop, `dist/`), `app/ui/vite.server.config.ts` (`web/*.html` → `dist-server/`) | server config gets `publicDir: 'public-server'` |
| Markdown | `pulldown-cmark` `=0.13.5` in workspace deps, used by `crates/convert` | reused by `crates/docgen` |
| Workspace policy | `ci/check-workspace.mjs`: per-crate allowed internal deps | entry `{ pkg: docgen, allowed: [] }` |
| Menus | desktop `app/ui/src/shared/Header.tsx`; server `app/ui/src/server/shell/ServerHeader.tsx`, `app/ui/src/server/login/Login.tsx` | "Help"/"Hilfe" entry, "?" links (T7, T8) |
| Error codes | `ci/check-i18n.mjs` already parses `ErrorCode::ALL` (`crates/ipc/src/envelope.rs`), server `ApiError` codes (`crates/server/src/errors.rs`), `DecisionError`, `BatchFailure` | exported parsers reused by `ci/check-user-guide.mjs` (T3) |
| Screenshots | no Playwright; desktop e2e is `tauri-driver` + `ci/e2e-drive.py` on a debug bundle (`.github/workflows/e2e-bundle.yml`); server e2e is black-box HTTP | **no screenshots in M16** (allowed by the master plan; PD-330) |

---

## Global Constraints

- Languages `en`, `de`; same page ids, same file paths, same heading anchors in both (PD-321).
- Front matter (PD-322), between `---` lines, flat `key: value`: `id` (kebab, unique, = file stem), `title`, `mode: desktop|server|both`, `order` (integer). Anchors are explicit `{#anchor}` heading attributes (pulldown-cmark `ENABLE_HEADING_ATTRIBUTES`), never derived from German text, so both languages share them.
- Mode blocks inside a `both` page: fenced `::: desktop` / `::: server` / `:::` lines, stripped for the other set (PD-323).
- Generated HTML: no inline `<script>`/`<style>`/`style=`/`on*=` attributes; raw HTML in Markdown is rejected by the generator (error, not escape). Links: internal `[text](page-id#anchor)` only; `http(s)` links get `rel="noreferrer"`.
- Search (PD-324): `search-index.js` defines `window.ATLAS_HELP_INDEX = [...]` (page, anchor, title, heading, ~200-char text); `help.js` ≤ 8 KB unminified, plain substring/token match, no library. Without JS, the table of contents and an index page work.
- The guide contains no user data; server `/docs` is public and needs no session (PD-325).
- Language: desktop opens `help/<resolved lang>/…` from the M15 setting (Rust resolves `auto`); server pages link to `/docs/<lang>/…` from the current `useLang()`; every guide page has a switch link to the same page and anchor in the other language.
- German uses "Sie" and the M15 glossary terms; no human review (user decision). CLI, MCP tool names, codes, op ids stay verbatim.
- Generated output is committed; `atlas-duck-docgen --check` fails CI on drift (PD-326).

## Review Focus

1. CSP regressions: a generated page with inline script/style is blocked silently in the app → T2 test `no_inline_script_or_style` over all output; T6 asserts `/docs/...` responses carry `static_files::CSP`.
2. Path traversal on `/docs/{lang}/{page}` → `lang ∈ {en,de}`, `page` matches `[a-z0-9-]+(\.html)?` and must be in the generated manifest; T6 tests `..`, encoded `%2e%2e`, backslash, unknown lang.
3. The `help` window gaining IPC power → `capabilities/help.json` has no app permission; `check-commands.mjs` asserts it; T5 test.
4. Anchors drifting between languages or UI "?" links pointing at missing anchors → T3 checks.
5. Desktop set leaking server-only pages (OAuth, admin) or vice versa → T2 test on the manifest per mode.

---

## File structure

- Create: `crates/docgen/{Cargo.toml,src/main.rs,src/frontmatter.rs,src/render.rs,src/search.rs,src/tests.rs}`; `docs/user-guide/{en,de}/*.md`; `docs/user-guide/assets/{help.css,help.js}`; `docs/user-guide/ui-links.json` (UI page → page#anchor, PD-327); `ci/check-user-guide.mjs` + `.test.mjs`; `app/src-tauri/capabilities/help.json`; `app/src-tauri/src/commands/help.rs`; `app/ui/src/shared/HelpLink.tsx`.
- Generated (committed): `app/ui/public/help/{en,de}/…`, `app/ui/public-server/docs/{en,de}/…`.
- Modify: `Cargo.toml` (member), `ci/check-workspace.mjs`, `ci/check-commands.mjs`, `ci/check-control-bytes.mjs` (cover `docs/user-guide`), `app/src-tauri/src/windows.rs`, `app/src-tauri/src/commands/mod.rs`, `crates/server/src/static_files.rs`, `crates/server/src/web/mod.rs`, `app/ui/vite.server.config.ts`, headers/login, `.github/workflows/ci.yml`, `.gitlab-ci.yml` (`node:ci-checks`, `rust:test`), `CONTEXT.md`, master plan.

---

### Task 1: Guide skeleton and page inventory

**Files:** `docs/user-guide/{en,de}/*.md`, `docs/user-guide/ui-links.json`

- [ ] Create the page set with front matter and headings with `{#anchor}` only (bodies `TODO` placeholders, rejected later by T3 once content tasks land): `index` (both), `getting-started-desktop` (desktop), `getting-started-server` (server), `instances-and-tokens` (both), `agents-desktop` (desktop), `agents-server` (server: API keys, OAuth/connected apps), `approvals` (both), `scripts` (both), `audit` (both: audit log, export, `verify-export`), `settings` (both, incl. language), `admin` (server), `auditor` (server), `troubleshooting` (both), `error-reference` (both; sections `{#err-<code>}` per mode).
- [ ] `ui-links.json`: every desktop window label and every server `PAGES` path → `page#anchor`.
- [ ] Commit `docs(user-guide): page inventory and anchors (M16 T1)`.

### Task 2: Generator crate `atlas-duck-docgen`

**Files:** `crates/docgen/**`, `Cargo.toml`, `ci/check-workspace.mjs`, `docs/user-guide/assets/*`

- [ ] Write failing tests in `src/tests.rs`: `front_matter_parses_and_rejects_unknown_keys`, `mode_blocks_are_stripped_per_set`, `heading_attributes_become_ids`, `raw_html_is_an_error`, `internal_link_resolves_to_relative_href`, `no_inline_script_or_style` (scan output for `<script>` without `src`, `<style`, ` style=`, ` on[a-z]+=`), `desktop_set_excludes_server_pages`, `output_is_deterministic` (two runs byte-equal, sorted iteration, no timestamps).
- [ ] Run `cargo test -p atlas-duck-docgen --locked -j 4` → FAIL.
- [ ] Implement: `main` takes `--src docs/user-guide --desktop-out app/ui/public/help --server-out app/ui/public-server/docs [--check]`; per set/lang: page template (header with set title, language switch to the same page in the other language, search box, TOC sidebar sorted by `order`), `index`, `search-index.js`, `manifest.json` (pages + anchors, used by T3 and T6), copies `help.css`/`help.js` into `<lang>/assets/`. Desktop links relative (`page.html#a`), server links `/docs/<lang>/page#a`. `--check` exits 1 listing differing files.
- [ ] `help.css` takes the app's colour/typography tokens (copied values, not an import across the build); `help.js` search over `window.ATLAS_HELP_INDEX`, results as links, ≤ 8 KB.
- [ ] Workspace member + `check-workspace.mjs` entry `allowed: []`; `node --test ci/check-workspace.test.mjs` green.
- [ ] Tests PASS; `cargo clippy -p atlas-duck-docgen --locked -- -D warnings`; generate and commit output. Commit `feat(docgen): Markdown to static help sets (M16 T2)`.

### Task 3: `ci/check-user-guide.mjs` and CI wiring

**Files:** `ci/check-user-guide.mjs`, `ci/check-user-guide.test.mjs`, `ci/check-control-bytes.mjs`, `.github/workflows/ci.yml`, `.gitlab-ci.yml`

- [ ] Tests first (`node --test`), one fixture each: `missing_page_in_de_fails`, `anchor_set_differs_fails`, `error_code_without_entry_fails`, `entry_without_error_code_fails`, `ui_link_target_missing_fails`, `ui_page_without_link_fails` (every label in `check-commands.mjs` `LABELS` except `help`/`credential`, every server `PAGES` path except `/oauth/consent`), `broken_internal_link_fails`, `todo_placeholder_fails`.
- [ ] Implement by importing `parseEnvelopeCodes`/`parseServerCodes`/… from `ci/check-i18n.mjs`; read `manifest.json` of both sets. Add `docs/user-guide/**` to the control-byte scan.
- [ ] Wire: GitHub `ui` job and GitLab `node:ci-checks` run `node ci/check-user-guide.mjs`; GitHub/GitLab Rust jobs run `cargo run -p atlas-duck-docgen --locked -- --check …`.
- [ ] Commit `ci: user guide consistency checks (M16 T3)`. (The check is expected red until T9–T11 fill content and T7/T8 add links; land T3 with `--allow-todo` used only on the branch, removed in T12.)

### Task 4: Content — getting started, instances & tokens, settings (en + de)

- [ ] Write `index`, `getting-started-desktop`, `getting-started-server`, `instances-and-tokens`, `settings` in English, then German (Sie, glossary terms). Facts from `docs/server/` and the UI text modules, not invented. Regenerate, `node ci/check-user-guide.mjs`. Commit.

### Task 5: Desktop Help window

**Files:** `app/src-tauri/src/windows.rs`, `app/src-tauri/capabilities/help.json`, `app/src-tauri/src/commands/help.rs`, `commands/mod.rs`, `ci/check-commands.mjs` (+ test), `app/src-tauri/src/i18n.rs` (title)

- [ ] Tests first: Rust `help_url_uses_resolved_lang` (`auto` + OS `de-DE` → `help/de/approvals.html#…`), `help_open_rejects_unknown_page_or_anchor` (validated against the bundled desktop `manifest.json`, `include_str!`), `help_window_reuses_existing`; `check-commands.test.mjs`: `help_capability_has_no_app_permission`, `help_open_granted_to_all_other_labels`.
- [ ] Implement label `Help` (TITLES 8 entries, de "Hilfe"), `WebviewUrl::App("help/<lang>/<page>.html#<anchor>")`, focus-and-navigate if open; capability `help.json` with `core:default` window basics only. Help window navigation stays inside `help/` (existing navigation guard from M6 extended to the label).
- [ ] Tray menu entry "Help"/"Hilfe" (M15 table). `cargo test -p atlas-duck-app --locked -j 4`, `node --test ci/check-commands.test.mjs`. Commit.

### Task 6: Server `/docs` routes

**Files:** `crates/server/src/static_files.rs`, `crates/server/src/web/mod.rs`, `crates/server/src/web/tests/mod.rs`, `app/ui/vite.server.config.ts`

- [ ] Tests first: `docs_page_served_without_session`, `docs_headers` (CSP = `static_files::CSP`, `nosniff`, `no-referrer`, `Cache-Control: no-cache`), `docs_rejects_traversal_and_unknown_lang` (`/docs/fr/index`, `/docs/en/..%2fadmin`, `/docs/en/a\\b`), `docs_root_redirects_to_lang` (`/docs` → `/docs/en/` via `Accept-Language` `de*` → `/docs/de/`), `docs_assets_validated`.
- [ ] Implement: routes `/docs`, `/docs/{lang}/`, `/docs/{lang}/{page}`, `/docs/{lang}/assets/{name}`; page names checked against the `manifest.json` read at startup from `ATLAS_DUCK_WEB_DIR/docs/<lang>/`. Route is outside the session middleware and the CSRF origin guard (GET only). `publicDir: 'public-server'` in the server Vite config; confirm `dist-server/docs/` appears after `npm run build:server` (no Dockerfile change).
- [ ] `cargo test -p atlas-duck-server --locked -j 4 web::`. Commit.

### Task 7: Desktop "Help" and "?" links

**Files:** `app/ui/src/shared/HelpLink.tsx` (+ test), `app/ui/src/shared/Header.tsx`, window pages, `app/ui/src/shared/i18n/{en,de}`

- [ ] Tests first: `HelpLink` calls `help_open` with page/anchor from `ui-links.json` (imported at build time); header shows "Hilfe" in `de`.
- [ ] Add "Help" to the desktop header of every window and "?" next to the sections listed in `ui-links.json`. `npx vitest run`, `npx tsc --noEmit`, `node ci/check-i18n.mjs`. Commit.

### Task 8: Server "Help" header entry, login link, "?" links

**Files:** `app/ui/src/server/shell/ServerHeader.tsx`, `app/ui/src/server/login/Login.tsx`, server pages, `HelpLink` server variant (plain `<a href="/docs/<lang>/<page>#<anchor>" target="_blank" rel="noreferrer">`)

- [ ] Tests first: login page links `/docs/<lang>/getting-started-server`; header "Help" in both languages; each server page has a link resolving through `ui-links.json`. Implement, run gates, commit.

### Task 9: Content — agents (desktop launcher; server API keys + OAuth), approvals, scripts (en + de)

- [ ] Write `agents-desktop`, `agents-server`, `approvals`, `scripts`; anchors referenced from `ui-links.json`. Regenerate, check, commit.

### Task 10: Content — audit & export/verify, admin and auditor pages (en + de)

- [ ] Write `audit`, `admin`, `auditor` (server-only parts in `::: server` blocks). Regenerate, check, commit.

### Task 11: Content — troubleshooting and error reference (en + de)

- [ ] `error-reference`: one `{#err-<code>}` section per code from the check-i18n code sets, cause + what to do; `troubleshooting` links into it. Check `entry_without_error_code`/`error_code_without_entry` both green. Commit.

### Task 12: Docs, status, final review, merge and deploy — Model: Opus (review)

- [ ] Remove `--allow-todo`; all CI checks green locally (`node ci/check-user-guide.mjs`, `docgen --check`, vitest, tsc, cargo tests per crate).
- [ ] `CONTEXT.md` (User guide: where it lives, how it is built), `docs/server/` operations note on `/docs` (public, no data), master plan M16 status → done, ledger L311–L325, PD-330 (no screenshots, follow-up).
- [ ] Opus whole-branch review (`superpowers:requesting-code-review`); fix findings with Sonnet.
- [ ] Push, GitHub + GitLab CI green (including desktop bundle jobs: Windows, macOS, Linux bundles contain `help/`), merge to `master` (`superpowers:finishing-a-development-branch`), auto deploy to production.
- [ ] Live check: `https://atlas-duck.dux.intern.gipmbh.de/docs/de/` and `/docs/en/` load, search works, CSP header present, login page "Hilfe" link resolves; tear down any review env (memory `cluster-hygiene`).

---

## Decisions (PD-321..PD-330)

- **PD-321** Both languages carry identical page ids, file names and anchors; CI-enforced.
- **PD-322** Flat front matter `id/title/mode/order`; unknown keys are an error.
- **PD-323** `::: desktop|server` blocks for mode-specific parts of shared pages.
- **PD-324** Search index as generated JS (`window.ATLAS_HELP_INDEX`), because the desktop CSP's `connect-src` forbids fetching a JSON file; no library.
- **PD-325** `/docs` is public, served outside session/CSRF middleware, same CSP as the app, `no-cache`.
- **PD-326** Generator is a workspace Rust bin reusing pulldown-cmark; output committed and drift-checked, so Tauri and the node-only Docker stage need no cargo step.
- **PD-327** `docs/user-guide/ui-links.json` is the single map UI page → guide anchor, read by the UI build and the CI check.
- **PD-328** Help window: own label `help`, zero app permissions; only `help_open` (on the other seven labels) opens it.
- **PD-329** `/docs` without language redirects by `Accept-Language`; the desktop resolves `auto` in Rust from the M15 setting.
- **PD-330** No screenshots in M16: no headless browser for web pages in CI (desktop e2e is tauri-driver on debug bundles); follow-up item in the master plan.

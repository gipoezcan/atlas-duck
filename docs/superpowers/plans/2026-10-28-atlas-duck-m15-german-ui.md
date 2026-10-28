# atlas-duck M15 (German UI) Implementation Plan

> **Draft status:** draft, written 2026-10-28 against `master` at `bdec7ef`, not yet reviewed. Numbering: M13/M14 end at PD-290; M15 claims **PD-291..PD-320** (used: PD-291..PD-304) and ledger entries **L291–L310**.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. One implementer subagent per task, one reviewer after each task.
>
> **Model policy (memory `subagent-model-preference`; never Fable):** Sonnet for every task and reviewer; Opus only for the final whole-branch review (Task 12).
>
> **Hard execution limits (memory `agent-execution-limits`):** no agent downloads or runs executables or installers, runs `npm install`/`npm ci`/`cargo install`, or starts `atlas-duck-app`/`atlas-duck-server`. Locally: `npx vitest run`, `npx tsc --noEmit`, `npx eslint`, `node ci/*.mjs`, `node --test`, `cargo check|clippy|test -p <crate> --locked -j 4` (one cargo process at a time, shared scratch `CARGO_TARGET_DIR`, memory `disk-usage-target-dir`). Worktrees: junction `node_modules` per memory `ui-gates-in-worktree`.
>
> **Shell:** PowerShell; edit with the Edit tool, never `Get-Content | Set-Content` (memory `powershell-utf8-rewrite`); German text contains umlauts, so every file stays BOM-less UTF-8. Commit with `git commit -F <file>`.

**Goal:** Ship every desktop window and server web page in English and German, with error texts, browser and desktop notifications and the desktop app's native dialogs translated, a per-user language choice (Automatic / Deutsch / English) in both modes, and CI that proves German is complete.

**Architecture:** One own typed dictionary module `app/ui/src/shared/i18n/` (English is the source object, German must satisfy its widened type, so a missing key is a compile error), a `LangProvider` React context and `useText()` hook, error-code→text maps in the UI keyed by the Rust code enums, and `Intl` helpers for dates and numbers. The credential page keeps its own small dictionary (PD-71 bundle isolation). Rust renders user-visible text in exactly one place, `app/src-tauri` (tray, native dialogs, toasts, status lines), through a two-language table and a `Lang` argument; core, server, CLI and MCP keep sending codes and English. Server mode stores the choice per user (schema v4); the desktop stores it app-side, outside the audit store.

**Tech Stack:** React 19.3.0, TypeScript 5.9.3, Vite 8.3.3, Vitest 5.0.3, Rust 1.95.0, axum 0.8.9, rusqlite 0.40.2, `tauri-plugin-dialog`, `windows-sys` (existing). **No new npm package and no new `[[package]]` in `Cargo.lock`.**

**Spec:** master plan `docs/superpowers/plans/2026-10-07-atlas-duck-master-plan.md` "### M15 — German UI" (decisions final, design interview 2026-10-28). Glossary `CONTEXT.md`. Earlier plans for touched areas: M6 (credential page PD-71, CSP), M12/M14 (server pages, `errors.rs`, store migrations v1→v3).

---

## What exists (survey at `bdec7ef`)

| Area | Now | M15 |
|---|---|---|
| Desktop texts | `app/ui/src/shared/strings.ts` (1124 lines, ~25 `*_TEXT` objects, `as const`, e.g. `BATCH_TEXT`, `QUEUE_TEXT`, `DETAIL_TEXT`, `SETTINGS_TEXT`, `AUDIT_TEXT`, `RUNNING_TEXT`, `RECOVERY_TEXT`, `BLOCK_REASON_TEXT`, `STATUS_LABELS`, `BATCH_FAILURE_TEXT`); per-window extras `settings/text.tsx`, `setup/text.ts`, `onboarding/OnboardingText.tsx`, `audit/text.tsx`; inline strings in `approvals/redaction/Panel.tsx`, `approvals/RequestTab.tsx`, `shared/Header.tsx` | moved into `shared/i18n/{en,de}/*.ts` (T1, T5, T6) |
| Credential window | plain TS, `credential/page.ts` (704 lines, texts inline and `RESTORE_LINE`), `credential/text.ts` (escape helper); imports nothing from `src/shared/` (PD-71); `ci/check-credential-bundle.mjs` forbids shared chunks and `localStorage`/`cookie`; `PASSPHRASE_PURPOSE` duplicated in `app/src-tauri/src/credential/mod.rs:48` | own `credential/i18n.ts`, lang from Rust over its IPC (T7) |
| Server texts | per page constants (`KEY_TEXT` in `server/api_keys/ApiKeys.tsx`, ~10 pages, 4–33 refs each), `server/approvals/notify.ts` (`NOTIFY_TITLE`, `NOTIFY_TEXT`), `server/shell/ServerHeader.tsx` | `shared/i18n/{en,de}/server*.ts` (T8, T9) |
| Errors | desktop: envelope `ErrorCode` (30 codes, `crates/ipc/src/envelope.rs:25`, `ErrorCode::ALL`), command errors `CmdError` kinds (`crates/server/src/cmd.rs:61-77`, same JSON as desktop), batch failures, block reasons; core's validator message shown raw in `approvals/Detail.tsx:118`. Server: `{"error":{"code","message","reason"?}}` from `crates/server/src/errors.rs` (~40 `ApiError` constants, codes like `api/not_found`); UI reads `code`/`reason` in `server/http.ts:27-34`, maps per page (`createError(code)` in `ApiKeys.tsx:65`) | central maps `shared/i18n/errors.ts` + CI check (T2) |
| Rust-rendered UI text | `app/src-tauri/src/tray.rs:39-52,222,248` (menu, tooltip), `windows.rs:66-70,369,829-853` (error/info dialogs, gate text), `confirm.rs` (`.confirm` OkCancel), `attention.rs:86` (`toast_text`, desktop notification), `status.rs:45-184` (`StatusLineDto{id,text,level}`), `restore_flow.rs`, `recovery_tier.rs`, `removal.rs`, `serve.rs:1121`, `commands/audit.rs:50-59`, `credential/mod.rs:48,713` | `Lang` argument + table `app/src-tauri/src/i18n.rs` (T10) |
| Settings | desktop: `settings_get`/`settings_apply` (`app/src-tauri/src/commands/settings.rs:566,678,880,915`) over core's audit-backed `SettingsView` (`crates/core/src/settings/mod.rs:372`), unavailable while locked; server: no per-user prefs; `server.db` `SCHEMA_VERSION = 3` (`crates/server/src/store/schema.rs:6`), migrations `up_from` | desktop app-side file (T3); server `users.lang_pref`, v4 (T4) |
| Dates/numbers | one helper `server/http.ts:262` (ISO slice + " UTC"); audit filters read UTC (`audit/text.tsx:88`) | `shared/i18n/format.ts` (T1) |
| HTML | 7 desktop + 10 server HTML files with `<html lang="en">`; CSP in `credential.html` and Tauri config (`ci/check-csp.mjs`, no inline script) | `document.documentElement.lang` set at runtime (T1); no CSP change |
| Tests/CI | Vitest `vite.config.ts` `test.include: src/**/*.test.{ts,tsx}`, jsdom; tests import the English constants (e.g. `ApiKeys.test.tsx` 27 refs to `KEY_TEXT`); GitHub `ui` job `.github/workflows/ci.yml:1992`; GitLab `ui` `.gitlab-ci.yml:40-58` | tests import `en`; new German tests; `node ci/check-i18n.mjs` in both `ui` jobs (T2, T11) |

---

## Global Constraints

- Languages: exactly `en` and `de`. `type Lang = 'en' | 'de'`; `type LangPref = 'auto' | 'en' | 'de'`; default pref `auto`.
- Resolution (PD-291): `auto` → `de` when the locale tag starts with `de` (case-insensitive: `de`, `de-DE`, `de-AT`, `de-CH`), else `en`. Server: `navigator.language` (then `navigator.languages[0]`). Desktop: the OS locale (Rust `os_locale()`, T3), handed to the webviews.
- Translated: every desktop window and server page, error texts the UI shows, browser and desktop notifications, native dialogs, tray. Stays English: CLI output, MCP, audit records and their payloads, logs, metrics, `docs/server/`, exported audit files (ISO dates).
- Core and server keep sending codes; the UI maps codes to text. The one exception is `app/src-tauri`, which renders native/tray/status text itself (PD-292).
- No new runtime dependency (npm or crate). No `localStorage`/`sessionStorage`/cookie for the language (desktop and server persist it server/app-side).
- Product names, codes, op ids, aliases, URLs, `UTC` and agent-supplied text are never translated.
- German uses "Sie", sentence case, and the glossary terms of `CONTEXT.md` with their German equivalents fixed in a `GLOSSARY_DE` table in `shared/i18n/de/terms.ts` (Approval → Freigabe, Agent → Agent, Audit log → Audit-Protokoll, Token → Token, Session → Sitzung, Auditor → Auditor, Admin → Administrator). German text has no human review (user decision for M16; same here).
- Existing English tests keep passing unchanged in behaviour (they render without a provider → `en`).

## Review Focus

1. A German string that is longer than its English one breaks a fixed-width layout (buttons, tray tooltip limit 127 chars on Windows) → T10 asserts every German tooltip ≤ 127 UTF-16 units; T5 renders the decision bar in `de` and asserts no button text is cut (`scrollWidth <= clientWidth` is not testable in jsdom, so the check is a max-length table in `check-i18n.mjs` for keys marked `short`).
2. A user switches language while a dialog, an unsent edit or a deny reason is open → the switch re-renders texts only, never resets state: T3 test `lang_change_keeps_open_deny_draft`.
3. Plural forms copied from English (`n === 1 ? '' : 's'`) give wrong German → each function key is tested in `de` with `n = 0, 1, 2` (T1 helper `pluralCases`).
4. An unknown error code (newer server, older UI) shows nothing or `undefined` → maps return the generic text plus the code in parentheses: T2 test `unknown_code_shows_generic_text_and_code`.
5. Locale tags like `de_DE.UTF-8` (Linux env), `de-DE-u-co-phonebk` or empty → `resolveLang` handles `_`, extensions and empty input: T1 test `resolve_accepts_posix_and_bcp47_tags`.

---

## File structure

```
app/ui/src/shared/i18n/
  index.ts          Lang, LangPref, resolveLang, Dict, Widen<T>
  context.tsx       LangProvider, useLang, useText
  format.ts         formatDateTime, formatNumber, formatBytes
  errors.ts         envelopeErrorText, cmdErrorText, serverErrorText (+ maps)
  en/*.ts, de/*.ts  one file per area: approvals, desktop, server, admin, errors, common
  dict.ts           en: Dict, de: Dict assembled
  i18n.test.ts      completeness, identical-string allowlist, plurals
app/ui/src/credential/i18n.ts      credential page's own two-language table
app/src-tauri/src/i18n.rs          Lang, os_locale(), text table for Rust-rendered UI text
app/src-tauri/src/ui_lang.rs       LangPref persistence (app data dir file `ui-lang`)
crates/server/src/web/pref_routes.rs   PUT /api/me/preferences
ci/check-i18n.mjs (+ .test.mjs)    error-code coverage, allowlist, short-key lengths
```

---

### Task 1: The i18n module (types, resolution, provider, formatting)

**Files:**
- Create: `app/ui/src/shared/i18n/{index.ts,context.tsx,format.ts,dict.ts,en/common.ts,de/common.ts,de/terms.ts,i18n.test.ts}`
- Modify: `app/ui/src/server/http.ts:262` (date helper delegates to `format.ts`)

**Interfaces:**
- Produces:
  - `type Lang = 'en' | 'de'`, `type LangPref = 'auto' | 'en' | 'de'`, `const LANG_PREFS: readonly LangPref[]`
  - `resolveLang(pref: LangPref, locale: string | null | undefined): Lang`
  - `type Widen<T>`: string literal → `string`; `(...a: A) => string` → same; `readonly string[]` → `readonly string[]`; objects recursively. `type Dict = Widen<typeof en>`; `export const en`, `export const de: Dict` in `dict.ts`.
  - `LangProvider({ lang, children })`, `useLang(): Lang`, `useText(): Dict` (no provider → `en`). The provider sets `document.documentElement.lang`.
  - `formatDateTime(lang: Lang, secs: number): string` (UTC, `Intl.DateTimeFormat` with `timeZone: 'UTC'`, suffix ` UTC`; `en` keeps today's `YYYY-MM-DD HH:MM UTC`, `de` → `28.10.2026, 14:05 UTC`), `formatNumber(lang, n)`, `formatBytes(lang, n)`.
  - test helper `pluralCases(fn: (n: number) => string): string[]` for `n = 0,1,2`.

- [ ] **Step 1: Write the failing tests** in `i18n.test.ts`: `resolve_accepts_posix_and_bcp47_tags` (`'de_DE.UTF-8'`, `'de-AT'`, `'DE'`, `'de-DE-u-co-phonebk'` → `de`; `'en-US'`, `'fr'`, `''`, `null` → `en`; pref `'en'` with locale `'de'` → `en`); `provider_sets_html_lang`; `no_provider_is_english`; `format_datetime_en_unchanged` (`formatDateTime('en', 0) === '1970-01-01 00:00 UTC'`); `format_datetime_de` (`'01.01.1970, 00:00 UTC'`); `format_number_de_grouping` (`formatNumber('de', 12345) === '12.345'`).
- [ ] **Step 2:** `npx vitest run src/shared/i18n` → FAIL (module missing).
- [ ] **Step 3: Implement** the files above; `en/common.ts` holds shared words (Cancel, Close, Save, Retry, language labels `lang_auto: 'Automatic'`, `lang_de: 'Deutsch'`, `lang_en: 'English'` — the two language names are the same in both dictionaries and are on the allowlist).
- [ ] **Step 4:** run → PASS; `npx tsc --noEmit` clean.
- [ ] **Step 5: Commit** `feat(ui): typed en/de dictionary, language resolution and Intl formatting`.

### Task 2: Error-code texts and the i18n CI check

**Files:**
- Create: `app/ui/src/shared/i18n/errors.ts`, `en/errors.ts`, `de/errors.ts`, `ci/check-i18n.mjs`, `ci/check-i18n.test.mjs`
- Modify: `app/ui/src/server/http.ts` (export `ServerErrorCode` union), `app/ui/src/server/api_keys/ApiKeys.tsx:65` (`createError` → `serverErrorText`), `app/ui/src/approvals/{Batch,Detail}.tsx` (failure/block maps move), `app/ui/package.json` (`"check:i18n": "node ../../ci/check-i18n.mjs"`)

**Interfaces:**
- Consumes: `Lang`, `Dict` (T1).
- Produces: `type EnvelopeErrorCode` (the 30 snake_case names of `ErrorCode::ALL`), `type CmdErrorKind` (`invalid_argument`, `not_found`, `release_blocked`, `unknown_command`, `not_ready`, `audit_unreadable`, `audit_failed`, `internal`), `type ServerErrorCode` (every `"…/…"` code in `crates/server/src/errors.rs`); `dict.errors.envelope: Record<EnvelopeErrorCode, string>`, `.cmd: Record<CmdErrorKind, string>`, `.server: Record<ServerErrorCode, string>`, `.generic: (code: string) => string`; `envelopeErrorText(t: Dict, code: string): string`, `cmdErrorText(t, kind)`, `serverErrorText(t, code: string | null, reason: string | null)`.
- `check-i18n.mjs` (no npm deps): (a) parses `ErrorCode::ALL` in `crates/ipc/src/envelope.rs`, the `CmdError` variants in `crates/server/src/cmd.rs`, the `e(StatusCode::…, "<code>", …)` constants in `crates/server/src/errors.rs`, and fails unless each set equals the keys of `en/errors.ts` and `de/errors.ts` (both ways); (b) fails on a German string leaf equal to its English leaf unless its key path is in `I18N_SAME_ALLOWLIST` (each entry with a one-line reason); (c) fails on an empty string leaf; (d) enforces max lengths for keys listed in `SHORT_KEYS` (German ≤ 1.5× English + 4). Modelled on `ci/check-commands.mjs`.

- [ ] **Step 1: Failing tests:** `check-i18n.test.mjs` fixtures: missing German code → violation naming it; stale UI code not in Rust → violation; identical leaf not allowlisted → violation; allowlisted → ok. Vitest `errors.test.ts`: `unknown_code_shows_generic_text_and_code` (`envelopeErrorText(de, 'zzz')` contains `zzz`); `every_envelope_code_has_text_in_both`.
- [ ] **Step 2:** `node --test ci/check-i18n.test.mjs`; `npx vitest run src/shared/i18n` → FAIL.
- [ ] **Step 3: Implement**; the `edit_rejected` core validator message (`Detail.tsx:118`, `crates/core/src/validate/mod.rs:348`) stays English and is listed as residual in PD-293 (it is app-generated text naming JSON paths; mapping it needs a code in core, out of scope).
- [ ] **Step 4:** both → PASS; `node ci/check-i18n.mjs` exits 0 on the repo.
- [ ] **Step 5: Commit** `feat(ui): error-code texts in en/de and ci/check-i18n`.

### Task 3: Desktop language setting (Rust storage, OS locale, settings UI, live switch)

**Files:**
- Create: `app/src-tauri/src/ui_lang.rs`, `app/src-tauri/src/i18n.rs` (only `Lang`, `LangPref`, `os_locale()`, `resolve()` here; the table is T10)
- Modify: `app/src-tauri/src/commands/settings.rs:566-720,880-950` (`SettingsGet.ui_lang: LangPrefDto`, `settings_apply` accepts `{key:'ui_lang', value}` handled app-side before core, never written to the audit store), `app/src-tauri/src/state.rs` (`AppState.lang: RwLock<Lang>`), `app/src-tauri/Cargo.toml` (`windows-sys` feature `Win32_Globalization`; no lock entry change), `app/src-tauri/src/os_hooks/macos.rs` (CoreFoundation `CFLocaleCopyPreferredLanguages` via the existing `extern "C"` pattern), `app/ui/src/shared/ipc/{types.ts,validate.ts,events.ts}`, `app/ui/src/settings/Settings.tsx` (new "Language" section), every desktop `*/main.tsx` (wrap in `DesktopLangRoot`), `ci/check-commands.mjs` fixtures if the DTO shape is pinned there
- Create: `app/ui/src/shared/i18n/DesktopLangRoot.tsx`
- Test: `app/src-tauri/src/ui_lang.rs` (unit), `app/ui/src/settings/Language.test.tsx`

**Interfaces:**
- Produces (Rust): `enum Lang { En, De }`, `enum LangPref { Auto, En, De }` (serde snake_case), `fn os_locale() -> Option<String>` (Linux/BSD: `LC_ALL`, `LC_MESSAGES`, `LANG` in that order; Windows: `GetUserDefaultLocaleName`; macOS: first preferred language), `fn resolve(pref: LangPref, locale: Option<&str>) -> Lang` (same rule as TS), `ui_lang::load(dir: &Path) -> LangPref` (missing/garbled file → `Auto`), `ui_lang::store(dir: &Path, pref: LangPref) -> io::Result<()>` (atomic write of one word into `<local data dir>/ui-lang`). Event `lang_changed { lang: Lang, pref: LangPref }` emitted to all windows on apply.
- Produces (TS): `SettingsGet.ui_lang: { pref: LangPref; lang: Lang }`, change `{ key: 'ui_lang'; value: LangPref }`, `DesktopLangRoot` reads `settings_get` once and listens to `lang_changed`.
- PD-294: the preference lives outside the audit store because the gate dialogs, "Waiting for keyring" and the no-tray message show while core is locked; it is not audited (it is not a security setting).

- [ ] **Step 1: Failing tests:** Rust `resolve_matches_ts_rule` (same table as T1), `load_missing_is_auto`, `load_garbage_is_auto`, `store_then_load_roundtrips`, `apply_ui_lang_does_not_touch_core` (fake `SettingsAdmin` records no call); Vitest `language_select_offers_three_choices`, `apply_switches_open_window_to_german` (fake transport emits `lang_changed`), `lang_change_keeps_open_deny_draft` (approvals window with a typed deny reason keeps it after the switch).
- [ ] **Step 2:** `cargo test -p atlas-duck-app --locked -j 4 ui_lang i18n` and `npx vitest run src/settings/Language.test.tsx` → FAIL.
- [ ] **Step 3: Implement.** Before the first window exists, Rust uses `resolve(load(dir), os_locale())`.
- [ ] **Step 4:** both → PASS; `cargo clippy -p atlas-duck-app --locked -j 4 -- -D warnings`.
- [ ] **Step 5: Commit** `feat(app): desktop language setting with OS-locale default`.

### Task 4: Server language preference (schema v4, API, header control)

**Files:**
- Modify: `crates/server/src/store/schema.rs` (`SCHEMA_VERSION = 4`, `V3_TO_V4 = "ALTER TABLE users ADD COLUMN lang_pref TEXT NOT NULL DEFAULT 'auto';"`, `up_from(3)`), `crates/server/src/store/{mod.rs,sqlite.rs,memory.rs}` (`user_lang_pref`, `set_user_lang_pref`), `crates/server/src/web/auth_routes.rs:92-98` (`"lang_pref"` in `/api/session`), `crates/server/src/web/mod.rs` (`("PUT", "/api/me/preferences", Access::Session)` in `ROUTES` and router), `crates/server/src/admin/backup.rs` (schema v4 accepted by restore), `crates/server/tests/isolation.rs` (route walked), `app/ui/src/server/shell/{RequireSession.tsx,ServerHeader.tsx}`, every `app/ui/src/server/*/main.tsx` (wrap in `ServerLangRoot`), `app/ui/src/server/login/main.tsx` (browser language only, no session yet)
- Create: `crates/server/src/web/pref_routes.rs`, `app/ui/src/server/shell/ServerLangRoot.tsx`

**Interfaces:**
- Produces: store `fn user_lang_pref(&self, user_id: &str) -> StoreResult<LangPref>`, `fn set_user_lang_pref(&self, user_id: &str, pref: LangPref) -> StoreResult<()>`; `PUT /api/me/preferences` body `{"lang_pref":"auto"|"en"|"de"}` → 204; unknown value → `ApiError::BAD_REQUEST`; CSRF/Origin through the existing `StateChanging` layer; not an audit record (PD-295, same reason as PD-294). `/api/session` gains `"lang_pref"`. UI: `ServerLangRoot` resolves from `/api/session` + `navigator.language`; header select calls PUT and switches without reload.
- Unchanged: `crates/core/src/settings/mod.rs::SettingsView`, `/api/cmd/*`, isolation semantics.

- [ ] **Step 1: Failing tests:** `migrate_v3_to_v4_defaults_auto` (v3 file → v4, existing users `auto`), `put_preferences_requires_csrf` (403 `csrf/…` without header), `put_preferences_rejects_unknown` (400), `session_reports_lang_pref`, `other_user_pref_untouched` (isolation suite); Vitest `server_header_switches_to_german`, `login_page_follows_browser_language`.
- [ ] **Step 2:** `cargo test -p atlas-duck-server --locked -j 4 lang_pref preferences migrate_v3` and Vitest → FAIL.
- [ ] **Step 3: Implement.** Bump every test or fixture that pins `SCHEMA_VERSION == 3` (grep `schema_version` in `crates/server`).
- [ ] **Step 4:** → PASS; `cargo clippy -p atlas-duck-server --locked -j 4 -- -D warnings`.
- [ ] **Step 5: Commit** `feat(server): per-user language preference (schema v4)`.

### Task 5: Translate the desktop approvals window

**Files:**
- Create: `app/ui/src/shared/i18n/{en,de}/approvals.ts`
- Modify: `app/ui/src/shared/strings.ts` (approval objects `WINDOW_TITLES`, `BATCH_TEXT`, `BATCH_FAILURE_TEXT`, `QUEUE_TEXT`, `CLASS_LABELS`, `HEADER_TEXT`, `RECENT_TEXT`, `DETAIL_TEXT`, `KEYBOARD_TEXT`, `DENY_TEXT`, `EDIT_TEXT`, `REDACTION_TEXT`, `BLOCK_REASON_TEXT`, `RAW_TEXT`, `REQUEST_TEXT`, `STATUS_LABELS`, `UNVERIFIED`, `UNUSUAL_CHARACTERS` move out), all of `app/ui/src/approvals/**/*.tsx`, `app/ui/src/shared/{Header.tsx,text/*.tsx}`, the approvals tests (import `en.approvals` instead of the old constants, assertions unchanged); `crates/preview/src/warning.rs` only if a warning lacks a stable `kind` on the wire (then add `kind`, keep `text` English for CLI/MCP; UI shows `dict.approvals.warning[kind]`)

**Interfaces:**
- Consumes: `useText()`, `Dict`, `formatDateTime` (T1); `cmdErrorText`, `envelopeErrorText` (T2).
- Produces: `dict.approvals.*` with the same key names as the old objects (lower-cased object names: `batch`, `queue`, `detail`, …) so the diff in components is `BATCH_TEXT.x` → `t.approvals.batch.x`.

- [ ] **Step 1: Failing test** `approvals/german.test.tsx`: `queue_and_detail_render_in_german` (fixture queue in `<LangProvider lang="de">`; asserts `de.approvals.queue.title` visible and no `en.approvals.queue.title`), `batch_plurals_in_german` (`pluralCases(de.approvals.batch.deny_selected_title)` gives three distinct correct German forms), `decision_bar_short_keys` (keys in `SHORT_KEYS`).
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement** the move and the German texts (terms from `de/terms.ts`).
- [ ] **Step 4:** `npx vitest run src/approvals src/shared` (all old tests still green), `node ci/check-i18n.mjs`, `npx tsc --noEmit`, `npm run lint` → PASS.
- [ ] **Step 5: Commit** `feat(ui): approvals window in German`.

### Task 6: Translate settings, setup, onboarding, audit and running-scripts windows

**Files:**
- Create: `app/ui/src/shared/i18n/{en,de}/{settings,setup,onboarding,audit,running}.ts`
- Modify: `shared/strings.ts` (remaining objects `SETTINGS_TEXT`, `AUDIT_TEXT`, `RUNNING_TEXT`, `ONBOARDING_PANEL_TEXT`, `COMMITTED_INCOMPLETE_TEXT`, `RECOVERY_TEXT`, `HTTPS_REQUIRED_HINT`, `IDENTITY_HEADER_HINT`, `PAC_HINT`; file deleted when empty), `settings/text.tsx`, `setup/text.ts`, `onboarding/OnboardingText.tsx`, `audit/text.tsx`, all components and tests in `settings/`, `setup/`, `onboarding/`, `audit/`, `running_scripts/`
- Audit views keep timestamps in UTC through `formatDateTime`; the export path and exported files are untouched (ISO).

**Interfaces:** Consumes T1/T2. Produces `dict.{settings,setup,onboarding,audit,running}`.

- [ ] **Step 1: Failing tests** `settings/german.test.tsx` (`settings_sections_in_german`), `setup/german.test.tsx` (`wizard_first_step_in_german`), `audit/german.test.tsx` (`event_list_dates_german_utc`: `01.01.1970, 00:00 UTC`), `onboarding/german.test.tsx`, `running_scripts/german.test.tsx`.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement.** `audit/text.tsx`'s `utcOf` parsing stays as is (input fields are `datetime-local`, language-neutral).
- [ ] **Step 4:** full `npx vitest run`, `node ci/check-i18n.mjs`, `npx tsc --noEmit`, `npm run lint` → PASS.
- [ ] **Step 5: Commit** `feat(ui): settings, setup, onboarding, audit and running-scripts in German`.

### Task 7: Credential window (isolated dictionary)

**Files:**
- Create: `app/ui/src/credential/i18n.ts`
- Modify: `app/ui/src/credential/{page.ts,ipc.ts}`, `credential.test.ts`, `app/src-tauri/src/credential/mod.rs:48,713` (`PASSPHRASE_PURPOSE` → `passphrase_purpose(lang: Lang) -> &'static str`; the window's init payload gains `lang: "en"|"de"`), `ci/check-credential-bundle.test.mjs` (fixture: `credential/i18n.ts` stays inside the credential chunk)

**Interfaces:**
- Consumes: Rust `Lang` (T3).
- Produces: `CREDENTIAL_TEXT: { en: CredentialText; de: CredentialText }` with `type CredentialText` declared from `en` like `Widen` (local copy, no import from `src/shared/`, PD-71); `pageText(lang: 'en' | 'de'): CredentialText`. The page never reads `navigator.language` or storage; Rust sends the resolved language.

- [ ] **Step 1: Failing tests:** `credential_page_renders_german_when_rust_says_de`, `passphrase_purpose_matches_rust_in_both_languages` (the existing verbatim-equality test, now per language; Rust side `passphrase_purpose_texts_pinned`), `credential_chunk_imports_nothing_shared` (bundle check fixture).
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `npx vitest run src/credential`, `node --test ci/check-credential-bundle.test.mjs`, `cargo test -p atlas-duck-app --locked -j 4 credential` → PASS.
- [ ] **Step 5: Commit** `feat(credential): credential window in German`.

### Task 8: Translate the server user pages and browser notifications

**Files:**
- Create: `app/ui/src/shared/i18n/{en,de}/server.ts`
- Modify: `app/ui/src/server/{login/Login.tsx,shell/ServerHeader.tsx,api_keys/ApiKeys.tsx,credentials/Credentials.tsx,connected_apps/ConnectedApps.tsx,oauth/Consent.tsx,approvals/ServerApprovals.tsx,approvals/notify.ts,audit/OwnAudit.tsx}` and their tests; `server/http.ts:262` callers use `formatDateTime`
- `notify.ts`: `NOTIFY_TITLE` becomes `t.server.notify.title` (`atlas-duck: approval needed` / `atlas-duck: Freigabe erforderlich`); body stays the op id (PD-207). `Notifier` takes `title: () => string` so a language switch applies to the next notification.

**Interfaces:** Consumes T1, T2 (`serverErrorText`), T4 (`ServerLangRoot`). Produces `dict.server.{login,header,api_keys,credentials,connected_apps,consent,approvals,notify,own_audit}`.

- [ ] **Step 1: Failing tests:** `server/german.test.tsx`: `login_in_german`, `api_key_errors_in_german` (`api_key/limit_reached` → German text), `consent_in_german`, `notification_title_follows_language` (`notify.test.ts` with fake env, `de`).
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement**; per-page `*_TEXT` constants are deleted, tests import `en.server.*`.
- [ ] **Step 4:** `npx vitest run src/server`, `node ci/check-i18n.mjs`, `npx tsc --noEmit`, `npm run build:server` → PASS.
- [ ] **Step 5: Commit** `feat(ui): server user pages and notifications in German`.

### Task 9: Translate the server admin, auditor and export pages

**Files:**
- Create: `app/ui/src/shared/i18n/{en,de}/admin.ts`
- Modify: `app/ui/src/server/{admin/Instances.tsx,auditor/Users.tsx,auditor/UserAudit.tsx,export/ExportPanel.tsx}` and tests

**Interfaces:** Consumes T1, T2, T4. Produces `dict.admin.{instances,auditor,export}`.

- [ ] **Step 1: Failing tests:** `admin_instances_in_german`, `auditor_users_in_german`, `export_panel_in_german_keeps_iso_filename` (download name unchanged).
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `npx vitest run src/server`, `node ci/check-i18n.mjs`, `npm run build:server` → PASS.
- [ ] **Step 5: Commit** `feat(ui): server admin, auditor and export pages in German`.

### Task 10: Rust-rendered desktop texts (tray, native dialogs, toasts, status lines)

**Files:**
- Modify: `app/src-tauri/src/i18n.rs` (add `struct T { en: &'static str, de: &'static str }` table and `fn tr(lang: Lang, t: &T) -> &'static str`), `tray.rs:39-52,222,248`, `windows.rs:66-70,369,829-853`, `attention.rs:86` (`toast_text(lang, …)`), `status.rs:45-184` (texts take `lang`; `id` and `level` unchanged), `restore_flow.rs:50,61`, `recovery_tier.rs:131-227`, `removal.rs:754,796`, `serve.rs:1121-1127`, `commands/audit.rs:50,59`, `os_hooks/windows.rs:91`, `cli_install/linux.rs:138` (only if shown in a dialog); tray and status lines rebuild on `lang_changed`

**Interfaces:**
- Consumes: `Lang`, `AppState.lang` (T3).
- Produces: every listed `*_text` function gains a first parameter `lang: Lang`; the `pub const` English texts become `T` entries (English values unchanged byte for byte, so existing Rust tests pass with `Lang::En`).
- PD-292: `.confirm(text)` call sites keep their shape; only the text argument changes, so `ci/check-dialog-proofs.mjs` needs no new `PROOF_HELPERS` entry. Button labels of `OkCancelCustom` come from the table.

- [ ] **Step 1: Failing tests** (Rust unit, `app/src-tauri/src/i18n.rs` tests): `every_entry_has_both_languages` (no empty `de`), `de_differs_from_en_unless_allowlisted`, `tray_tooltip_de_fits_127_utf16`, `toast_text_de`, `gate_text_de`, `status_lines_keep_ids_across_languages`.
- [ ] **Step 2:** `cargo test -p atlas-duck-app --locked -j 4 i18n` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `cargo test -p atlas-duck-app --locked -j 4`, `node ci/check-dialog-proofs.mjs`, `node ci/check-no-panic-macros.mjs` → PASS.
- [ ] **Step 5: Commit** `feat(app): tray, dialogs, toasts and status lines in German`.

### Task 11: German flow tests and CI wiring

**Files:**
- Create: `app/ui/src/shared/i18n/flows.de.test.tsx`
- Modify: `.github/workflows/ci.yml` (`ui` job at line 1992: step `node ci/check-i18n.mjs` and `node --test ci/check-i18n.test.mjs` after the UI tests), `.gitlab-ci.yml:53-58` (same two lines in `ui`), `ci/check-no-skips.mjs` only if it needs the new file pattern

**Interfaces:** Consumes everything above.

- [ ] **Step 1: Write the flow tests** (fake transports, `<LangProvider lang="de">` or `lang_changed` event): `de_approve_write_flow` (queue → detail → approve, only German UI text visible: assert `document.body.textContent` contains no leaf of `en` longer than 12 chars that is not allowlisted), `de_deny_with_reason_flow`, `de_settings_switch_back_to_english`, `de_server_api_key_create_and_error`, `de_server_consent_flow`. Plus `whole_dictionary_has_no_english_leftovers` (iterates `en`/`de` leaves).
- [ ] **Step 2:** run → green once T5–T9 are in; any leftover English text is fixed in the owning area file.
- [ ] **Step 3:** wire CI as listed.
- [ ] **Step 4:** full local gates: `npx vitest run`, `npm run lint`, `npx tsc --noEmit`, `npm run build`, `npm run build:server`, `npm run check:bundle`, `node ci/check-csp.mjs`, `node ci/check-i18n.mjs`, `node ci/check-commands.mjs` → PASS.
- [ ] **Step 5: Commit** `test(ui): German flow tests; ci: i18n check in GitHub and GitLab`.

### Task 12: Docs, status, final review and deploy — Model: Opus (review)

**Files:**
- Modify: `docs/superpowers/plans/2026-10-07-atlas-duck-master-plan.md` ("### M15" status → done with date and commit), `CONTEXT.md` (term **UI language** / **Language preference** with the Automatic/Deutsch/English rule), `docs/server/` operations doc for schema v4 (backup/restore compatibility, `PUT /api/me/preferences`), the plan decisions PD-291..PD-304 and ledger entries in this plan's appendix.

- [ ] **Step 1:** whole-branch review (Opus) against the master plan M15 section and the Review Focus list.
- [ ] **Step 2:** push to GitHub and GitLab; wait for GitHub CI and the GitLab pipeline green (including `ui`, `server`, `chart:test` as optional need).
- [ ] **Step 3:** after the merge to `master`, `deploy:production` runs automatically; verify on `https://atlas-duck.dux.intern.gipmbh.de`: `/api/session` carries `lang_pref`, a browser with `Accept-Language: de` gets the German login page, the header switch persists across reload. Tear down review environments (memory `cluster-hygiene`).
- [ ] **Step 4: Commit** `docs: M15 German UI done`.

---

## Plan decisions

- **PD-291** Resolution rule `auto` → `de` iff the locale tag's primary subtag is `de` (POSIX `_`/`.` and BCP 47 extensions stripped), else `en`.
- **PD-292** Rust renders user text only in `app/src-tauri`, through `i18n.rs`; core, server, preview, CLI and MCP stay English/code-only.
- **PD-293** Residual English: core's edit-validator message (`Detail.tsx:118`), agent-supplied text, op ids, product names. Listed, not translated.
- **PD-294** Desktop preference in `<local data dir>/ui-lang`, outside the audit store, not audited.
- **PD-295** Server preference in `users.lang_pref` (schema v4), returned by `/api/session`, set by `PUT /api/me/preferences`; not audited.
- **PD-296** German leaves equal to English need an allowlist entry with a reason (`check-i18n.mjs`).
- **PD-297** The credential page carries its own table (PD-71) and gets the language from Rust.
- **PD-298** Dates in the UI are always UTC with suffix ` UTC`, formatted per language; exports keep ISO.

## Self-review

1. Coverage: windows (T5, T6, T7), server pages (T8, T9), error texts (T2), notifications browser (T8) and desktop (T10), native dialogs (T10), language choice desktop (T3) and server (T4), mechanism and compile-time completeness (T1), CI check (T2, T11), Intl (T1), tests in English unchanged and German tests (T5–T11), CI GitHub/GitLab (T11), deploy (T12).
2. Each step names a file, signature or test; translated text bodies are left to the implementer by design.
3. Names used across tasks: `Lang`, `LangPref`, `resolveLang`, `useText`, `Dict`, `formatDateTime`, `envelopeErrorText`, `cmdErrorText`, `serverErrorText`, `ui_lang::{load,store}`, `os_locale`, `resolve`, `tr`, `lang_changed`, `PUT /api/me/preferences`, `users.lang_pref`.
4. Review Focus items 1–5 each have a test in T1, T2, T3, T5 or T10.
5. Proportion: no component bodies; the plan stays shorter than the code it describes.

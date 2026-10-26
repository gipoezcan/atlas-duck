# atlas-duck M11 (UI visual design) Implementation Plan

> **Draft status:** draft, written 2026-10-26 against `m10-audit-export-packaging` (M10 about to merge). Not yet reviewed.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. One implementer subagent per task, one reviewer after each task.
>
> **Model policy (memory `subagent-model-preference`; never Fable):** Sonnet (medium) for every task unless the task says otherwise; Haiku for none (the contrast and layout judgement is not mechanical enough).
>
> **Hard execution limits (corporate AV, memory `agent-execution-limits`):** no subagent downloads or runs executables or installers, runs any `npm install`/`npm ci`/`npx`, or adds a package. Only the lead runs cargo (Task 12), one cargo process at a time, `-j 4`, `--locked`, shared `CARGO_TARGET_DIR` in the scratchpad (memory `disk-usage-target-dir`).
>
> **Worktree UI gates (memory `ui-gates-in-worktree`):** worktrees have no `node_modules`; the lead creates a junction `app\ui\node_modules` → `C:\Code\atlas-duck\app\ui\node_modules` (lockfiles equal) and removes it with `cmd /c rmdir` before merge. `npm run` fails under nvm: call node directly (see "UI gates" below). Use the Edit tool or `UTF8Encoding($false)` for file writes, never `Get-Content | Set-Content` (memory `powershell-utf8-rewrite`); commit with `git commit -F <file>` (memory `powershell-net-paths-and-commit-quoting`).

**Goal:** Every window (Setup, Settings, Approvals, Audit, Credential, Onboarding, Running scripts) stops rendering with browser defaults (Times New Roman, cramped inline forms, grey system buttons) and gets one clean, consistent, accessible look from bundled CSS only.

**Architecture:** No new crate, IPC method, npm package or runtime dependency. `app/ui/src/shared/app.css` is split into ordered layers under `app/ui/src/shared/styles/` (tokens, base, forms, layout, components, per-window files), imported from a single `app.css` entry with `@import` (Vite inlines them into one bundled stylesheet, so CSP `style-src 'self'` is unchanged). The credential page keeps its own stylesheet (`src/credential/credential.css`, spec §10.3: the credential chunk shares no module with the main bundle) with a copy of the token block. A new dependency-free node checker `app/ui/scripts/check-css.mjs` (with `check-css.test.mjs`) enforces: tokens defined for both color schemes, no hard-coded colors outside token blocks, computed WCAG contrast for the token pairs, the queue-row height contract, reduced-motion handling, no new `style=` props. JSX changes are limited to class names and wrapper elements.

**Tech Stack:** unchanged pins (React 19.3.0, Vite 8.3.3, Vitest 5.0.3, TypeScript 5.9.3, ESLint 9.39.5, Node 24 via nvm locally / `^22.13.0` per `package.json`). Plain CSS (custom properties, `@media (prefers-color-scheme)`, `@media (prefers-reduced-motion)`, `:focus-visible`, flex/grid); no preprocessor, no PostCSS plugin, no Tailwind, no UI library.

**Spec:** `docs/superpowers/specs/2026-10-07-atlas-duck-design.md` §2.4 (everything bundled, no CDN/remote loads), §2.5 (windows), §6.4 (CSP: `style-src 'self'` + the isolation-style hash + the preview-CSS hash, no `'unsafe-inline'`), §10.3 (credential page policy and its isolated chunk), the UI rule "All badges, warnings and flags are text-labelled with accessible names; colour is never the only signal" (spec l.545). Server-mode addendum `docs/superpowers/specs/2026-10-26-atlas-duck-server-mode.md`: M12 serves the same React pages over HTTPS in a browser, so nothing here may assume Tauri or WebView2/WebKitGTK quirks.

**Prerequisite:** M10 merged on `master`. Branch `m11-ui-visual-design` from that merge.

**Master plan line (M11):** scope = base theme (system font stack, light/dark palette, spacing scale, button/input/select styles, focus rings), form layout (labels above fields, grouped sections, one action row), layout pass per window. Constraints = CSP, no new runtime deps, class-name changes keep existing tests and `QUEUE_ROW_REM`, accessibility. Exit = every window reviewed in a screenshot on Windows and Linux (and the macOS GUI checklist), UI gates and e2e green.

---

## Global Constraints

1. **CSP.** No `<style>` elements, no `style=""` attributes in HTML, no new React `style={...}` props. The two existing ones stay as they are and are the allow-list: `src/shared/list/Windowed.tsx` (row positioning, height) and `src/approvals/redaction/Tree.tsx` (`paddingLeft` per depth). React writes these through CSSOM, which `style-src` without `'unsafe-inline'` does not block; `check-css.mjs` fails on any further `style=` in `src/**/*.tsx`. No `@import url(http…)`, no `url()` to anything but relative bundled files, no web fonts (system font stack only). `ci/check-csp.mjs` must stay green with no change to `tauri.conf.json` or `credential.html`.
2. **No hard-coded colors outside token blocks.** Every color in any `.css` under `app/ui/src` is `var(--…)`, `currentColor`, `transparent` or `inherit`, except inside the `:root` token blocks of `styles/tokens.css` and `credential/credential.css`. The existing `#8884`, `#8881`, `#8886`, `#8a1c1c`, `#1c6b3a` go away.
3. **Queue-row height contract.** `QUEUE_ROW_REM = 7.5` (`src/approvals/Queue.tsx`) and the audit `ROW_REM` 4.25 (`src/audit/EventList.tsx`) stay. Do not change `html { font-size }` (stays the user-agent 100%), do not add vertical padding/margin/border to `.windowed-row`, `.queue-line`, `.queue-flags`, `.audit-line`, `.audit-row` beyond what exists (`.windowed-row` keeps exactly `border-bottom: 1px solid <token>`), and keep `.queue-line { height: 2rem }`, `.queue-flags { height: 3.5rem }`, `.audit-line { height: 2rem }`. Line-height inside them may be set but must keep text inside the fixed heights. `check-css.mjs` pins these declarations.
4. **Credential isolation (spec §10.3, PD-71).** `credential.css` is imported only by `src/credential/main.ts`; it never `@import`s anything from `src/shared`, and its content must differ from every main-bundle CSS file (comment in the file). `node ../../ci/check-credential-bundle.mjs <dist>` stays green.
5. **Accessibility.** WCAG 2.2 AA: text pairs ≥ 4.5:1, large text and UI-component boundaries (input borders, focus ring, badges' borders) ≥ 3:1, in both schemes, verified by `check-css.mjs`. Focus is always visible (`:focus-visible` ring of 2px `--focus` with 2px offset; never `outline: none` without a replacement). `@media (prefers-reduced-motion: reduce)` disables every transition/animation. Colour is never the only signal: banners, badges and status keep their text prefixes (`Caution:`, level words); styling only adds to them.
6. **Browser-neutral.** Plain CSS that renders the same in WebView2, WebKitGTK, WKWebView and a desktop browser (M12). No `-webkit-app-region`, no Tauri-only selectors except the existing `#__tauri_isolation__` rule (harmless in a browser). `color-scheme: light dark` on `:root` so native controls (scrollbars, date pickers, checkboxes) follow the scheme.
7. **Tests stay green; structure changes are deliberate.** Selectors used by tests and e2e must survive: `.batch-blocked`, `.batch-session`, `.as-json`, `.queue-item[aria-current="true"] .target`, `pre.params-text`, `section.audit-record`, iframes; e2e `ci/e2e-drive.py` uses `form.entry input`, `form.entry button.primary`, `div.result.ok` on the credential page. A task that has to change a test selector says so in its Files line and changes the test in the same commit.
8. **Out of scope.** The preview document's CSS (`crates/preview`, `preview.css`, hash-pinned in `tauri.conf.json` via `check-csp.mjs --write`) is not touched: it renders agent content in a sandboxed iframe and has its own contract. No copy/text changes, no new strings, no behaviour changes, no i18n.

## UI gates (exact commands)

Run from `C:\Code\atlas-duck-m11\app\ui` (or the worktree's `app\ui`) in PowerShell, with `$node = 'C:\Users\oezcan\AppData\Local\Author Software\nvm\installs\v24.22.0\node.exe'` and `$out = '<scratchpad>\m11-dist'` (never build into the worktree's `dist` while the main checkout's `dist` is junction-adjacent):

| Gate | Command |
|---|---|
| G1 types | `& $node node_modules\typescript\bin\tsc --noEmit` |
| G2 lint | `& $node node_modules\eslint\bin\eslint.js .` |
| G3 sinks | `& $node scripts\check-html-sinks.mjs src` |
| G4 css (from Task 1) | `& $node scripts\check-css.mjs src` |
| G5 unit | `& $node node_modules\vitest\vitest.mjs run` |
| G6 node tests | `& $node --test scripts\check-html-sinks.test.mjs scripts\eslint-credential.test.mjs scripts\check-css.test.mjs` |
| G7 build | `& $node node_modules\vite\bin\vite.js build --outDir $out --emptyOutDir` |
| G8 bundle | `& $node ..\..\ci\check-credential-bundle.mjs $out` |
| G9 csp | `& $node ..\..\ci\check-csp.mjs --dist $out` (run from the repo root with `app\ui\…` adjusted: `& $node ci\check-csp.mjs --dist $out`) |

"All UI gates" = G1–G9. Tasks 0–1 run the subset that exists. CI runs the same through `npm run lint`, `npm test`, `npm run test:scripts`, `npm run build`, `npm run check:bundle` (Task 1 wires G4/G6 into those scripts and into `.github/workflows/ci.yml` if the workflow lists the node tests explicitly).

---

## What exists (surveyed on m10-audit-export-packaging)

| Area | Now | M11 does |
|---|---|---|
| Entry HTML | `setup/settings/approvals/audit/onboarding/running_scripts.html` each `<link rel="stylesheet" href="/src/shared/app.css">`; `credential.html` carries the §10.3 meta CSP and no link (CSS comes from `import './credential.css'` in `src/credential/main.ts`) | unchanged; `app.css` becomes an `@import` index |
| `src/shared/app.css` | ~95 lines of functional rules (flex rows, fixed heights, `#888x` borders), no font, no colors, no buttons | split into `styles/*.css`, all functional rules kept |
| `src/credential/credential.css` | `system-ui` font, 34rem max width, `.facts` grid, `.field`, `.actions`, `.result.ok/.failed`, `#8a1c1c` / `#1c6b3a` | token copy + same component look as the main bundle |
| Window roots | `<main>` in Settings, Setup (`<header><h1>` inside), Onboarding, Running scripts, Approvals (`App.tsx` `<main><h1 tabIndex=-1>`), Audit (`<main className="audit">`); `Header.tsx` = `<header className="app-header"><nav>` + `ul.banner` | add `className="window window-<name>"` to each `<main>` |
| Sections | Settings and Wizard steps are `<section aria-label>` siblings of `<main>`; Approvals `section.batch/.edit-form/.raw-pager/.recent/.request-tab`; Audit `section.audit-*` | `main > section` styled as cards via CSS; no wrapper needed |
| Inline styles | `Windowed.tsx` (3 props), `Tree.tsx` (1 prop) | allow-listed, unchanged |
| Row contract | `QUEUE_ROW_REM 7.5`, `.queue-line 2rem`, `.queue-flags 3.5rem`; audit `ROW_REM 4.25`, `.audit-line 2rem` | pinned by `check-css.mjs` |

---

## Design tokens (exact values; Task 1 writes them)

Light scheme on `:root`, dark scheme on `:root` inside `@media (prefers-color-scheme: dark)`. Every color token below exists in both.

```css
:root {
  color-scheme: light dark;
  /* type */
  --font-sans: system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", "Helvetica Neue", Arial, sans-serif;
  --font-mono: ui-monospace, "Cascadia Mono", "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --text-xs: 0.75rem;   --text-sm: 0.875rem; --text-md: 1rem;
  --text-lg: 1.125rem;  --text-xl: 1.375rem; --text-2xl: 1.75rem;
  --leading: 1.5; --leading-tight: 1.25;
  --weight-normal: 400; --weight-medium: 500; --weight-bold: 600;
  /* space (4px grid, in rem so it scales with the user's font size) */
  --space-1: 0.25rem; --space-2: 0.5rem; --space-3: 0.75rem; --space-4: 1rem;
  --space-5: 1.5rem;  --space-6: 2rem;   --space-7: 3rem;
  /* shape */
  --radius-sm: 4px; --radius-md: 6px; --radius-lg: 10px; --radius-pill: 999px;
  --border-width: 1px;
  --content-max: 60rem; --form-max: 36rem; --control-height: 2.25rem;
  --focus-width: 2px; --focus-offset: 2px;
  --shadow-card: 0 1px 2px rgb(0 0 0 / 0.06), 0 1px 3px rgb(0 0 0 / 0.08);
  --duration: 120ms;
  /* light palette */
  --bg: #ffffff;          --surface: #f6f8fa;      --surface-raised: #ffffff; --surface-sunken: #eef1f4;
  --text: #1f2328;        --text-muted: #57606a;   --text-on-accent: #ffffff;
  --border: #d0d7de;      --border-strong: #6e7781;
  --accent: #0a58ca;      --accent-hover: #084298; --accent-subtle: #e7f0fd;
  --danger: #b42318;      --danger-hover: #8f1c13; --danger-subtle: #fdecea; --text-on-danger: #ffffff;
  --warning: #7a4d00;     --warning-subtle: #fff4d6; --warning-border: #b07000;
  --success: #1a7f37;     --success-subtle: #e6f4ea;
  --info: #0a58ca;        --info-subtle: #e7f0fd;
  --focus: #0a58ca;
  --row-selected: #e7f0fd; --row-hover: #f3f5f7;
}
@media (prefers-color-scheme: dark) {
  :root {
    --shadow-card: 0 1px 2px rgb(0 0 0 / 0.5);
    --bg: #16181d;          --surface: #1e2128;      --surface-raised: #252932; --surface-sunken: #121418;
    --text: #e6e8eb;        --text-muted: #a4acb6;   --text-on-accent: #0b1220;
    --border: #3b414c;      --border-strong: #808996;
    --accent: #6eb0ff;      --accent-hover: #9ccaff; --accent-subtle: #1b2c44;
    --danger: #ff8b82;      --danger-hover: #ffb0a9; --danger-subtle: #3b1d1b; --text-on-danger: #1a0b0a;
    --warning: #f3c063;     --warning-subtle: #33280f; --warning-border: #c99a3a;
    --success: #6fd08c;     --success-subtle: #15301e;
    --info: #6eb0ff;        --info-subtle: #1b2c44;
    --focus: #6eb0ff;
    --row-selected: #1b2c44; --row-hover: #222630;
  }
}
```

`--shadow-card` is the one token allowed to carry `rgb()` (it is in the token block). **Contrast pairs checked by `check-css.mjs` in both schemes** (fail below the threshold; if a pair fails, the implementer adjusts the foreground value in steps of 5% lightness toward more contrast, records the final value in the commit message, and changes this table in the same commit):

| Foreground | Background(s) | Min |
|---|---|---|
| `--text` | `--bg`, `--surface`, `--surface-raised`, `--surface-sunken`, `--row-selected`, `--row-hover` | 4.5 |
| `--text-muted` | `--bg`, `--surface`, `--surface-raised` | 4.5 |
| `--accent` (links, ghost buttons) | `--bg`, `--surface`, `--surface-raised` | 4.5 |
| `--text-on-accent` | `--accent`, `--accent-hover` | 4.5 |
| `--text-on-danger` | `--danger`, `--danger-hover` | 4.5 |
| `--danger` | `--bg`, `--surface`, `--danger-subtle` | 4.5 |
| `--warning` | `--bg`, `--warning-subtle` | 4.5 |
| `--success` | `--bg`, `--success-subtle` | 4.5 |
| `--info` | `--info-subtle` | 4.5 |
| `--text` | `--warning-subtle`, `--danger-subtle`, `--success-subtle`, `--info-subtle` | 4.5 |
| `--border-strong` (input borders) | `--bg`, `--surface`, `--surface-raised` | 3 |
| `--focus` | `--bg`, `--surface`, `--surface-raised`, `--accent-subtle` | 3 |
| `--warning-border` | `--bg`, `--warning-subtle` | 3 |

`--border` (decorative card/table dividers) is exempt: it is never the only boundary of an interactive control.

---

## Class vocabulary (new, shared)

Buttons: plain `<button>` = secondary; `.primary`, `.danger`, `.ghost` modifiers (`.primary` already exists on the credential page and is used by e2e). Layout: `.window` + `.window-<name>` on `<main>`, `.page-header`, `.actions` (one action row: flex, wrap, gap, top margin, primary action last on the right in LTR is **not** required — keep DOM order, align start), `.stack` (vertical flow with `--space-3` gaps), `.field` (label above control), `.field-hint`, `.field-error`, `.card`. Feedback: `.notice` + `.notice-info|warning|danger|success` (block banner with left border + subtle background), `.badge` (existing) + `.badge-caution` (existing), `.empty-state`, `.toast` (fixed-position live region; only if a window already shows a transient message — none does today, so `.toast` is defined but unused; documented for M12). Tables: `table` base style + `.table-compact`. Code: `code`, `pre`, `kbd`.

Mapping of existing state classes onto the new look (CSS only, no JSX change): `.caution-strip` → warning notice look; `.banner-caution` → warning text color + bold; `.banner-info` → muted; `.audit-field-error` → `--danger`; `.audit-credential-line` → left border `--warning-border`; `[role="alert"]` → danger notice look when it is a `<p>` directly in `main` or a `section`; `[role="status"]` → info notice look under the same rule.

---

### Task 0: Branch, junction, baseline

**Model:** lead (no subagent).

**Files:** none committed.

- [ ] **Step 1:** `git worktree add C:\Code\atlas-duck-m11 -b m11-ui-visual-design master` (after the M10 merge), junction `app\ui\node_modules` → `C:\Code\atlas-duck\app\ui\node_modules` (`cmd /c mklink /J`), confirm `package-lock.json` equal.
- [ ] **Step 2:** Run G1, G2, G3, G5, G6 (without `check-css.test.mjs`), G7, G8, G9; record the vitest test count as the baseline in the ledger.
- [ ] **Step 3:** Baseline screenshots: the lead builds once (`cargo build --release -p atlas-duck-app --features tauri/custom-protocol --locked -j 4`, shared `CARGO_TARGET_DIR`) and screenshots every window (Setup on a fresh data dir via the dev env var the e2e uses, then Settings, Approvals with the mock queue, Audit, Running scripts, Onboarding, Credential) into `<scratchpad>\m11-shots\before\`. These are the "before" set for Task 12.

### Task 1: CSS checker (tests first) and token layer

**Model:** Sonnet (medium).

**Files:** Create `app/ui/scripts/check-css.mjs`, `app/ui/scripts/check-css.test.mjs`, `app/ui/src/shared/styles/tokens.css`; Modify `app/ui/src/shared/app.css` (top: `@import './styles/tokens.css';` then the existing rules, unchanged otherwise for now), `app/ui/package.json` (`lint`: append `&& node scripts/check-css.mjs src`; `test:scripts`: append `scripts/check-css.test.mjs`), `.github/workflows/ci.yml` only if it names the node test files explicitly instead of calling `npm run test:scripts`.

**Interfaces:** `check-css.mjs <srcDir>` exits 0/1, one violation per stdout line, uses only `node:fs`, `node:path`, `node:url`. Exports for the test: `parseTokens(css) → { light: Map, dark: Map }`, `contrast(hexA, hexB) → number` (WCAG relative luminance, sRGB linearisation with 0.04045 threshold; alpha hex not allowed in token colors except `--shadow-card`), `checkAll(srcDir) → string[]`.

**Rules it enforces:**
1. `styles/tokens.css` defines every color token listed above in the light `:root` block and in the dark `@media (prefers-color-scheme: dark) { :root { … } }` block; same name set in both; same for the token block in `credential/credential.css` (the credential set may be a subset but every token it defines must be in both of its schemes).
2. Contrast table above, both schemes, both token sources (credential only for pairs whose tokens it defines).
3. No color literal (`#hex`, `rgb(`, `rgba(`, `hsl(`, `hsla(`, `oklch(`, `color-mix(`, or a CSS named color from a fixed list of the 148 names, matched as whole words in a declaration value) outside a token block, in any `*.css` under `srcDir`. Comments are stripped first.
4. No `outline: none` / `outline: 0` unless the same rule or a `:focus-visible` rule for the same selector sets an outline or box-shadow using `--focus`.
5. Every `transition`/`animation` declaration is neutralised under `@media (prefers-reduced-motion: reduce)` (rule: the file `styles/base.css` contains the global reduce block from Task 2; any other file with `transition`/`animation` fails unless that block exists).
6. Row contract: `.queue-line` has `height: 2rem`, `.queue-flags` `height: 3.5rem`, `.audit-line` `height: 2rem`; `.windowed-row` has no `padding`, `margin` or `border-top`; no rule sets `font-size` on `html` or `:root`. Also reads `src/approvals/Queue.tsx` and asserts `QUEUE_ROW_REM = 7.5`.
7. No `@import` of a URL with a scheme, no `url(` other than relative paths, no `@font-face`.
8. `style=` occurrences in `src/**/*.tsx` (excluding `*.test.tsx`): only in `shared/list/Windowed.tsx` and `approvals/redaction/Tree.tsx`, with counts 3 and 1.
9. `credential/credential.css` contains no `@import`.

- [ ] **Step 1: Failing tests** in `check-css.test.mjs` (node:test, temp dirs under `os.tmpdir()`): `contrast_known_values` (`#000`/`#fff` = 21, `#777777`/`#ffffff` ≈ 4.48), `missing_dark_token_fails`, `hex_outside_token_block_fails`, `named_color_outside_token_block_fails`, `currentColor_and_var_pass`, `low_contrast_pair_fails_with_pair_named`, `outline_none_without_focus_visible_fails`, `transition_without_reduce_block_fails`, `queue_line_height_changed_fails`, `windowed_row_padding_fails`, `html_font_size_fails`, `remote_import_fails`, `font_face_fails`, `new_style_prop_fails`, `repo_src_passes` (runs `checkAll` on the real `src` — expected to fail until Step 3).
- [ ] **Step 2:** Implement `check-css.mjs` until all but `repo_src_passes` pass.
- [ ] **Step 3:** Write `styles/tokens.css` exactly as in "Design tokens"; import it from `app.css`; replace the hard-coded colors in `app.css` (`#8884` → `var(--border)`, `#8881` → `var(--row-selected)`, `#8886` → `var(--border)`) and give `credential.css` its token block (light + dark, the subset: `--bg --surface --surface-raised --text --text-muted --text-on-accent --border --border-strong --accent --accent-hover --danger --danger-subtle --success --success-subtle --warning --warning-subtle --focus --text-on-danger --danger-hover`, plus the non-color tokens it uses), replacing `#8a1c1c` → `var(--danger)`, `#1c6b3a` → `var(--success)`. Now `repo_src_passes` passes. Fix any contrast failure per the rule under the token table.
- [ ] **Step 4: Gates:** all UI gates.
- [ ] **Commit** `feat(ui): design tokens and CSS checker (M11)` (+ trailer).

### Task 2: Base element styles

**Model:** Sonnet (medium).

**Files:** Create `app/ui/src/shared/styles/base.css`; Modify `app/ui/src/shared/app.css` (`@import './styles/base.css';` after tokens).

- [ ] **Step 1:** `base.css`:
  - `*, *::before, *::after { box-sizing: border-box; }` — **check first** that no fixed-height rule depends on content-box: `.windowed-row` already sets `box-sizing: border-box`; `.tree-toggle`/`.tree-leaf` widths and `.badge-fixed` min-width are unaffected by border-box in practice (no padding on them); the reviewer checks the queue in the Task 12 screenshot.
  - `body { margin: 0; font-family: var(--font-sans); font-size: var(--text-md); line-height: var(--leading); color: var(--text); background: var(--bg); -webkit-text-size-adjust: 100%; }`
  - Headings: `h1 { font-size: var(--text-2xl); }`, `h2 { --text-xl }`, `h3 { --text-lg }`, `h4–h6 { --text-md }`; all `line-height: var(--leading-tight); font-weight: var(--weight-bold); margin: 0 0 var(--space-3);`. `h1[tabindex="-1"]:focus { outline: none; }` is **not** allowed by rule 4; instead `h1:focus:not(:focus-visible) { outline: none; }` plus `h1:focus-visible` uses the ring (Approvals moves focus to its heading programmatically).
  - `p, ul, ol, dl, pre, table, fieldset { margin: 0 0 var(--space-3); }`; `ul, ol { padding-left: var(--space-5); }`.
  - Links: `a { color: var(--accent); text-underline-offset: 2px; } a:hover { color: var(--accent-hover); }`.
  - `code, kbd, pre, samp { font-family: var(--font-mono); font-size: 0.9em; }`; `code { background: var(--surface-sunken); padding: 0 var(--space-1); border-radius: var(--radius-sm); }`; `pre { background: var(--surface-sunken); padding: var(--space-3); border-radius: var(--radius-md); overflow: auto; }` — but `pre.raw-text`, `pre.params-text`, `.onboarding-text` keep their existing `white-space`/`max-height` rules (they come later in the cascade); `kbd { border: 1px solid var(--border-strong); border-bottom-width: 2px; border-radius: var(--radius-sm); padding: 0 var(--space-1); }`.
  - Tables: `table { border-collapse: collapse; width: 100%; } th, td { text-align: start; padding: var(--space-2) var(--space-3); border-bottom: 1px solid var(--border); vertical-align: top; } th { font-weight: var(--weight-bold); color: var(--text-muted); font-size: var(--text-sm); } .table-compact th, .table-compact td { padding: var(--space-1) var(--space-2); }`.
  - Focus: `:focus-visible { outline: var(--focus-width) solid var(--focus); outline-offset: var(--focus-offset); }`.
  - `::selection { background: var(--accent-subtle); color: var(--text); }`.
  - `hr { border: 0; border-top: 1px solid var(--border); margin: var(--space-4) 0; }`.
  - `[hidden] { display: none !important; }`.
  - Reduced motion: `@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: 0.01ms !important; animation-iteration-count: 1 !important; transition-duration: 0.01ms !important; scroll-behavior: auto !important; } }`.
  - `iframe { border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--surface-raised); }` (the existing `.detail-panel iframe` / `.audit-payload iframe` rules keep width/height; their `border` values become `var(--border)`).
- [ ] **Step 2: Gates:** all UI gates. Vitest is unaffected (jsdom ignores CSS); `check-css.mjs` must pass.
- [ ] **Commit** `feat(ui): base element styles (M11)` (+ trailer).

### Task 3: Buttons and form controls

**Model:** Sonnet (medium).

**Files:** Create `app/ui/src/shared/styles/controls.css`; Modify `app.css` (import after base).

- [ ] **Step 1:** Buttons (all `button`, `input[type="button"|"submit"|"reset"]`, excluding `.tree-select` which keeps its reset look and `[role="tab"]` which Task 6 styles):
  - Secondary (default): `font: inherit; font-weight: var(--weight-medium); min-height: var(--control-height); padding: 0 var(--space-4); border: 1px solid var(--border-strong); border-radius: var(--radius-md); background: var(--surface-raised); color: var(--text); cursor: pointer; transition: background-color var(--duration), border-color var(--duration); display: inline-flex; align-items: center; justify-content: center; gap: var(--space-2);` hover `background: var(--surface)`, active `background: var(--surface-sunken)`.
  - `.primary`: `background: var(--accent); border-color: var(--accent); color: var(--text-on-accent);` hover `var(--accent-hover)`.
  - `.danger`: `background: var(--danger); border-color: var(--danger); color: var(--text-on-danger);` hover `var(--danger-hover)`.
  - `.ghost`: transparent background and border, `color: var(--accent)`.
  - `:disabled, [aria-disabled="true"]`: `opacity: 0.55; cursor: not-allowed;` and no hover change (`:disabled:hover` resets background). Note: `opacity` on disabled controls is WCAG-exempt (inactive components).
  - Small buttons inside fixed-height rows: `.queue-line button, .audit-line button, .tree-row button, .raw-nav button { min-height: 0; padding: 0 var(--space-2); }` so a 2rem line still fits (control height 2.25rem would overflow a 2rem line — this rule is mandatory, and the reviewer checks it against rule 6).
  - `.audit-row button[aria-current="true"]` keeps `font-weight: 700` and gains `background: var(--row-selected)`.
- [ ] **Step 2:** Inputs: `input:not([type="checkbox"]):not([type="radio"]):not([type="button"]):not([type="submit"]):not([type="reset"]):not([type="file"]), select, textarea { font: inherit; color: var(--text); background: var(--surface-raised); border: 1px solid var(--border-strong); border-radius: var(--radius-md); min-height: var(--control-height); padding: var(--space-1) var(--space-3); max-width: 100%; }`; `textarea { min-height: 5rem; resize: vertical; line-height: var(--leading); }`; `select { padding-right: var(--space-5); }` (native arrow kept; no background-image since `url()` data images are allowed by `img-src data:` but not needed); `::placeholder { color: var(--text-muted); opacity: 1; }`; `[aria-invalid="true"] { border-color: var(--danger); }`; `input:disabled, select:disabled, textarea:disabled { background: var(--surface-sunken); color: var(--text-muted); }`.
  - Checkboxes/radios: `accent-color: var(--accent); width: 1.1rem; height: 1.1rem; margin: 0;` and `label:has(> input[type="checkbox"]), label:has(> input[type="radio"]) { display: inline-flex; align-items: center; gap: var(--space-2); }`. (`:has` is supported by WebView2, WebKitGTK ≥ 2.42, WKWebView 15.4+, every current browser; where unsupported the label just stays inline.)
  - `fieldset { border: 1px solid var(--border); border-radius: var(--radius-md); padding: var(--space-3) var(--space-4); min-width: 0; } legend { padding: 0 var(--space-1); font-weight: var(--weight-bold); }`; `.settings-guard` keeps `margin:0; padding:0; border:0` (it must stay invisible; it is the Guard wrapper).
- [ ] **Step 3: Gates:** all UI gates.
- [ ] **Commit** `feat(ui): button and form-control styles (M11)` (+ trailer).

### Task 4: Form layout and page layout primitives

**Model:** Sonnet (medium).

**Files:** Create `app/ui/src/shared/styles/layout.css`; Modify `app.css` (import after controls).

- [ ] **Step 1: Page layout.** `.window { max-width: var(--content-max); margin: 0 auto; padding: var(--space-5) var(--space-5) var(--space-7); }` and `@media (max-width: 40rem) { .window { padding: var(--space-4); } }`. `.window > h1, .page-header { margin-bottom: var(--space-4); }`. `.page-header { display: flex; flex-wrap: wrap; align-items: baseline; justify-content: space-between; gap: var(--space-2) var(--space-4); }`.
- [ ] **Step 2: Cards.** `.window > section, .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-4) var(--space-5); margin: 0 0 var(--space-4); box-shadow: var(--shadow-card); }`; `.window > section > h2:first-child, .card > h2:first-child { margin-top: 0; font-size: var(--text-lg); }`; nested sections inside a card get no card look (`.window > section section { background: none; border: 0; padding: 0; box-shadow: none; }`) except those with their own class rules later.
- [ ] **Step 3: Forms — labels above fields.** `.window form label, .field { display: flex; flex-direction: column; align-items: flex-start; gap: var(--space-1); margin: 0 0 var(--space-3); max-width: var(--form-max); }`; control inside fills: `.window form label > input:not([type="checkbox"]):not([type="radio"]), .window form label > select, .window form label > textarea, .field > input…, .field > select, .field > textarea { width: 100%; }`; checkbox labels keep the inline row from Task 3 (the `:has` rule must win: put it after with equal or higher specificity: `.window form label:has(> input[type="checkbox"])` `flex-direction: row; align-items: center;`). `.field-hint { font-size: var(--text-sm); color: var(--text-muted); }` `.field-error { font-size: var(--text-sm); color: var(--danger); font-weight: var(--weight-medium); }`.
  - **Verify against the DOM** before relying on `form label`: grep `app/ui/src/{settings,setup}` for `<label` and record whether controls are nested in labels or linked with `htmlFor`. For `htmlFor` siblings, add the rule `.window form label:not(:has(input, select, textarea)) { margin-bottom: var(--space-1); }` and wrap label+control in `<div className="field">` in Task 7/8 (that is a permitted wrapper change).
- [ ] **Step 4: Action row.** `.actions, .edit-actions, .detail-actions, .batch-actions, .audit-actions, .redaction-actions { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2); margin-top: var(--space-4); }` (the existing per-class rules keep their margins where tests/screens need them; this rule only adds the shared look; keep the later, more specific rules winning).
- [ ] **Step 5: Utilities.** `.stack > * + * { margin-top: var(--space-3); }`, `.muted { color: var(--text-muted); }`, `.visually-hidden` unchanged (moved here from `app.css`).
- [ ] **Step 6: Gates:** all UI gates.
- [ ] **Commit** `feat(ui): page, card, form and action-row layout (M11)` (+ trailer).

### Task 5: Feedback components (notices, badges, banners, empty states, toast)

**Model:** Sonnet (medium).

**Files:** Create `app/ui/src/shared/styles/components.css`; Modify `app.css` (import after layout; move `.badge*`, `.banner*`, `.agent-text*`, `.caution-strip` out of `app.css` into this file, values kept, colors tokenised).

- [ ] **Step 1: Notices.** `.notice { display: block; padding: var(--space-3) var(--space-4); border: 1px solid var(--border); border-left-width: 4px; border-radius: var(--radius-md); background: var(--surface); margin: 0 0 var(--space-4); }` with `.notice-info { border-left-color: var(--info); background: var(--info-subtle); }`, `.notice-warning { border-left-color: var(--warning-border); background: var(--warning-subtle); }`, `.notice-danger { border-left-color: var(--danger); background: var(--danger-subtle); }`, `.notice-success { border-left-color: var(--success); background: var(--success-subtle); }`; text stays `var(--text)` (pairs checked).
  - Apply by selector, no JSX: `.caution-strip` = `.notice-warning` declarations (keep its `margin: 0.5rem 0` → `var(--space-2) 0`; drop `2px solid currentColor`); `.window > [role="alert"], .window > section > [role="alert"]` = `.notice-danger`; `.window > [role="status"], .window > section > [role="status"]` = `.notice-info`. Exclude `.visually-hidden` (`:not(.visually-hidden)`) — the Wizard's live region must stay invisible.
- [ ] **Step 2: Header banner** (`Header.tsx`, Approvals only): `.app-header { position: sticky; top: 0; z-index: 1; background: var(--surface); border-bottom: 1px solid var(--border); }`; `.app-header nav { display: flex; flex-wrap: wrap; gap: var(--space-2); padding: var(--space-2) var(--space-5); max-width: var(--content-max); margin: 0 auto; }`; `.banner { list-style: none; margin: 0 auto; padding: 0 var(--space-5) var(--space-2); max-width: var(--content-max); }`; `.banner li { padding: var(--space-1) 0; }`; `.banner-caution { color: var(--warning); font-weight: var(--weight-bold); }`; `.banner-info { color: var(--text-muted); }`. Is the Quit button `.danger`? **No** (decision: Quit is a normal window action, not a destructive data action; it stays secondary).
- [ ] **Step 3: Badges.** Keep `.badge` metrics (`flex: none; display: inline-block; white-space: nowrap; font-size: 0.8em; padding: 0 0.35rem; margin: 0 0.25rem`) so queue lines keep their width; restyle: `border: 1px solid var(--border-strong); border-radius: var(--radius-pill); background: var(--surface-raised); color: var(--text); line-height: 1.4;`. `.badge-caution { color: var(--warning); border-color: var(--warning-border); background: var(--warning-subtle); font-weight: var(--weight-bold); }`. `.badge-fixed` unchanged.
- [ ] **Step 4: Empty state and toast.** `.empty-state { padding: var(--space-6) var(--space-4); text-align: center; color: var(--text-muted); border: 1px dashed var(--border); border-radius: var(--radius-lg); }`. `.toast { position: fixed; inset-inline-end: var(--space-4); inset-block-end: var(--space-4); max-width: 24rem; padding: var(--space-3) var(--space-4); background: var(--surface-raised); color: var(--text); border: 1px solid var(--border-strong); border-radius: var(--radius-md); box-shadow: var(--shadow-card); }` (defined, unused until a window needs it; documented in the file header).
  - **Find existing empty-list texts:** grep `src/**/text*.ts*` and `strings.ts` for `empty`, `none`, `No ` and, where the element is a plain `<p>` that only shows when a list is empty (Queue, Recent, Running scripts, Audit list, Instances), add `className="empty-state"` in Tasks 6–10 as listed there.
- [ ] **Step 5: Gates:** all UI gates.
- [ ] **Commit** `feat(ui): notices, banner, badges, empty state (M11)` (+ trailer).

### Task 6: Window pass — Approvals

**Model:** Sonnet (medium).

**Files:** Create `app/ui/src/shared/styles/approvals.css`; Modify `app.css` (move every approvals rule — `.windowed-row` through `.batch-*` — into `approvals.css` and import it), `src/approvals/App.tsx` (`<main className="window window-approvals">`), the empty-list `<p>`s in `src/approvals/{Queue,Recent}.tsx` (`className="empty-state"`, only if they exist as described in Task 5 Step 4).

- [ ] **Step 1:** Layout: on viewports ≥ 64rem, `.window-approvals` is wider (`max-width: 80rem`) and its list/detail area becomes two columns **only if** App.tsx already renders queue and detail as siblings under one parent; if they are not siblings, keep one column (no restructuring in this milestone). Record which in the commit message.
- [ ] **Step 2:** Queue: `.windowed-row { border-bottom: 1px solid var(--border); }` (contract), `.queue-item` hover `var(--row-hover)`, `.queue-item[aria-current="true"] { background: var(--row-selected); box-shadow: inset 3px 0 0 var(--accent); }` (inset shadow, not border, so the row height is unchanged), `.queue-group { color: var(--text-muted); font-size: var(--text-sm); text-transform: none; }`, `.queue-line, .audit-line { line-height: 2rem; }` is **not** added (height already fixes it; `align-items: center` handles it). `.target` gets `font-family: var(--font-mono); font-size: var(--text-sm);`.
- [ ] **Step 3:** Detail: `.detail { padding: var(--space-4); background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); }`; tabs: `.detail [role="tablist"] { display: flex; gap: var(--space-1); border-bottom: 1px solid var(--border); margin-bottom: var(--space-3); }`, `.detail [role="tab"] { background: none; border: 0; border-bottom: 2px solid transparent; border-radius: 0; min-height: var(--control-height); color: var(--text-muted); }`, `[aria-selected="true"] { color: var(--text); border-bottom-color: var(--accent); font-weight: var(--weight-bold); text-decoration: none; }` (the selected tab keeps a non-colour signal: weight + underline bar).
- [ ] **Step 4:** Decision bar: give the approve button `className="primary"` and the deny button `className="danger"` in `DecisionBar.tsx` **only if** each is a single `<button>` whose text is the approve/deny label; tests find buttons by role/name, so classes do not break them. Deny dialog, edit form, redaction panel, batch: replace `#888x` borders with `var(--border)` and radius `var(--radius-md)`; `.edit-form .json-input` uses `var(--font-mono)`; `.keyboard-legend` uses `kbd`-like look via existing markup (no JSX change) and `color: var(--text-muted)`.
- [ ] **Step 5:** `.tree-select[aria-pressed="true"] { outline: 2px solid var(--focus); outline-offset: -2px; background: var(--row-selected); }` (rule 4 compliant: an outline is set).
- [ ] **Step 6: Gates:** all UI gates; vitest count equals the Task 0 baseline (no test changed).
- [ ] **Commit** `feat(ui): Approvals window layout pass (M11)` (+ trailer).

### Task 7: Window pass — Settings

**Model:** Sonnet (medium).

**Files:** Create `app/ui/src/shared/styles/settings.css`; Modify `app.css` (import), `src/settings/Settings.tsx` (both `<main>` → `className="window window-settings"`), and per section file under `src/settings/` only: (a) a visible `<h2>` exists or is added? **No new text:** if a section has only `aria-label`, it stays without a visible heading (adding visible text is a copy change, out of scope); (b) `className="field"` wrappers around label/control pairs that are siblings (per Task 4 Step 3 finding); (c) `className="actions"` on the element that holds a section's buttons when it is a `<div>`/`<p>` with two or more buttons; (d) `className="primary"` on the one submit button per form (Add instance, Save limits, Save retention, Save script limits, Choose anchor dir), `className="danger"` on destructive buttons (Remove instance, Prune now, the Removal flow's final confirm, Forget token) — identify by the `T.*` label keys in `src/settings/text.tsx` and list them in the commit message.

- [ ] **Step 1:** Grep the section components and make the class changes above; no other JSX change.
- [ ] **Step 2:** `settings.css`: `.window-settings > section` cards from Task 4; instance list rows (whatever `Instances.tsx` renders — table or list) get `table` base or `.card`-free list style: `ul` → `list-style: none; padding: 0;` with `li { padding: var(--space-2) 0; border-bottom: 1px solid var(--border); display: flex; flex-wrap: wrap; gap: var(--space-2); align-items: center; }` scoped `.window-settings section ul:not(.consequences)`. `.audit-job` (used by Removal) gets the `.notice-info` look.
- [ ] **Step 3: Tests:** `Settings.test.tsx` and `Removal.test.tsx` must pass unchanged; if one queries by a structure that a `field` wrapper changes (e.g. `label.nextElementSibling`), update that test in this commit and say why.
- [ ] **Step 4: Gates:** all UI gates.
- [ ] **Commit** `feat(ui): Settings window layout pass (M11)` (+ trailer).

### Task 8: Window pass — Setup wizard

**Model:** Sonnet (medium).

**Files:** Create `app/ui/src/shared/styles/setup.css`; Modify `app.css` (import), `src/setup/Wizard.tsx` (both `<main>` → `className="window window-setup"`, the inner `<header>` → `className="page-header"`), `src/setup/SetupInstances.tsx` (same rules as Task 7: `field`, `actions`, `primary` on the step's forward button — the "Continue"/"Next"/"Create" button of each step; `danger` on none: the wizard has no destructive action except the passphrase restore which is not destructive to existing data). `Quit` stays secondary.

- [ ] **Step 1:** `.window-setup { max-width: 44rem; }` (a wizard reads better narrow); each step `section` is a card; the step's `h2` (if rendered by the Panel) at `--text-xl`; passphrase fields full width up to `--form-max`; the recovery-note step's note text (`pre` or `code`) uses the base `pre` look with `user-select: all` **only if** it is already a `pre`/`code` element.
- [ ] **Step 2:** The Wizard live region (`p.visually-hidden[aria-live]`) must remain visually hidden: confirm `.window > [role="status"]` from Task 5 does not match it (it has no role; it uses `aria-live`), and `state.notice`/`refused_count` `role="status"` paragraphs get the info notice look.
- [ ] **Step 3: Tests:** `Wizard.test.tsx` unchanged and green.
- [ ] **Step 4: Gates:** all UI gates.
- [ ] **Commit** `feat(ui): Setup wizard layout pass (M11)` (+ trailer).

### Task 9: Window pass — Audit

**Model:** Sonnet (medium).

**Files:** Create `app/ui/src/shared/styles/audit.css`; Modify `app.css` (move every `.audit*` rule into `audit.css`, import), `src/audit/Audit.tsx` (`<main className="audit window window-audit">` — keep `audit`, the existing rules and the injection test depend on it), `src/audit/Filters.tsx` (`className="primary"` on the Apply submit button), `src/audit/Incidents.tsx` (`primary` on the acknowledge submit), `src/audit/ExportBackup.tsx` (`primary` on Export…/Back up…; Restore backup… stays secondary — its tests find it by exact text `Restore backup…`, which a class does not change).

- [ ] **Step 1:** `.window-audit { max-width: 80rem; }`. Filters: `.audit-fields` grid `repeat(auto-fill, minmax(12rem, 1fr))` with `gap: var(--space-3) var(--space-4)`; `.audit-field` label above control (already column; add `font-size: var(--text-sm); color: var(--text-muted)` on its label text only if the label is a `<label>` element: `.audit-field > label`). `.audit-flags` = fieldset look from Task 3 (replace `#8886`). `.audit-field-error { color: var(--danger); }`.
- [ ] **Step 2:** List: `.audit-line` keeps `height: 2rem` (contract); `.audit-row` bottom border `var(--border)` only if it already had one in the row height math (it has none now: `ROW_REM 4.25` = 2 + 2 + 0.25 for the `.windowed-row` border-bottom — do not add another). Selected row: `.audit-row button[aria-current="true"]` from Task 3.
- [ ] **Step 3:** Record: `.audit-record` card look; `dl` grid kept; `dt { color: var(--text-muted); font-weight: var(--weight-medium); }`. `.audit-credential-line { border-left: 3px solid var(--warning-border); }`. `.audit-ack` = notice-warning look. `.audit-export-result code` keeps `overflow-wrap: anywhere`.
- [ ] **Step 4: Tests:** all `src/audit/*.test.tsx` unchanged and green (they query `section.audit-record`, iframes and button texts).
- [ ] **Step 5: Gates:** all UI gates.
- [ ] **Commit** `feat(ui): Audit window layout pass (M11)` (+ trailer).

### Task 10: Window pass — Running scripts and Onboarding

**Model:** Sonnet (medium).

**Files:** Create `app/ui/src/shared/styles/misc-windows.css`; Modify `app.css` (import; move `.onboarding-text`), `src/running_scripts/Running.tsx` (both `<main>` → `className="window window-running"`; the kill button `className="danger"`; the "no running scripts" paragraph `className="empty-state"` if it exists), `src/onboarding/Onboarding.tsx` (`<main className="window window-onboarding">`), `src/onboarding/OnboardingText.tsx` (`.onboarding-section` unchanged in JSX).

- [ ] **Step 1:** Running scripts: if the list is a `<table>`, base table styles apply; if `<ul>`, rows as in Task 7 Step 2 scoped to `.window-running`. Numbers/ids `font-variant-numeric: tabular-nums`.
- [ ] **Step 2:** Onboarding: `.onboarding-section` card look; `.onboarding-text` keeps `white-space: pre-wrap; overflow-wrap: anywhere; max-height: 32rem; overflow: auto;` and gets `font-family: var(--font-mono); font-size: var(--text-sm); background: var(--surface-sunken); border: 1px solid var(--border); border-radius: var(--radius-md); padding: var(--space-3);` (it is copy-paste text for agents).
- [ ] **Step 3: Tests:** `Running.test.tsx`, `Onboarding.test.tsx` unchanged and green.
- [ ] **Step 4: Gates:** all UI gates.
- [ ] **Commit** `feat(ui): Running scripts and Onboarding layout pass (M11)` (+ trailer).

### Task 11: Credential page restyle

**Model:** Sonnet (medium). Reviewer additionally checks spec §10.3 isolation.

**Files:** Modify `app/ui/src/credential/credential.css` only (no `page.ts` change unless a class is missing; `page.ts` builds the DOM imperatively and its classes `.title .facts .unusual .warning .locked .field .label .purpose-line .hint .actions .result .ok .failed`, `form.entry`, `button.primary` are the contract — e2e uses `form.entry input`, `form.entry button.primary`, `div.result.ok`).

- [ ] **Step 1:** Keep the token block from Task 1. Add: `*, *::before, *::after { box-sizing: border-box; }`; `body { font-family: <same stack, written out — no var import from shared>; color: var(--text); background: var(--bg); line-height: 1.5; margin: 0; padding: 1.5rem; max-width: 34rem; margin-inline: auto; }`; `.title { font-size: 1.375rem; }`; `.facts` in a surface card (`background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 0.75rem 1rem;`), `dt { color: var(--text-muted); }`; inputs and buttons with the same declarations as Task 3 written out (no shared import); `button.primary` accent; `.unusual, .warning { color: var(--danger); }`; `.result` notice look with `.ok` → success left border/background, `.failed` → danger; `:focus-visible` ring; the reduced-motion block.
- [ ] **Step 2:** The comment at the top states why the file duplicates the shared look (spec §10.3, PD-71) and that its content must not equal any main-bundle CSS file.
- [ ] **Step 3: Tests:** `credential.test.ts`, `ipc.test.ts`, `violations.test.ts`, `scripts/eslint-credential.test.mjs` unchanged and green.
- [ ] **Step 4: Gates:** all UI gates, G8 and G9 explicitly.
- [ ] **Commit** `feat(ui): credential page restyle (M11)` (+ trailer).

### Task 12: Visual check, e2e, docs

**Model:** lead (build and screenshots), Sonnet (medium) for the doc edit.

**Files:** Modify `docs/superpowers/plans/2026-10-07-atlas-duck-master-plan.md` (M11 status), the macOS GUI checklist doc that M6 created (grep `docs/` for "GUI checklist"; add a "visual design (M11)" item: light and dark appearance, focus ring visible on Tab, reduced motion honoured).

- [ ] **Step 1 (lead):** `cargo build --release -p atlas-duck-app --features tauri/custom-protocol --locked -j 4` with the shared `CARGO_TARGET_DIR`; launch, screenshot every window in light mode and again with Windows "dark" app mode into `<scratchpad>\m11-shots\after\{light,dark}\`; also Tab through Settings and Approvals and screenshot one focused control each; with "Show animations" off confirm nothing animates. Compare with `before\`.
- [ ] **Step 2 (lead) review checklist per window:** system font (no serif), labels above fields, one action row per form, cards separated, primary/danger buttons distinguishable without colour (text labels unchanged), queue rows not clipped (badges and two lines fully visible at 100% and 125% Windows scaling), audit rows not clipped, no horizontal scroll at 800 px width, dark mode readable, credential page centred and styled. Findings go back to the task that owns the window as a fix commit `fix(ui): <window> visual review (M11)`.
- [ ] **Step 3:** Browser parity (M12 readiness): open `<scratchpad>\m11-dist\settings.html` via `vite preview`-free static check — **not possible without a server and IPC**; instead record in the ledger that the CSS has no Tauri-only selector (rule checked by grep for `tauri` in `src/shared/styles` = only the isolation rule in `app.css`).
- [ ] **Step 4:** CI: push; Linux e2e (`ci/e2e-linux.sh` → `e2e-drive.py`) and Windows e2e green; Linux screenshot from the CI artefact if the e2e job uploads one, otherwise the lead asks the user for a Linux screenshot (exit criterion). macOS: checklist item only.
- [ ] **Step 5:** Master plan M11 status → done with the CI run URL; remove the `node_modules` junction (`cmd /c rmdir app\ui\node_modules`).
- [ ] **Commit** `docs: M11 status done` (+ trailer).

---

## Decisions taken in this plan (for review)

1. Token values are fixed here and checked by computed contrast; a failing pair is fixed by adjusting the foreground only.
2. Dark mode follows `prefers-color-scheme` only; no in-app theme switch (no new setting, no new string).
3. Quit and Restore backup… stay secondary buttons; only clearly destructive data actions are `.danger`.
4. No new visible headings or copy: sections with only `aria-label` stay without a visible `<h2>`. If the screenshot review finds Settings unreadable without headings, that is a follow-up with new strings, not M11.
5. The two existing React `style` props stay (CSSOM writes are CSP-safe); any new one fails `check-css.mjs`.
6. The credential page duplicates the token block instead of importing it (spec §10.3 isolation outranks DRY).
7. `preview.css` (agent-content preview iframe) is out of scope.
8. `.toast` is defined but unused; it exists for M12 (web approvals notifications).

# M17: accessible redesign

Design canvas: https://claude.ai/artifact/Dh6KSroMymxewdLTgVYwQB (17 artboards: every desktop
window, every server page, the user guide, light and dark).

## Goal

A calmer, more legible look for the desktop app, the server web pages and the user guide, and
WCAG 2.2 AA throughout, without changing behaviour. Approval safety rules (no Enter/Space approve,
the 1 s inert time, chords) stay exactly as they are.

## Constraints

- System font stack only: both CSPs allow fonts from `'self'` only, and `check-css.mjs` forbids `@font-face`.
- Colours only in `tokens.css` (and `credential.css`, `docs/user-guide/assets/help.css`), checked by `check-css.mjs`.
- Every size in rem. Row-height contracts (`.queue-line` 2rem, `.queue-flags` 3.5rem, `.audit-line` 2rem, `QUEUE_ROW_REM`, `ROW_REM`) unchanged.
- Every new string in `en/` and `de/` (GLOSSARY.md). Labels used by `ui-links.json` and e2e tests keep their text.

## Visual language

- Warm off-white page (`--bg #f7f7f5`), white cards with a 1px border, no shadows; dark scheme to match.
- One accent, blue `#1d4ed8` (dark `#8ab4ff`); warning amber, danger red, success green, all ≥4.5:1.
- Body 1.0625rem, h1 2rem, line height 1.55; controls 2.75rem (44px) high; radii 8/14px.
- Focus ring 3px in the accent with a 2px offset on everything.
- Notices: full 1px border in the state colour plus the subtle fill (no thick left border), the state named in text.

## Structure changes

1. **App bar** on Approvals (desktop) and every server page: product name with mark, then the
   navigation as a list; the current page is marked `aria-current="page"` and highlighted.
   Server: language, Help, user and Sign out grouped at the end.
2. **Skip link** ("Skip to main content") as the first focusable element of every window and page
   that has navigation before `<main>`; `<main id="main" tabindex="-1">`.
3. **Settings**: an "On this page" navigation listing the sections, linking to section ids;
   side by side from 64rem, stacked above on narrow windows.
4. **Setup wizard**: a progress list (Data folder, Recovery, Instances, Command line, Finish) with
   `aria-current="step"` and "(done)" text for finished stages, plus "Step n of 5" above the heading.
5. **Tables** sit in a bordered box that scrolls sideways on narrow widths; header cells muted.
6. **Windows High Contrast**: `@media (forced-colors: active)` rules so focus, selected rows,
   badges, notices and the current nav item stay visible (system colours, borders instead of fills).
7. **User guide**: same tokens, app bar with search and language link, skip link, the page list
   as a side navigation with `aria-current="page"`.
8. **Credential window**: its own `credential.css` tokens updated to the same palette and sizes.

## Out of scope

New features shown only as ideas on early canvas drafts (deny with reason, single-key shortcuts).

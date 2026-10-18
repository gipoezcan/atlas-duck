## V16: heap expansion factor `k` (spec §9.4, §15 V16; PD-140, R13, L180)

Status: partial. The 1 and 4 MiB rows are local runs; the 16 MiB rows come from the CI step
"M8 k measurement" (Linux leg) and are added to the table when that step has run on the commit
that carries this section.

Question: what is the factor `k` such that `heap_mb >= k x max_call_result_mb` (invariant 1)
keeps one host-call answer inside the QuickJS heap limit while the host frame's text and the
parse tree are both live?

Method: `crates/sandbox-worker/tests/k_factor.rs`, in process through the real `Engine::deliver`
path. A run makes one host call and holds the answer in a global. The allocator's count gives
`k_peak = (peak during deliver) / (JSON text bytes of the answer)` (the figure invariant 1 uses)
and `k_retained = (count after a GC) / bytes`. The limit is 4 GiB so the peak is never clipped.
Every text mix (`ascii`, `mixed`, `sparse`, `wide`) runs at every size, because QuickJS keeps a
string with a character above U+00FF in 16-bit units.

Fixtures (seeded, in `crates/sandbox-worker/tests/common/fixtures.rs`):

- `jira-all-*`: Jira `fields=*all` search answers (text-heavy: 50 custom fields, long descriptions
  and comments, rendered HTML).
- `jira-dense-*`: Jira issues of many small values (changelog, issuelinks, worklogs, id and number
  arrays, nulls): the most QuickJS values per JSON byte.
- `confluence-storage-*`: a page list of about 5,000-word pages as `body.storage.value` (headings,
  paragraphs with links, lists, tables, info and code macros, images).
- `confluence-markdown-*`: the same pages after conversion to Markdown.
- `confluence-page-*`: one `page.get` answer of 5,000 words; `confluence-list25-*`: a list of 25
  such pages.

| fixture | bytes | heap_peak | k_peak | k_retained |
| --- | --- | --- | --- | --- |
| jira-all-ascii | 1046533 | 3657600 | 3.49 | 2.49 |
| jira-all-mixed | 1024153 | 7617152 | 7.44 | 2.72 |
| jira-all-sparse | 1041567 | 7984104 | 7.67 | 2.81 |
| jira-all-wide | 1040120 | 6234736 | 5.99 | 2.26 |
| jira-dense-ascii | 1026231 | 7488440 | 7.30 | 6.29 |
| jira-dense-mixed | 1034858 | 11606200 | 11.22 | 6.28 |
| jira-dense-sparse | 1043129 | 11243016 | 10.78 | 6.03 |
| jira-dense-wide | 1036988 | 11313952 | 10.91 | 6.23 |
| jira-all-ascii | 4188279 | 14656648 | 3.50 | 2.50 |
| jira-all-mixed | 4175570 | 31029472 | 7.43 | 2.71 |
| jira-all-sparse | 4169074 | 31936120 | 7.66 | 2.81 |
| jira-all-wide | 4178592 | 25049672 | 5.99 | 2.26 |
| jira-dense-ascii | 4177340 | 30486072 | 7.30 | 6.30 |
| jira-dense-mixed | 4183062 | 47012648 | 11.24 | 6.30 |
| jira-dense-sparse | 4189471 | 45070064 | 10.76 | 6.01 |
| jira-dense-wide | 4166279 | 45341224 | 10.88 | 6.21 |
| confluence-page-ascii | 61720 | 149208 | 2.42 | 1.10 |
| confluence-list25-ascii | 1514125 | 3183432 | 2.10 | 1.10 |
| confluence-storage-ascii | 1035723 | 2172424 | 2.10 | 1.10 |
| confluence-markdown-ascii | 1028706 | 2172392 | 2.11 | 1.11 |
| confluence-storage-ascii | 4179025 | 8783984 | 2.10 | 1.10 |
| confluence-markdown-ascii | 4185830 | 8876264 | 2.12 | 1.12 |
| confluence-page-mixed | 64121 | 434840 | 6.78 | 1.87 |
| confluence-list25-mixed | 1637469 | 10525944 | 6.43 | 1.88 |
| confluence-storage-mixed | 1043335 | 6680264 | 6.40 | 1.87 |
| confluence-markdown-mixed | 998617 | 6242864 | 6.25 | 1.83 |
| confluence-storage-mixed | 4180674 | 26803952 | 6.41 | 1.88 |
| confluence-markdown-mixed | 4157713 | 25963608 | 6.24 | 1.83 |
| confluence-page-sparse | 67810 | 459536 | 6.78 | 1.91 |
| confluence-list25-sparse | 1683006 | 11099608 | 6.60 | 1.92 |
| confluence-storage-sparse | 1014324 | 6710296 | 6.62 | 1.92 |
| confluence-markdown-sparse | 1011113 | 6563456 | 6.49 | 1.89 |
| confluence-storage-sparse | 4159487 | 27360352 | 6.58 | 1.92 |
| confluence-markdown-sparse | 4136586 | 26782448 | 6.47 | 1.90 |
| confluence-page-wide | 82889 | 397688 | 4.80 | 1.26 |
| confluence-list25-wide | 2082938 | 9085848 | 4.36 | 1.28 |
| confluence-storage-wide | 1026555 | 4507224 | 4.39 | 1.28 |
| confluence-markdown-wide | 975754 | 3786912 | 3.88 | 1.14 |
| confluence-storage-wide | 4125742 | 18043208 | 4.37 | 1.28 |
| confluence-markdown-wide | 4179244 | 16163048 | 3.87 | 1.15 |

Pending: the 16 MiB rows (Jira `all` and `dense`, Confluence `storage` and `markdown`, four mixes
each) from the CI step "M8 k measurement". Compare each with its 4 MiB row: the factor is flat
between 1 and 4 MiB (Jira dense-mixed 11.22 and 11.24). A 16 MiB `k_peak` above 12.00 makes the
rule below give a `k` above 15, and one above 12.80 a `k` above 16 (R13: stop, the lead rules).
Add the rows to the table; `heap_k_constant_matches_evidence` (`crates/core/tests/validate.rs`)
then names the value the constant must have.

### The fixed `k`

Rule (lead ruling for Task 33): `k = ceil(1.25 x max k_peak)` over all fixtures, the dense shapes
and the Confluence storage bodies included.

Maximum `k_peak` of the local table: 11.24 (`jira-dense-mixed`, 4 MiB). The largest Confluence
value is 6.78 (`confluence-page-mixed`, one 5,000-word page; 6.62 for a list), so the Jira dense
shape decides. `ceil(1.25 x 11.24) = ceil(14.05) = 15`.

SCRIPT_HEAP_K = 15

R13: not triggered. `k = 15 <= 16`, so the spec defaults `heap_mb` 256 and `max_call_result_mb` 16
satisfy invariant 1 (`15 x 16 = 240 <= 256`) and invariant 2 (`process_mb` 512 `>= 256 + 88`);
only the constant changes. The three options of R13 are not needed.

Notes the number carries:

- M-3: the allocator accounts a moving `realloc` as remove-old then add-new, so the transient in
  which the old and the new block both exist is not in `heap_peak`. That is consistent with how
  `heap_mb` is enforced, so `k` matches the limit it feeds, but it understates real process
  memory. `process_mb` (invariant 2) needs its own number: this task does not derive it from `k`.
- M-6: the Rust-side frame buffer (the host's frame, up to 24 MiB) is not part of the `heap_mb`
  count, so it is in no `k`. The process-level total (frame bytes plus the JS copy of the text
  plus the tree) belongs to `process_mb`; invariant 2's `+ 24 MiB` frame term and `+ 64 MiB`
  margin stand as the spec has them, unmeasured by this table.
- L180: with `max_concurrent_calls = 4`, up to four call results can be live in the heap at once.
  Invariant 1 covers one result at the peak factor; it does not cover the sum of four live
  results (each held at `k_retained`, up to 6.3 per byte of the dense shape, while another
  delivery peaks). This measurement says nothing about that case.

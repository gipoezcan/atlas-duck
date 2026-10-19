// S-06 (spec 13, Security Frontend row; spec 6.4, 10.3), the UI half: whatever string a window is
// given, it reaches the DOM as text. Every string field of every fixture Rust generated
// (src/shared/ipc/fixtures) is replaced by each payload of the corpus, every window is rendered
// from that, every tab, form, dialog and button is opened or pressed, and the page is scanned:
//
//  - no `<script>` and no element the baseline run (benign text) did not already show,
//  - no `on*` attribute, no `href`/`src`/`action`-like attribute anywhere (the preview iframe
//    carries `sandbox=""` and its document, nothing else),
//  - `window.__pwned` stays undefined and no prototype was written to,
//  - nothing threw while rendering (a lookup of a wire string in a plain table of the page hands
//    back `Object.prototype` members, which React refuses to render).
//
// The windows run on their real command wrappers (`shared/ipc/invoke.ts`, validators included):
// only Tauri's `invoke` is replaced, so a poisoned answer reaches a component exactly when the
// runtime's validation lets it through. Three passes: `all` (every string, discriminators too),
// `free` (discriminators keep their values so every known branch renders) and `keys` (records
// gain `__proto__`/`constructor` keys). The fixtures are enumerated with a glob: a fixture no
// window consumes fails `every_fixture_reaches_a_window`.
import { act, fireEvent, render } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { Audit } from '../audit/Audit';
import { mountCredentialPage } from '../credential/page';
import { Onboarding } from '../onboarding/Onboarding';
import { Running } from '../running_scripts/Running';
import { Settings } from '../settings/Settings';
import { Wizard } from '../setup/Wizard';
import { on } from '../shared/ipc/events';
import { combined, COMBINABLE, CORPUS, KINDS, PROTOTYPE_KEYS } from '../shared/injection-corpus';
import { App } from './App';

// Only Tauri's invoke is replaced. shared/ipc/ is the one place that may import the API, so the
// stand-in is reached through a hoisted bridge and this file needs no such import.
const bridge = vi.hoisted(() => ({
  invoke: (_cmd: string, _args: Record<string, unknown>): Promise<unknown> => Promise.reject(new Error('unwired')),
}));
vi.mock('@tauri-apps/api/core', () => ({ invoke: (cmd: string, args: Record<string, unknown> = {}) => bridge.invoke(cmd, args) }));
vi.mock('../shared/ipc/events');

type Json = unknown;
type Mode = 'all' | 'free' | 'keys';

const RAW = import.meta.glob('../shared/ipc/fixtures/*.json', { eager: true, import: 'default' });
const FIXTURES = new Map<string, Json>(
  Object.entries(RAW).map(([path, value]) => [path.replace(/^.*\/(.+)\.json$/, '$1'), value]),
);

/** Keys whose string is a wire name the window switches on, not text the window shows. */
const DISCRIMINANTS = new Set([
  'kind', 'class', 'status', 'level', 'step', 'state', 'product', 'purpose', 'choice', 'result',
  'outcome', 'mode', 'op', 'scope', 'preset', 'method', 'cli', 'autostart',
  'attention_mode', 'anchors_missing', 'secret_service', 'code', 'field', 'conn', 'error', 'preselect', 'scripts',
]);

/** The one discriminator path a `free` run poisons as well (the per-path prototype pass), or null. */
let focus: string | null = null;

/** The paths of the fixtures that end in a discriminator, by the path rule of `poison`. */
function discriminantPaths(value: Json, key: string, path: string, out: Set<string>): void {
  if (typeof value === 'string') {
    if (DISCRIMINANTS.has(key)) out.add(path);
  } else if (Array.isArray(value)) {
    for (const v of value) discriminantPaths(v, key, path, out);
  } else if (typeof value === 'object' && value !== null) {
    for (const [k, v] of Object.entries(value)) discriminantPaths(v, k, path === '' ? k : `${path}.${k}`, out);
  }
}

const DISCRIMINANT_PATHS = (() => {
  const out = new Set<string>();
  for (const fixture of FIXTURES.values()) discriminantPaths(fixture, '', '', out);
  return [...out].sort();
})();

const KEY_MODE_VALUE = '<img src=x onerror="window.__pwned=1">';

function own(target: object, key: string, value: unknown): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

/** `path` is the dotted keys from the root, lists left out: `instances.state`. */
function poison(value: Json, payload: string, mode: Mode, key = '', path = ''): Json {
  if (typeof value === 'string') {
    return mode === 'keys' || (mode === 'free' && DISCRIMINANTS.has(key) && path !== focus) ? value : payload;
  }
  if (Array.isArray(value)) return value.map((v) => poison(v, payload, mode, key, path));
  if (typeof value === 'object' && value !== null) {
    const out = {};
    for (const [k, v] of Object.entries(value)) own(out, k, poison(v, payload, mode, k, path === '' ? k : `${path}.${k}`));
    if (mode === 'keys') for (const k of PROTOTYPE_KEYS) own(out, k, payload);
    return out;
  }
  return value;
}

// What a window may put on the page, learned from a run with benign text.
const baseline = new Set<string>();
let learning = false;

const FORBIDDEN_ATTRIBUTES = new Set([
  'href', 'src', 'srcset', 'action', 'formaction', 'xlink:href', 'data', 'poster', 'background',
  'ping', 'longdesc', 'cite', 'manifest', 'codebase', 'usemap',
]);

function scan(where: string): string[] {
  const found: string[] = [];
  const g = window as unknown as Record<string, unknown>;
  if (g['__pwned'] !== undefined) found.push(`${where}: window.__pwned is set`);
  // What a table lookup that hit `Object.prototype` leaves in plain DOM text (a text node is a string).
  const text = document.body.textContent ?? '';
  if (text.includes('[native code]') || text.includes('[object Object]')) {
    found.push(`${where}: the page shows a function or an object as text`);
  }
  for (const el of document.documentElement.querySelectorAll('*')) {
    const tag = el.tagName.toLowerCase();
    if (learning) baseline.add(tag);
    else if (!baseline.has(tag)) found.push(`${where}: unexpected <${tag}>`);
    if (tag === 'script') found.push(`${where}: <script>`);
    const frame = tag === 'iframe';
    for (const name of el.getAttributeNames()) {
      const attr = name.toLowerCase();
      const value = el.getAttribute(name) ?? '';
      if (attr.startsWith('on')) found.push(`${where}: <${tag} ${name}>`);
      else if (FORBIDDEN_ATTRIBUTES.has(attr)) found.push(`${where}: <${tag} ${name}>`);
      else if (attr === 'style' && /url\s*\(|javascript:|expression\s*\(/i.test(value)) {
        found.push(`${where}: <${tag} style=${value.slice(0, 40)}>`);
      } else if (frame && attr !== 'sandbox' && attr !== 'srcdoc' && attr !== 'title') {
        found.push(`${where}: <iframe ${name}>`);
      }
    }
    if (frame && el.getAttribute('sandbox') !== '') found.push(`${where}: iframe sandbox is not empty`);
  }
  return found;
}

const protos = [Object.prototype, Array.prototype, Function.prototype, String.prototype];
const protoNames = protos.map((p) => Object.getOwnPropertyNames(p).join());

function protoIntact(): boolean {
  return (
    protos.every((p, i) => Object.getOwnPropertyNames(p).join() === protoNames[i]) &&
    (({}) as Record<string, unknown>)['polluted'] === undefined
  );
}

// ---- the answers of the commands ----

const used = new Set<string>();
/** The fixtures the scenario now running has read. */
let current = new Set<string>();
let payload = 'x';
let mode: Mode = 'free';
let preview = 0;
let enabled = false;
let pin = 0;
let variant: 'none' | 'tokens' | 'removal' = 'none';
/** The blocked read of the M-11 scenario: `redaction_preview` answers the report that flags mirror entries. */
let mirror = false;
let counters = new Map<string, number>();

/** The fixture called `name` as a list, poisoned as the current pass says (or as `pass` says). */
function fx(name: string, pass: Mode = mode): Json[] {
  used.add(name);
  current.add(name);
  const base = FIXTURES.get(name);
  if (base === undefined) throw new Error(`no fixture ${name}`);
  const v = poison(base, payload, pass);
  return Array.isArray(v) ? v : [v];
}

/**
 * The n-th call of a command: the fixtures in turn; every second call refuses with one of the
 * `command_error` fixtures, so the error paths of every window are shown too.
 */
function reply(cmd: string, name: string, pick?: (list: Json[]) => Json): Promise<Json> {
  const i = counters.get(cmd) ?? 0;
  counters.set(cmd, i + 1);
  if (i % 2 === 1) {
    const errors = fx('command_error');
    return Promise.reject(errors[(i >> 1) % errors.length]);
  }
  const list = fx(name);
  return Promise.resolve(pick ? pick(list) : list[(i >> 1) % list.length]);
}

/** A read that always answers the scenario's pinned fixture: the window stays on that state. */
function pinned(name: string): Promise<Json> {
  const list = fx(name);
  return Promise.resolve(list[pin % list.length]);
}

function previewResponse(id: string): Json {
  const previews = fx('preview') as Record<string, unknown>[];
  const base = previews[preview % previews.length] as { header: Record<string, unknown> };
  const items = fx('queue_item') as { request_id: string; candidate_rev: unknown }[];
  const item = [...items].reverse().find((i) => i.request_id === id) ?? items[0];
  const header = enabled ? { ...base.header, release_blocked: null } : base.header;
  const contexts = fx('redaction_context');
  return {
    preview: { ...base, header, candidate_rev: item?.candidate_rev, ...(enabled ? { approvable: true } : {}) },
    srcdoc: payload,
    redaction: base.header['class'] === 'write' ? null : contexts[preview % contexts.length],
  };
}

/** The candidate the redaction panel reads through `raw_page`: a Jira-shaped document of the payload. */
const CANDIDATE = {
  self: 'x',
  issues: [{ key: 'ABC-1', fields: { summary: 's', labels: ['l'], description: 'd' } }],
  fields: { comment: { comments: [{ id: '10001', body: 'b' }] }, attachment: [{ content: 'c' }] },
  note: 'n',
};

/** Page 0 holds the whole candidate, page 1 is empty; the fixture's text fields stay as they are. */
function rawPage(page: number): Promise<Json> {
  const pages = fx('raw_page') as Record<string, unknown>[];
  const base = pages[Math.min(page, pages.length - 1)] ?? {};
  const bytes = new TextEncoder().encode(JSON.stringify(poison(CANDIDATE, payload, mode)));
  const whole = page === 0 ? bytes : new Uint8Array();
  return Promise.resolve({
    ...base,
    page,
    page_count: 2,
    total_bytes: bytes.length,
    bytes_b64: btoa(String.fromCharCode(...whole)),
  });
}

/** `tokens` variant: every instance waits for its token, so its Retest button is shown. */
function withTokenStates(v: Json): Json {
  const view = v as { instances: object[] };
  return variant === 'tokens' ? { ...view, instances: view.instances.map((i) => ({ ...i, state: 'needs_token' })) } : v;
}

/** `removal` variant: the checklist is under way and every instance answered, so Finish is offered. */
function answered(v: Json): Json {
  const state = v as { instances: object[] };
  if (variant !== 'removal') return v;
  return { ...state, active: true, instances: state.instances.map((i) => ({ ...i, choice: 'done', token_deleted: true, error: null })) };
}

const hasBlocked = (r: Json) => ((r as { blocked?: unknown[] }).blocked?.length ?? 0) > 0;

/**
 * The probe of a mirror-blocked read (T24): the report of the fixture that flags mirror entries. Its
 * `reason` names stay as Rust wrote them (the panel only offers the item for the two mirror reasons,
 * and `reason` is not a discriminant: a poisoned one would end the item as "could not be found"); the
 * paths stay poisoned, so the flagged list and the tree lookup are drawn from the payload.
 */
function mirrorReport(): Promise<Json> {
  const orig = FIXTURES.get('redaction_report') as { blocked: { reason: string }[] }[];
  const at = orig.findIndex((r) => r.blocked.some((b) => b.reason.startsWith('mirror_')));
  const poisoned = fx('redaction_report')[at] as { blocked: object[] };
  const blocked = poisoned.blocked.map((b, i) => ({ ...b, reason: orig[at]?.blocked[i]?.reason }));
  return Promise.resolve({ ...poisoned, blocked });
}

/** A row a batch may decide: opened, approvable, not flagged (a batch needs all of it). */
function decidable(item: Json): Json {
  return { ...(item as object), opened: true, approvable: true, possible_duplicate_of: null, similar_to: null };
}

/** Every command of the seven windows (`COMMANDS`): its answer comes from the fixtures. */
function answer(cmd: string, args: Record<string, unknown>): Promise<Json> {
  switch (cmd) {
    case 'queue_list': return Promise.resolve(enabled ? fx('queue_item').map(decidable) : fx('queue_item'));
    case 'recent_list': return Promise.resolve(fx('recent_item'));
    case 'app_status': return Promise.resolve(fx('status_line'));
    case 'queue_get': return reply(cmd, 'queue_detail');
    case 'preview_fetch': return Promise.resolve(previewResponse(String(args['request_id'])));
    case 'raw_page': return rawPage(Number(args['page']));
    case 'redaction_preview':
      // The first answer (the probe) is the mirror report; the second, as in every window, is a refusal.
      if (mirror && (counters.get(cmd) ?? 0) % 2 === 0) {
        counters.set(cmd, (counters.get(cmd) ?? 0) + 1);
        return mirrorReport();
      }
      return reply(cmd, 'redaction_report', (l) => l.find((r) => hasBlocked(r)) ?? l[0]);
    case 'decide': return reply(cmd, 'decision_outcome');
    case 'decide_batch': return reply(cmd, 'batch_outcome');
    case 'deny_batch':
    case 'deny_session': return reply(cmd, 'deny_count');
    case 'acknowledge_attention':
    case 'open_window':
    case 'quit':
    case 'credential_window_open': return Promise.resolve(null);
    case 'settings_get': return pinned('settings_get').then(withTokenStates);
    case 'settings_apply': return reply(cmd, 'settings_get', (l) => (l[0] as { settings: unknown }).settings);
    case 'instance_add':
    case 'instance_change_url':
    case 'instance_confirm_config':
    case 'instance_accept_url_change':
    case 'instance_set_proxy': return reply(cmd, 'instance_view');
    case 'retest_token': return reply(cmd, 'retest_outcome');
    case 'prune_backlog_now': return reply(cmd, 'prune_report');
    case 'cli_install':
    case 'cli_uninstall': return reply(cmd, 'cli_install_answer');
    case 'removal_state': return pinned('removal_state').then(answered);
    case 'removal_begin':
    case 'removal_mark': return reply(cmd, 'removal_state');
    case 'removal_backup': return reply(cmd, 'removal_backup_answer');
    case 'removal_finish': return reply(cmd, 'removal_finish_answer', (l) => l.find((a) => (a as { cli_reason?: unknown }).cli_reason != null) ?? l[0]);
    case 'verify_now': return reply(cmd, 'verify_now');
    case 'running_list': return Promise.resolve(fx('running_script'));
    case 'running_kill': return reply(cmd, 'kill_answer');
    case 'onboarding_text': return reply(cmd, 'onboarding_text');
    case 'wizard_state': return pinned('wizard_state');
    case 'wizard_use_default_dir':
    case 'wizard_choose_dir':
    case 'wizard_begin':
    case 'wizard_skip_instances':
    case 'wizard_finish': return reply(cmd, 'wizard_state');
    // M10 T12 (Δ-M10-3): the Audit window's commands; its UI (T20) renders their answers.
    case 'audit_query': return reply(cmd, 'audit_page');
    case 'audit_trail': return reply(cmd, 'audit_trail');
    case 'audit_payload': return reply(cmd, 'audit_payload');
    case 'audit_status': return pinned('audit_status');
    case 'acknowledge_incident': return reply(cmd, 'acknowledged');
    case 'export_trigger': return reply(cmd, 'export_done');
    case 'export_cancel': return reply(cmd, 'export_cancel');
    case 'backup_trigger': return reply(cmd, 'removal_backup_answer');
    // M10 T13 (PD-168): Settings "Restore backup…"; its UI is Task 21's.
    case 'restore_begin': return reply(cmd, 'restore_done');
    case 'restore_cancel': return reply(cmd, 'restore_cancel');
    // M10 T14 (PD-166, PD-170): the recovery tier and the anchor directory; their UI is Task 21's.
    case 'recovery_passphrase_change': return Promise.resolve(null);
    case 'anchor_dir_set':
    case 'anchor_dir_remove': return reply(cmd, 'anchor_dir_answer');
    case 're_anchor': return reply(cmd, 're_anchored');
    case 'orphan_installs': return Promise.resolve(fx('orphan_install'));
    case 'forget_install': return reply(cmd, 'forgotten');
    default: return Promise.reject('command not allowed');
  }
}

/**
 * Fixtures of M10 T12's Audit-window answers that no window renders yet: the Audit window's UI is
 * Task 20, which removes each name here as its window comes to consume it (`audit_job` is an event
 * payload, so it stays until events are driven here too). M10 T13's restore answers and M10 T14's
 * recovery-tier answers likewise wait for the Settings UI (Task 21).
 */
const NOT_YET_RENDERED = [
  'acknowledged',
  'anchor_dir_answer',
  'audit_job',
  'audit_page',
  'audit_payload',
  'audit_status',
  'audit_trail',
  'export_cancel',
  'export_done',
  'forgotten',
  'orphan_install',
  're_anchored',
  'restore_cancel',
  'restore_done',
];

function wire(): void {
  counters = new Map();
  vi.mocked(on).mockImplementation(() => Promise.resolve(() => undefined));
  bridge.invoke = answer;
}

// ---- driving a window ----

async function settle(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 12; i++) await Promise.resolve();
  });
}

async function tick(ms: number): Promise<void> {
  await act(async () => {
    vi.advanceTimersByTime(ms);
    for (let i = 0; i < 6; i++) await Promise.resolve();
  });
}

const TEXT_FIELDS = 'input:not([type]), input[type=text], input[type=search], input[type=url], input[type=password], textarea';
const PRESSABLE = 'button, [role=tab], summary, input[type=checkbox], input[type=radio]';
const CLICK_BUDGET = 60;

/**
 * Types the payload into every text field and presses every control, depth first: what a press
 * brings up (a tab, a dialog, a confirmation, a tree) is explored before the controls that were
 * already there. The clock moves between presses, so the inert periods of the approval controls
 * end.
 */
async function explore(where: string): Promise<string[]> {
  const found = scan(`${where} (rendered)`);
  const known = new WeakSet<Element>();
  const pressed = new WeakSet<Element>();
  // Controls to press, newest first: the ones a press brought up go in front of the older ones.
  let stack: HTMLElement[] = [];
  // A control the window re-creates after each press (a dialog's Send, Open) is pressed a few times only.
  const presses = new Map<string, number>();
  const label = (el: Element) => `${el.tagName}:${el.getAttribute('aria-label') ?? el.textContent ?? ''}`;
  let clicks = 0;
  let idle = 0;
  while (clicks < CLICK_BUDGET && idle < 2) {
    for (const field of document.body.querySelectorAll<HTMLInputElement>(TEXT_FIELDS)) {
      if (known.has(field) || field.disabled || field.readOnly) continue;
      known.add(field);
      await act(async () => {
        fireEvent.change(field, { target: { value: payload } });
        // The credential page is plain DOM and listens to `input`.
        fireEvent.input(field);
      });
    }
    const fresh = [...document.body.querySelectorAll<HTMLElement>(PRESSABLE)].filter(
      (el) => !known.has(el) && !(el as HTMLButtonElement).disabled,
    );
    for (const el of fresh) known.add(el);
    const tabs = fresh.filter((el) => el.getAttribute('role') === 'tab');
    stack = [...tabs, ...fresh.filter((el) => !tabs.includes(el)), ...stack];
    stack = stack.filter(
      (el) =>
        el.isConnected &&
        !pressed.has(el) &&
        !(el as HTMLButtonElement).disabled &&
        (presses.get(label(el)) ?? 0) < 3,
    );
    const next = stack.shift();
    if (next === undefined) {
      idle += 1;
      await tick(1500);
      continue;
    }
    idle = 0;
    pressed.add(next);
    presses.set(label(next), (presses.get(label(next)) ?? 0) + 1);
    clicks += 1;
    await act(async () => {
      fireEvent.click(next);
    });
    await settle();
    await tick(1100);
    found.push(...scan(`${where} after "${(next.textContent ?? '').slice(0, 30)}"`));
  }
  return found;
}
interface Scenario {
  name: string;
  /** Small and cheap: every payload runs through it alone. */
  cheap?: boolean;
  /** Only the wide runs (baseline, prototype keys, fixture coverage) render it: it shows what a core one does. */
  wide?: boolean;
  /** The passes that run it in a corpus run besides the wide runs; default both. */
  modes?: readonly Mode[];
  element?: () => ReactElement;
  mount?: (root: HTMLElement) => () => void;
  before?: () => void;
}

/** The first state of a window also runs in the `all` pass; its validators leave the others little to show. */
const only = (index: number): readonly Mode[] => (index === 0 ? ['free', 'all'] : ['free']);

/**
 * The credential page (vanilla TypeScript): its own wire, so its answers are not validated here.
 * Scenario `k` shows context `k % 4` and answers every submit with outcome `k` of the fixtures.
 */
function credential(k: number): Scenario {
  return {
    name: `credential ${k}`,
    cheap: true,
    mount: (root) => {
      let n = 0;
      const answers: Record<string, string> = {
        submit_secret: 'submit_outcome',
        archive_and_start_fresh: 'archive_outcome',
        retry_keychain: 'retry_started',
        save_recovery_note: 'note_saved',
        restore_from_backup: 'submit_outcome',
      };
      return mountCredentialPage(root, {
        invoke: (cmd) => {
          if (cmd === 'credential_context') return Promise.resolve(fx('credential_context', mode === 'all' ? 'free' : mode)[k % 4]);
          const fixture = answers[cmd];
          const i = n++;
          if (fixture === undefined || i % 4 === 3) {
            const errors = fx('command_error');
            return Promise.reject(errors[i % errors.length]);
          }
          const list = fx(fixture);
          return Promise.resolve(list[k % list.length]);
        },
        listen: () => Promise.resolve(() => undefined),
      });
    },
  };
}
const SCENARIOS: Scenario[] = [
  // The nineteen preview kinds, alternately blocked as Rust built them and made approvable. The
  // corpus runs take the kinds that differ in what the window draws: a read with the redaction
  // panel (0), a write with the edit form, blocked (1) and approvable (4), a read with an
  // "also appears in" note (8); the others only join the wide runs. Kind 0 as a blocked read with
  // the mirror probe follows these nineteen (its own scenario, below).
  ...Array.from({ length: 19 }, (_, i): Scenario => ({
    name: `approvals preview ${i}`,
    wide: ![0, 1, 4, 8].includes(i),
    modes: i === 0 ? ['free', 'all'] : ['free'],
    element: () => <App />,
    before: () => {
      preview = i;
      enabled = i % 2 === 0;
    },
  })),
  // M8 T24 (M-11): the blocked read of kind 0 keeps its banner and its redaction context, and the probe
  // answers the mirror report: the flagged list (Rust's reason and path text), the tree it is looked
  // up in and "Drop the flagged items" are drawn and pressed. Not in `all`: the banner needs its
  // discriminators. A core scenario, so every payload reaches it.
  {
    name: 'approvals preview blocked read',
    modes: ['free'],
    element: () => <App />,
    before: () => {
      preview = 0;
      enabled = false;
      mirror = true;
    },
  },
  // Fixture 3 is the degraded one (`confinement.scripts` = degraded, the caution and the toggle on).
  ...[0, 1, 2, 3].map((i): Scenario => ({ name: `settings ${i}`, modes: only(i), element: () => <Settings />, before: () => void (pin = i) })),
  { name: 'settings tokens', modes: ['free'], element: () => <Settings />, before: () => void (variant = 'tokens') },
  { name: 'settings removal', modes: ['free', 'all'], element: () => <Settings />, before: () => void ((variant = 'removal'), (pin = 1)) },
  ...[0, 1, 2, 3, 4].map((i): Scenario => ({ name: `setup ${i}`, cheap: true, modes: only(i), element: () => <Wizard />, before: () => void (pin = i) })),
  { name: 'audit', cheap: true, element: () => <Audit /> },
  { name: 'running_scripts', cheap: true, element: () => <Running /> },
  { name: 'onboarding', cheap: true, element: () => <Onboarding /> },
  ...[0, 1, 2, 3, 4, 5, 6, 7].map(credential),
];

/** The fixtures each scenario read in the benign runs, by `mode/name`: a payload run has to read them too. */
const benignUsed = new Map<string, Set<string>>();

async function run(scenario: Scenario): Promise<string[]> {
  wire();
  current = new Set();
  variant = 'none';
  pin = 0;
  mirror = false;
  scenario.before?.();
  let stop: () => void = () => undefined;
  let view: ReturnType<typeof render> | null = null;
  if (scenario.element) view = render(scenario.element());
  else if (scenario.mount) {
    const root = document.createElement('main');
    document.body.append(root);
    stop = scenario.mount(root);
  }
  await settle();
  const where = `${mode}/${scenario.name}`;
  const found = await explore(where);
  if (learning) benignUsed.set(where, current);
  else if (focus === null && mode !== 'keys' && payload.trim() !== '') {
    // A payload that makes the explorer stall (its clicks spent on controls the payload made) would
    // scan less and still pass: the run has to reach every tab, dialog and panel the benign run did.
    // (A blank payload leaves the required fields empty, so the buttons that send stay off.)
    for (const name of benignUsed.get(where) ?? []) {
      if (!current.has(name)) found.push(`${where}: did not read fixture ${name} as the benign run did`);
    }
  }
  view?.unmount();
  stop();
  document.body.replaceChildren();
  return found;
}

type Reach = 'cheap' | 'core' | 'wide';

/** Renders the scenarios of `reach` that take the current pass: `wide` takes all of them. */
async function runAll(reach: Reach = 'wide'): Promise<string[]> {
  const found: string[] = [];
  for (const scenario of SCENARIOS) {
    if (reach === 'cheap' && scenario.cheap !== true) continue;
    if (reach !== 'wide' && (scenario.wide === true || scenario.modes?.includes(mode) === false)) continue;
    found.push(...(await run(scenario)));
  }
  return found;
}

let errors: string[] = [];
/** Console errors of the benign runs: the baseline has to render cleanly before payloads are blamed. */
const baselineErrors: string[] = [];

beforeAll(async () => {
  vi.useFakeTimers();
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    baselineErrors.push(args.map(String).join(' ').slice(0, 300));
  });
  // What the windows put on the page when the text is benign: the elements the corpus runs are measured against.
  learning = true;
  payload = 'benign text';
  for (const m of ['all', 'free', 'keys'] as const) {
    mode = m;
    await runAll();
  }
  learning = false;
  vi.restoreAllMocks();
  const failures = baselineErrors.filter((e) => RENDER_FAILURES.test(e));
  baselineErrors.length = 0;
  baselineErrors.push(...failures);
}, 300_000);

afterAll(() => {
  vi.useRealTimers();
});

beforeEach(() => {
  errors = [];
  pin = 0;
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    errors.push(args.map(String).join(' ').slice(0, 300));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** Console errors that mean a window failed to render, not React's own notes. */
const RENDER_FAILURES = /not valid as a React child|Minified React error|Cannot read|is not a function|is not iterable|Functions are not valid|Uncaught|above error occurred/;

/** Both passes over `reach`; nothing on the page, nothing thrown, no prototype written to. */
async function clean(value: string, reach: Reach, modes: readonly Mode[] = ['free', 'all']): Promise<void> {
  payload = value;
  const found: string[] = [];
  for (const m of modes) {
    mode = m;
    found.push(...(await runAll(reach)));
  }
  expect([...new Set(found)].slice(0, 25)).toEqual([]);
  expect(errors.filter((e) => RENDER_FAILURES.test(e))).toEqual([]);
  expect(protoIntact()).toBe(true);
}

describe('s06_injection_payloads_every_field_every_tab', () => {
  it('baseline: benign text shows an iframe and no script or image', () => {
    expect(baseline.has('iframe')).toBe(true);
    expect(baseline.has('script')).toBe(false);
    expect(baseline.has('img')).toBe(false);
    expect(baselineErrors).toEqual([]);
    expect(benignUsed.size).toBeGreaterThan(0);
  });

  // Every payload alone, in every string field of the small windows.
  it.each(CORPUS.map((p) => [p.id, p.value] as const))('%s alone, in the credential, setup, audit, running and onboarding windows', (_id, value) =>
    clean(value, 'cheap'),
  );

  // Every payload of a kind at once, in every string field of every window and every tab.
  it.each(COMBINABLE)('all %s payloads at once, in every window and tab', (kind) => clean(combined(kind), 'core'));

  // Names and odd values only matter as the whole value of a field (a table lookup, a key).
  it.each(
    [...KINDS.prototype, ...KINDS.null, ...KINDS.long].map((p) => [p.id, p.value] as const),
  )('%s alone, in every window and tab', (_id, value) => clean(value, 'core'));

  // A wire name looked up in a table of a page: the record's other discriminators stay valid, so
  // the record is rendered, and this one field (a path, as a closed sibling of the same name
  // elsewhere would reject the record) holds the name of an `Object.prototype` member.
  it.each(DISCRIMINANT_PATHS.flatMap((path) => ['__proto__', 'constructor'].map((name) => [path, name] as const)))(
    'discriminator %s = %s, in every window and tab',
    async (path, name) => {
      focus = path;
      try {
        await clean(name, 'core', ['free']);
      } finally {
        focus = null;
      }
    },
  );

  it('prototype keys and markup on every record of every answer', async () => {
    mode = 'keys';
    payload = KEY_MODE_VALUE;
    const found = await runAll();
    expect([...new Set(found)].slice(0, 25)).toEqual([]);
    expect(errors.filter((e) => RENDER_FAILURES.test(e))).toEqual([]);
    expect(protoIntact()).toBe(true);
  }, 300_000);

  it('every_fixture_reaches_a_window: a new fixture has to be wired into this test', async () => {
    used.clear();
    mode = 'free';
    payload = 'benign text';
    await runAll();
    const unused = [...FIXTURES.keys()].filter((name) => !used.has(name)).sort();
    expect(unused).toEqual(NOT_YET_RENDERED);
  }, 300_000);
});

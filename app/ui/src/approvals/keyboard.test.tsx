import { fireEvent, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { decide, previewFetch } from '../shared/ipc/invoke';
import { INERT_MS } from './inert';
import { ChordTracker, chordOf, type KeyInput } from './keyboard';
import {
  advance,
  emit,
  flush,
  Keyboard,
  listeners,
  mockWindow,
  positive,
  READ,
  renderWindow,
  WRITE,
} from './testing';

vi.mock('../shared/ipc/invoke', () => ({
  queueList: vi.fn(),
  recentList: vi.fn(),
  appStatus: vi.fn(),
  acknowledgeAttention: vi.fn(),
  previewFetch: vi.fn(),
  decide: vi.fn(),
  rawPage: vi.fn(),
  queueGet: vi.fn(),
  openWindow: vi.fn(),
  quit: vi.fn(),
}));
vi.mock('../shared/ipc/events', () => ({ on: vi.fn() }));

const mockedPreview = vi.mocked(previewFetch);
const mockedDecide = vi.mocked(decide);

beforeEach(() => {
  vi.resetAllMocks();
  vi.useFakeTimers();
  mockWindow();
});

afterEach(() => {
  vi.useRealTimers();
});

/** Opens the first queue item with the next chord and lets its inert period pass. */
async function openFirst(keys: Keyboard) {
  keys.chord('Down');
  await flush();
  advance(INERT_MS);
}

/** The queue row marked as the one in the detail pane. */
function currentRow(): string | null {
  return document.querySelector('.queue-item[aria-current="true"] .target')?.textContent ?? null;
}

describe('keyboard (spec 5.6, PD-91)', () => {
  it('ui02_repeat_never_decides', async () => {
    const keys = new Keyboard();
    await renderWindow();
    await openFirst(keys);
    expect(positive('Release')?.disabled).toBe(false);

    // A held chord's auto-repeat: no decision, no deny field, no navigation.
    keys.down('Control');
    keys.down('Shift');
    for (const main of ['Enter', 'D', 'Down', 'Up'] as const) {
      expect(keys.down(main, true)).toBe(false);
      keys.up(main);
    }
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    expect(screen.queryByRole('group', { name: 'Deny this request' })).toBeNull();
    expect(mockedPreview).toHaveBeenCalledTimes(1);
    keys.up('Shift');
    keys.up('Control');

    // The same chord, pressed fresh, decides (the control above is not vacuous).
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({
      request_id: READ.request_id,
      decision: 'release',
      candidate_rev: READ.candidate_rev,
    });
  });

  it('ui02_held_chord_through_next_item_approves_nothing', async () => {
    const keys = new Keyboard();
    await renderWindow();
    await openFirst(keys);

    // Ctrl+Shift+Enter decides the first item; the keys stay down.
    keys.down('Control');
    keys.down('Shift');
    keys.down('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    // Still holding Ctrl+Shift+Enter: Down moves to the next item (navigation needs no release).
    keys.down('Down');
    keys.up('Down');
    await flush();
    expect(mockedPreview).toHaveBeenLastCalledWith(WRITE.request_id);
    // The held Enter repeats through and past the inert period.
    keys.down('Enter', true);
    advance(INERT_MS);
    keys.down('Enter', true);
    // Enter released and pressed again, Ctrl+Shift never released: still not armed.
    keys.up('Enter');
    keys.down('Enter');
    keys.up('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    expect(positive('Approve')?.disabled).toBe(false);

    // Every key released: the next chord approves the second item.
    keys.up('Shift');
    keys.up('Control');
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(2);
    expect(mockedDecide.mock.calls[1]?.[0]).toMatchObject({
      request_id: WRITE.request_id,
      decision: 'approve',
    });
  });

  it('ui02_no_auto_advance', async () => {
    const keys = new Keyboard();
    await renderWindow();
    await openFirst(keys);
    expect(currentRow()).toBe(READ.target_display);

    keys.chord('Enter');
    await flush();
    advance(5 * INERT_MS);
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    // The decided item stays selected, its preview is cleared, nothing else is fetched or opened.
    expect(currentRow()).toBe(READ.target_display);
    expect(screen.getByText('Decision recorded: released')).toBeTruthy();
    expect(screen.queryByTitle('Preview')).toBeNull();
    expect(mockedPreview).toHaveBeenCalledTimes(1);

    // Same after a deny.
    keys.chord('Down');
    await flush();
    advance(INERT_MS);
    keys.chord('D');
    keys.tap('Enter');
    await flush();
    advance(5 * INERT_MS);
    await flush();
    expect(mockedDecide.mock.calls[1]?.[0]).toMatchObject({
      request_id: WRITE.request_id,
      decision: 'deny',
    });
    expect(currentRow()).toBe(WRITE.target_display);
    expect(mockedPreview).toHaveBeenCalledTimes(2);
  });

  it('ui02_next_opens_and_starts_inert', async () => {
    const keys = new Keyboard();
    await renderWindow();
    // Nothing selected: next opens the first item in display order (an explicit navigation).
    keys.chord('Down');
    await flush();
    expect(mockedPreview).toHaveBeenCalledTimes(1);
    expect(mockedPreview).toHaveBeenLastCalledWith(READ.request_id);
    expect(currentRow()).toBe(READ.target_display);
    // Its controls and the chord are inert for 1 s.
    expect(positive('Release')?.disabled).toBe(true);
    advance(INERT_MS - 1);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    advance(1);
    expect(positive('Release')?.disabled).toBe(false);

    // Next again: the second item opens and its own inert period starts.
    keys.chord('Down');
    await flush();
    expect(mockedPreview).toHaveBeenLastCalledWith(WRITE.request_id);
    expect(positive('Approve')?.disabled).toBe(true);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    // Previous goes back to the first, which opens again (a new fetch) and is inert again.
    advance(INERT_MS);
    keys.chord('Up');
    await flush();
    expect(mockedPreview).toHaveBeenCalledTimes(3);
    expect(mockedPreview).toHaveBeenLastCalledWith(READ.request_id);
    expect(positive('Release')?.disabled).toBe(true);
    advance(INERT_MS);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
  });

  it('ui02_deny_chord_focuses_reason_enter_submits', async () => {
    const keys = new Keyboard();
    await renderWindow();
    await openFirst(keys);

    keys.chord('D');
    const field = screen.getByRole('textbox', { name: 'Reason for the agent' });
    expect(document.activeElement).toBe(field);
    // Esc cancels: nothing is sent and the field closes.
    keys.tap('Escape');
    expect(screen.queryByRole('textbox', { name: 'Reason for the agent' })).toBeNull();
    expect(mockedDecide).not.toHaveBeenCalled();

    keys.chord('D');
    const again = screen.getByRole('textbox', { name: 'Reason for the agent' });
    expect(document.activeElement).toBe(again);
    fireEvent.change(again, { target: { value: 'wrong project' } });
    // A repeated Enter does not send; a fresh one does.
    keys.down('Enter', true);
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    keys.up('Enter');
    keys.tap('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    expect(mockedDecide.mock.calls[0]?.[0]).toEqual({
      request_id: READ.request_id,
      candidate_rev: READ.candidate_rev,
      decision: 'deny',
      reason: 'wrong project',
    });
  });

  it('ui03_unrequested_focus_swallows_input_1s', async () => {
    const keys = new Keyboard();
    const { container } = await renderWindow();
    await openFirst(keys);
    keys.chord('D');
    const field = screen.getByRole('textbox', { name: 'Reason for the agent' });
    expect(document.activeElement).toBe(field);

    // The listener is bound to this window only (another window's focus is not ours).
    expect(listeners.get('window_focus')?.[0]?.options).toEqual({ thisWindow: true });
    emit('window_focus', { requested: false });

    // Focus is on the window heading, not on an input.
    const heading = screen.getByRole('heading', { level: 1 });
    expect(document.activeElement).toBe(heading);

    const seen: string[] = [];
    const spy = (e: Event) => seen.push(e.type);
    for (const t of ['keydown', 'keyup', 'keypress', 'beforeinput', 'input']) {
      container.addEventListener(t, spy);
    }
    // Typing into the deny field, Enter and Esc there, a queue chord: none reaches the page.
    expect(fireEvent.keyDown(field, { key: 'x', code: 'KeyX' })).toBe(false);
    expect(fireEvent.keyPress(field, { key: 'x', code: 'KeyX', charCode: 120 })).toBe(false);
    expect(fireEvent(field, new InputEvent('beforeinput', { bubbles: true, cancelable: true, data: 'x' }))).toBe(false);
    fireEvent.input(field, { target: { value: 'x' } });
    expect(fireEvent.keyDown(field, { key: 'Enter', code: 'Enter' })).toBe(false);
    fireEvent.keyDown(field, { key: 'Escape', code: 'Escape' });
    keys.chord('Down');
    keys.chord('Enter');
    advance(INERT_MS - 1);
    keys.chord('Up');
    await flush();
    expect(seen).toEqual([]);
    expect(mockedDecide).not.toHaveBeenCalled();
    expect(mockedPreview).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('textbox', { name: 'Reason for the agent' })).toBe(field);
    expect(currentRow()).toBe(READ.target_display);

    // After the period, input works again: Enter in the field sends the deny, without the swallowed "x".
    advance(1);
    field.focus();
    keys.tap('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    expect(mockedDecide.mock.calls[0]?.[0]).not.toHaveProperty('reason');
    for (const t of ['keydown', 'keyup', 'keypress', 'beforeinput', 'input']) {
      container.removeEventListener(t, spy);
    }
  });

  it('ui03_dom_focus_before_the_event_keeps_typed_text_out_of_the_deny_field', async () => {
    const keys = new Keyboard();
    await renderWindow();
    await openFirst(keys);
    keys.chord('D');
    const field = screen.getByRole('textbox', { name: 'Reason for the agent' }) as HTMLInputElement;
    expect(document.activeElement).toBe(field);

    // The window loses focus; focus leaves the field at once, so the browser has nothing to restore.
    fireEvent.blur(window);
    expect(document.activeElement).not.toBe(field);
    // The DOM focus comes first, window_focus {requested:false} only later: typing in the gap.
    fireEvent.focus(window);
    keys.tap('X');
    keys.tap('Enter');
    await flush();
    expect(field.value).toBe('');
    expect(mockedDecide).not.toHaveBeenCalled();
    emit('window_focus', { requested: false });
    expect(document.activeElement).toBe(screen.getByRole('heading', { level: 1 }));
  });

  it('a_requested_focus_makes_approve_inert_but_not_typing', async () => {
    const keys = new Keyboard();
    await renderWindow();
    await openFirst(keys);
    keys.chord('D');
    const field = screen.getByRole('textbox', { name: 'Reason for the agent' });
    keys.tap('Escape');
    emit('window_focus', { requested: true });
    expect(positive('Release')?.disabled).toBe(true);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    // Keys still reach the page (only approve/release is inert after a requested focus).
    expect(fireEvent.keyDown(document.body, { key: 'x', code: 'KeyX' })).toBe(true);
    expect(field.isConnected).toBe(false);
    advance(INERT_MS);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
  });

  it('a_malformed_window_focus_payload_counts_as_unrequested', async () => {
    const keys = new Keyboard();
    await renderWindow();
    await openFirst(keys);
    emit('window_focus', { requested: 'yes' });
    expect(document.activeElement).toBe(screen.getByRole('heading', { level: 1 }));
    expect(fireEvent.keyDown(document.body, { key: 'x', code: 'KeyX' })).toBe(false);
  });

  it('enter_or_space_on_a_positive_button_is_not_a_single_key_approval', async () => {
    const keys = new Keyboard();
    await renderWindow();
    await openFirst(keys);
    const release = positive('Release') as HTMLButtonElement;
    release.focus();
    expect(keys.tap('Enter')).toBe(false);
    expect(fireEvent.keyDown(release, { key: ' ', code: 'Space' })).toBe(false);
    expect(fireEvent.keyUp(release, { key: ' ', code: 'Space' })).toBe(false);
    // Other buttons keep their keyboard activation.
    const tab = screen.getByRole('tab', { name: 'Raw' });
    expect(fireEvent.keyDown(tab, { key: 'Enter', code: 'Enter' })).toBe(true);
  });

  it('single_keys_and_partial_chords_never_decide_or_navigate', async () => {
    const keys = new Keyboard();
    await renderWindow();
    await openFirst(keys);
    for (const k of ['Enter', 'D', 'Down', 'Up'] as const) keys.tap(k);
    keys.down('Control');
    keys.tap('Enter');
    keys.up('Control');
    keys.down('Shift');
    keys.tap('Enter');
    keys.tap('D');
    keys.up('Shift');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    expect(screen.queryByRole('textbox')).toBeNull();
    expect(mockedPreview).toHaveBeenCalledTimes(1);
  });

  it('a_key_down_when_the_window_lost_focus_must_be_released_first', async () => {
    const keys = new Keyboard();
    await renderWindow();
    await openFirst(keys);
    // Enter goes down, the window loses focus, and Enter's keyup is never seen here.
    keys.down('Enter');
    fireEvent.blur(window);
    keys.down('Control');
    keys.down('Shift');
    keys.down('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    // Seen released, the chord works.
    keys.up('Enter');
    keys.up('Shift');
    keys.up('Control');
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
  });

  it('chords_do_nothing_without_an_opened_item', async () => {
    const keys = new Keyboard();
    await renderWindow();
    keys.chord('Enter');
    keys.chord('D');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    expect(mockedPreview).not.toHaveBeenCalled();
    expect(screen.queryByRole('textbox')).toBeNull();
  });

  it('the_approve_chord_is_ignored_while_the_deny_field_is_open', async () => {
    const keys = new Keyboard();
    await renderWindow();
    await openFirst(keys);
    keys.chord('D');
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    expect(positive('Release')?.disabled).toBe(true);
  });
});

/** A keydown/keyup as the browser reports it, modifiers per `mods`. */
function ev(key: string, code: string, mods: Partial<KeyInput> = {}): KeyInput {
  return { key, code, ctrlKey: false, metaKey: false, shiftKey: false, altKey: false, repeat: false, ...mods };
}

describe('ChordTracker', () => {
  const CS = { ctrlKey: true, shiftKey: true };

  it('chords_are_modifier_chords_only', () => {
    expect(chordOf(ev('Enter', 'Enter'))).toBeNull();
    expect(chordOf(ev('Enter', 'Enter', { ctrlKey: true }))).toBeNull();
    expect(chordOf(ev('Enter', 'Enter', { shiftKey: true }))).toBeNull();
    expect(chordOf(ev('Enter', 'Enter', { ...CS, altKey: true }))).toBeNull();
    expect(chordOf(ev('Enter', 'Enter', CS))).toBe('approve');
    expect(chordOf(ev('Enter', 'Enter', { metaKey: true, shiftKey: true }))).toBe('approve');
    expect(chordOf(ev('D', 'KeyD', CS))).toBe('deny');
    expect(chordOf(ev('ArrowDown', 'ArrowDown', CS))).toBe('next');
    expect(chordOf(ev('ArrowUp', 'ArrowUp', CS))).toBe('prev');
  });

  it('a_key_held_when_the_window_lost_focus_must_be_seen_released', () => {
    const t = new ChordTracker();
    t.down(ev('Control', 'ControlLeft', { ctrlKey: true }));
    t.down(ev('Shift', 'ShiftLeft', CS));
    expect(t.down(ev('Enter', 'Enter', CS)).act).toBe(true);
    t.up(ev('Enter', 'Enter', CS));
    t.up(ev('Shift', 'ShiftLeft', { ctrlKey: true }));
    t.up(ev('Control', 'ControlLeft'));
    expect(t.armed).toBe(true);
    // Enter goes down, the window loses focus, its keyup goes elsewhere.
    t.down(ev('Enter', 'Enter'));
    t.blur();
    t.down(ev('Control', 'ControlLeft', { ctrlKey: true }));
    t.down(ev('Shift', 'ShiftLeft', CS));
    expect(t.down(ev('Enter', 'Enter', CS)).act).toBe(false);
    t.up(ev('Enter', 'Enter', CS));
    t.up(ev('Shift', 'ShiftLeft', { ctrlKey: true }));
    t.up(ev('Control', 'ControlLeft'));
    expect(t.armed).toBe(true);
  });

  it('a_modifier_flag_that_is_off_proves_the_release', () => {
    const t = new ChordTracker();
    t.down(ev('Control', 'ControlLeft', { ctrlKey: true }));
    t.down(ev('Shift', 'ShiftLeft', CS));
    t.down(ev('Enter', 'Enter', CS));
    t.up(ev('Enter', 'Enter', CS));
    // The modifier keyups went to another window; the next key event reports them up.
    expect(t.armed).toBe(false);
    t.down(ev('x', 'KeyX'));
    t.up(ev('x', 'KeyX'));
    expect(t.armed).toBe(true);
  });

  it('macos_keys_released_under_cmd_send_no_keyup_and_must_not_block_the_next_chord', () => {
    const t = new ChordTracker();
    const M = { metaKey: true, shiftKey: true };
    t.down(ev('Meta', 'MetaLeft', { metaKey: true }));
    t.down(ev('Shift', 'ShiftLeft', M));
    expect(t.down(ev('Enter', 'Enter', M)).act).toBe(true);
    // WebKit: Cmd is released first, Enter and Shift go up, but Enter's keyup is never sent.
    t.up(ev('Meta', 'MetaLeft', { shiftKey: true }));
    t.up(ev('Shift', 'ShiftLeft'));
    expect(t.armed).toBe(true);
    t.down(ev('Meta', 'MetaLeft', { metaKey: true }));
    t.down(ev('Shift', 'ShiftLeft', M));
    expect(t.down(ev('Enter', 'Enter', M)).act).toBe(true);
  });

  it('a_key_held_with_cmd_still_down_keeps_the_chord_blocked', () => {
    // Negative control of the rule above: only Meta's release frees the key.
    const t = new ChordTracker();
    const M = { metaKey: true, shiftKey: true };
    t.down(ev('Meta', 'MetaLeft', { metaKey: true }));
    t.down(ev('Shift', 'ShiftLeft', M));
    expect(t.down(ev('Enter', 'Enter', M)).act).toBe(true);
    t.up(ev('Shift', 'ShiftLeft', { metaKey: true }));
    expect(t.armed).toBe(false);
    expect(t.down(ev('Enter', 'Enter', M)).act).toBe(false);
  });

  it('a_decision_chord_that_did_not_act_still_needs_release', () => {
    const t = new ChordTracker();
    t.down(ev('Control', 'ControlLeft', { ctrlKey: true }));
    t.down(ev('Shift', 'ShiftLeft', CS));
    expect(t.down(ev('Enter', 'Enter', { ...CS, repeat: true })).act).toBe(false);
    t.up(ev('Enter', 'Enter', CS));
    expect(t.down(ev('Enter', 'Enter', CS)).act).toBe(false);
  });
});


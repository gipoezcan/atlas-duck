import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { Header } from './Header';
import { helpOpen, openWindow, quit } from './ipc/invoke';
import statusLines from './ipc/fixtures/status_line.json';
import type { StatusLine } from './ipc/types';

vi.mock('./ipc/invoke', () => ({ openWindow: vi.fn(), quit: vi.fn(), helpOpen: vi.fn() }));

beforeEach(() => {
  vi.mocked(openWindow).mockReset().mockResolvedValue(null);
  vi.mocked(quit).mockReset().mockResolvedValue(null);
  vi.mocked(helpOpen).mockReset().mockResolvedValue(null);
});

describe('Header', () => {
  it('banner_levels_text_labelled', () => {
    const lines: StatusLine[] = statusLines.map((l) => ({
      ...l,
      level: l.level === 'caution' ? 'caution' : 'info',
    }));
    render(<Header lines={lines} />);
    const items = screen.getAllByRole('listitem');
    expect(items).toHaveLength(statusLines.length);
    expect(items[0]?.textContent).toMatch(/^Caution: Locked/);
    expect(items[1]?.textContent).toBe('Info: 2 need attention');
  });

  // T21b: the anchor-directory and keychain-anchor ids of the shared (Rust-pinned) fixture each
  // render their own text under the caution label.
  it.each([
    ['anchor_dir_write_failing', 'Writing to the anchor directory fails; 3 lines wait and will be retried.'],
    ['anchor_dir_lines_pending', '1 line waits to be written to the anchor directory.'],
    ['anchors_missing', 'The head anchor entry is missing from the keychain.'],
  ])('banner_renders_%s', (id, text) => {
    const line = statusLines.find((l) => l.id === id);
    expect(line?.text).toBe(text);
    expect(line?.level).toBe('caution');
    render(<Header lines={[{ id, text, level: 'caution' }]} />);
    expect(screen.getByRole('listitem').textContent).toBe(`Caution: ${text}`);
  });

  it('buttons_call_open_window_and_quit', () => {
    render(<Header lines={[]} />);
    for (const [name, window] of [
      ['Settings', 'settings'],
      ['Audit', 'audit'],
      ['Running scripts', 'running_scripts'],
      ['Onboarding', 'onboarding'],
    ] as const) {
      fireEvent.click(screen.getByRole('button', { name }));
      expect(openWindow).toHaveBeenLastCalledWith(window);
    }
    expect(quit).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Quit' }));
    expect(quit).toHaveBeenCalledTimes(1);
  });

  it('help_button_opens_the_approvals_page', () => {
    render(<Header lines={[]} />);
    fireEvent.click(screen.getByRole('button', { name: 'Help' }));
    expect(helpOpen).toHaveBeenCalledWith('approvals', 'queue');
  });
});

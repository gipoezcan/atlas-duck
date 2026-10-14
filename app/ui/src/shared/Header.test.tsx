import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { Header } from './Header';
import { openWindow, quit } from './ipc/invoke';
import statusLines from './ipc/fixtures/status_line.json';
import type { StatusLine } from './ipc/types';

vi.mock('./ipc/invoke', () => ({ openWindow: vi.fn(), quit: vi.fn() }));

beforeEach(() => {
  vi.mocked(openWindow).mockReset().mockResolvedValue(null);
  vi.mocked(quit).mockReset().mockResolvedValue(null);
});

describe('Header', () => {
  it('banner_levels_text_labelled', () => {
    const lines: StatusLine[] = statusLines.map((l) => ({
      ...l,
      level: l.level === 'caution' ? 'caution' : 'info',
    }));
    render(<Header lines={lines} />);
    const items = screen.getAllByRole('listitem');
    expect(items).toHaveLength(2);
    expect(items[0]?.textContent).toMatch(/^Caution: Locked/);
    expect(items[1]?.textContent).toBe('Info: 2 need attention');
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
});
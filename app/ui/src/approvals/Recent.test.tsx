import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import recentFixture from '../shared/ipc/fixtures/recent_item.json';
import type { RecentItem } from '../shared/ipc/types';
import { Recent } from './Recent';

const fixture: RecentItem[] = recentFixture;

describe('Recent', () => {
  it('needs_attention_pinned_and_acknowledge', () => {
    const onAcknowledge = vi.fn();
    // The needs-attention row is listed second so that pinning, not order, puts it first.
    render(<Recent items={[...fixture].reverse()} onAcknowledge={onAcknowledge} />);
    const pinned = screen.getByRole('region', { name: 'Needs attention' });
    expect(within(pinned).getByText('jira.comment.add')).toBeTruthy();
    expect(within(pinned).getByText('HTTP 403: no permission')).toBeTruthy();
    expect(within(pinned).queryByText('jira.issue.get')).toBeNull();
    expect(screen.getByText('jira.issue.get')).toBeTruthy();

    fireEvent.click(within(pinned).getByRole('button', { name: 'Acknowledge' }));
    expect(onAcknowledge).toHaveBeenCalledWith(['req_0123456789abcdefghij']);
  });

  it('acknowledged_items_leave_the_pinned_section', () => {
    const items = fixture.map((i) => ({ ...i, acknowledged: true }));
    render(<Recent items={items} onAcknowledge={vi.fn()} />);
    expect(screen.queryByRole('region', { name: 'Needs attention' })).toBeNull();
    expect(screen.getByText('jira.comment.add')).toBeTruthy();
  });

  it('outcome_unknown_says_check_target', () => {
    const items = fixture.map((i) => ({ ...i, status: 'outcome_unknown', error_text: null }));
    render(<Recent items={items} onAcknowledge={vi.fn()} />);
    expect(screen.getAllByText('check target').length).toBeGreaterThan(0);
  });

  it('renders_decided_at_without_locale', () => {
    render(<Recent items={fixture} onAcknowledge={vi.fn()} />);
    expect(screen.getByText('2026-10-14 09:30 UTC')).toBeTruthy();
  });
});
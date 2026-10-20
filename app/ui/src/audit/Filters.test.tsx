import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import type { AuditFilter } from '../shared/ipc/types';
import { Filters } from './Filters';
import { utcOf } from './text';

const field = (name: string) => screen.getByLabelText(name) as HTMLInputElement;
const apply = () => fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));

function set(name: string, value: string) {
  fireEvent.change(field(name), { target: { value } });
}

describe('Audit filters (spec 8.10, L38)', () => {
  it('filters_build_typed_query: each typed input becomes its own key of the filter, empty ones none', () => {
    const onApply = vi.fn<(f: AuditFilter) => void>();
    render(<Filters onApply={onApply} />);
    // The time range: typed date-time inputs, read as UTC.
    expect(field('From (UTC)').type).toBe('datetime-local');
    expect(field('To (UTC)').type).toBe('datetime-local');
    set('From (UTC)', '2026-10-01T00:00');
    set('To (UTC)', '2026-10-19T08:30:15.250');
    set('Agent name', 'claude-code');
    set('Operation', 'jira.issue.get');
    set('Instance id', '0b9d3f62-4c1a-4f0e-9a51-7f2a6c3e8d11');
    set('Target (starts with)', 'PROJ-');
    // Class and decision are closed lists, not free text.
    expect(screen.getByLabelText('Class').tagName).toBe('SELECT');
    expect(screen.getByLabelText('Decision').tagName).toBe('SELECT');
    fireEvent.change(screen.getByLabelText('Class'), { target: { value: 'write' } });
    fireEvent.change(screen.getByLabelText('Decision'), { target: { value: 'deny' } });
    // The flags: one checkbox each, sent in the 8.2 order whatever the order of the clicks.
    fireEvent.click(screen.getByRole('checkbox', { name: 'integrity incident' }));
    fireEvent.click(screen.getByRole('checkbox', { name: 'stale' }));
    apply();
    expect(onApply).toHaveBeenCalledTimes(1);
    expect(onApply).toHaveBeenLastCalledWith({
      from_utc: '2026-10-01T00:00:00.000Z',
      to_utc: '2026-10-19T08:30:15.250Z',
      agent_name: 'claude-code',
      op_id: 'jira.issue.get',
      op_class: 'write',
      instance_id: '0b9d3f62-4c1a-4f0e-9a51-7f2a6c3e8d11',
      target: 'PROJ-',
      decision: 'deny',
      flags_any: ['stale', 'integrity_incident'],
    });
    // No payload field exists (L38): the only text inputs are the four column filters.
    expect(screen.getAllByRole('textbox')).toHaveLength(4);
    expect(screen.getByText(/payloads are not searched/)).toBeTruthy();
  });

  it('the class and decision options are labelled from the strings table, the value is the wire name', () => {
    render(<Filters onApply={() => undefined} />);
    const options = (label: string) =>
      [...(screen.getByLabelText(label) as HTMLSelectElement).options].map((o) => [o.value, o.textContent]);
    expect(options('Decision')).toContainEqual(['approve_edited', 'approve (edited)']);
    expect(options('Decision')).toContainEqual(['release_redacted', 'release (redacted)']);
    expect(options('Class')).toEqual([
      ['', 'any'],
      ['read', 'read'],
      ['write', 'write'],
      ['script', 'script'],
    ]);
  });

  it('a date-time field is read as UTC text in the `ts_utc` form; anything else is refused', () => {
    // A browser normalizes `.500` to `.5`: the fraction is milliseconds from the left.
    expect(utcOf('2026-10-19T08:30:15.5')).toBe('2026-10-19T08:30:15.500Z');
    expect(utcOf('2026-10-19T08:30:15.05')).toBe('2026-10-19T08:30:15.050Z');
    expect(utcOf('2026-10-19T08:30:15.123')).toBe('2026-10-19T08:30:15.123Z');
    expect(utcOf('2026-10-19T08:30:15')).toBe('2026-10-19T08:30:15.000Z');
    expect(utcOf('2026-10-19T08:30')).toBe('2026-10-19T08:30:00.000Z');
    expect(utcOf('')).toBeNull();
    for (const bad of ['2026-10-19', '2026-10-19 08:30', '+12026-10-19T08:30', '2026-10-19T08:30:15.1234', '2026-10-19T08:30Z']) {
      expect(utcOf(bad)).toBeUndefined();
    }
  });

  it('an untouched form is the empty filter; Clear goes back to it', () => {
    const onApply = vi.fn<(f: AuditFilter) => void>();
    render(<Filters onApply={onApply} />);
    apply();
    expect(onApply).toHaveBeenLastCalledWith({});
    set('Agent name', 'x');
    fireEvent.click(screen.getByRole('checkbox', { name: 'batch' }));
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(onApply).toHaveBeenLastCalledWith({});
    expect(field('Agent name').value).toBe('');
    expect((screen.getByRole('checkbox', { name: 'batch' }) as HTMLInputElement).checked).toBe(false);
  });

  it('a text over 2048 bytes, a NUL or a reversed range is refused here, named at its field', () => {
    const onApply = vi.fn<(f: AuditFilter) => void>();
    render(<Filters onApply={onApply} />);
    // 1024 two-byte characters are 2048 bytes: the bound itself is accepted.
    set('Agent name', 'é'.repeat(1024));
    apply();
    expect(onApply).toHaveBeenCalledTimes(1);
    set('Agent name', 'é'.repeat(1024) + 'a');
    apply();
    expect(onApply).toHaveBeenCalledTimes(1);
    expect(field('Agent name').getAttribute('aria-invalid')).toBe('true');
    const described = field('Agent name').getAttribute('aria-describedby') ?? '';
    expect(document.getElementById(described)?.textContent).toBe('At most 2048 bytes');
    expect(screen.getByRole('alert').textContent).toBe('Check the filters');
    // Focus goes to the field that was refused, not left on the button.
    expect(document.activeElement).toBe(field('Agent name'));

    set('Agent name', '');
    set('Target (starts with)', 'a\u0000b');
    apply();
    expect(onApply).toHaveBeenCalledTimes(1);
    expect(field('Target (starts with)').getAttribute('aria-invalid')).toBe('true');

    set('Target (starts with)', '');
    set('From (UTC)', '2026-10-19T00:00');
    set('To (UTC)', '2026-10-18T00:00');
    apply();
    expect(onApply).toHaveBeenCalledTimes(1);
    expect(screen.getByText('"From" is after "To"')).toBeTruthy();

    set('To (UTC)', '2026-10-19T00:00');
    apply();
    expect(onApply).toHaveBeenCalledTimes(2);
    expect(onApply).toHaveBeenLastCalledWith({
      from_utc: '2026-10-19T00:00:00.000Z',
      to_utc: '2026-10-19T00:00:00.000Z',
    });
    expect(screen.queryByRole('alert')).toBeNull();
  });
});

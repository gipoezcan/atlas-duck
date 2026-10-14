import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { Windowed } from './Windowed';

const rows = Array.from({ length: 10_000 }, (_, i) => i);

describe('Windowed', () => {
  it('renders_only_visible_slice', () => {
    const { container } = render(
      <Windowed label="rows" rows={rows} rowHeight={20} height={200} render={(r) => <span>row {r}</span>} />,
    );
    expect(container.querySelectorAll('.windowed-row').length).toBeLessThan(100);
    expect(screen.getByText('row 0')).toBeTruthy();
    expect(screen.queryByText('row 9999')).toBeNull();
  });

  it('scrolls_from_the_keyboard_and_on_scroll', () => {
    render(
      <Windowed label="rows" rows={rows} rowHeight={20} height={200} render={(r) => <span>row {r}</span>} />,
    );
    const list = screen.getByRole('list', { name: 'rows' });
    fireEvent.keyDown(list, { key: 'End' });
    expect(screen.getByText('row 9999')).toBeTruthy();
    expect(screen.queryByText('row 0')).toBeNull();
    fireEvent.keyDown(list, { key: 'Home' });
    expect(screen.getByText('row 0')).toBeTruthy();
    fireEvent.scroll(list, { target: { scrollTop: 2000 } });
    expect(screen.getByText('row 100')).toBeTruthy();
  });
});
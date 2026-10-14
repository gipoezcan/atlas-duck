import { useState, type KeyboardEvent, type ReactNode, type UIEvent } from 'react';

interface WindowedProps<T> {
  rows: readonly T[];
  /** Every row has this height in px; the slice is computed from it. */
  rowHeight: number;
  render: (row: T, index: number) => ReactNode;
  /** Viewport height in px. */
  height?: number;
  /** Rows rendered beyond each edge of the viewport. */
  overscan?: number;
  label: string;
}

/**
 * A fixed-row-height list that renders only the visible slice plus overscan, so a queue of
 * thousands of rows costs a screenful of DOM (P-02). The viewport is focusable and scrolls from
 * the keyboard.
 */
export function Windowed<T>({
  rows,
  rowHeight,
  render,
  height = 480,
  overscan = 5,
  label,
}: WindowedProps<T>) {
  const [top, setTop] = useState(0);
  const first = Math.max(0, Math.floor(top / rowHeight) - overscan);
  const last = Math.min(rows.length, Math.ceil((top + height) / rowHeight) + overscan);
  const slice = rows.slice(first, last);

  const onScroll = (e: UIEvent<HTMLDivElement>) => setTop(e.currentTarget.scrollTop);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.target !== e.currentTarget) return;
    const el = e.currentTarget;
    const max = Math.max(0, rows.length * rowHeight - height);
    const page = Math.max(rowHeight, height - rowHeight);
    const next = {
      ArrowDown: top + rowHeight,
      ArrowUp: top - rowHeight,
      PageDown: top + page,
      PageUp: top - page,
      Home: 0,
      End: max,
    }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    const clamped = Math.min(max, Math.max(0, next));
    el.scrollTop = clamped;
    setTop(clamped);
  };

  return (
    <div
      className="windowed"
      style={{ height, overflowY: 'auto', position: 'relative' }}
      tabIndex={0}
      role="list"
      aria-label={label}
      onScroll={onScroll}
      onKeyDown={onKeyDown}
    >
      <div style={{ height: rows.length * rowHeight, position: 'relative' }}>
        {slice.map((row, i) => (
          <div
            key={first + i}
            role="listitem"
            className="windowed-row"
            style={{
              position: 'absolute',
              top: (first + i) * rowHeight,
              height: rowHeight,
              left: 0,
              right: 0,
            }}
          >
            {render(row, first + i)}
          </div>
        ))}
      </div>
    </div>
  );
}
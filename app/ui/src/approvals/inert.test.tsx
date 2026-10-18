import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { INERT_MS, useInert } from './inert';

// The page clock is driven by hand; only the timers are fake, so a timer can fire while
// `performance.now()` still reads a little before the deadline (their clocks round differently).
let clock = 0;

beforeEach(() => {
  clock = 0;
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  vi.spyOn(performance, 'now').mockImplementation(() => clock);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('useInert timers', () => {
  it('ui01_inert_period_ends_even_when_the_timer_fires_before_the_clock_reaches_it', () => {
    const { result } = renderHook(() => useInert('r1:1:h'));
    expect(result.current.approveInert).toBe(true);

    // The timer fires 1 ms early by the page clock: the period is not over, the control stays
    // disabled, and another timer is armed for the rest.
    act(() => {
      clock = INERT_MS - 1;
      vi.advanceTimersByTime(INERT_MS);
    });
    expect(result.current.approveInert).toBe(true);
    expect(vi.getTimerCount()).toBe(1);

    // The rest elapses: the control comes on, with nothing else to re-render it.
    act(() => {
      clock = INERT_MS;
      vi.advanceTimersByTime(1);
    });
    expect(result.current.approveInert).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('ui01_inert_period_is_never_shortened_by_an_early_timer', () => {
    const { result } = renderHook(() => useInert('r1:1:h'));
    // Several early firings in a row: still inert while the clock is before the end.
    for (const at of [400, 700, 999]) {
      act(() => {
        clock = at;
        vi.advanceTimersByTime(INERT_MS);
      });
      expect(result.current.approveInert).toBe(true);
    }
    act(() => {
      clock = INERT_MS + 1;
      vi.advanceTimersByTime(INERT_MS);
    });
    expect(result.current.approveInert).toBe(false);
  });
});

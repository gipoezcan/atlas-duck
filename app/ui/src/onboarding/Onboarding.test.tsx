import { act, fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { onboardingText } from '../shared/ipc/invoke';
import { Onboarding } from './Onboarding';

vi.mock('../shared/ipc/invoke', () => ({ onboardingText: vi.fn() }));

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

beforeEach(() => {
  vi.mocked(onboardingText).mockReset();
});

describe('Onboarding shell', () => {
  it('onboarding_text_rendered_as_text: the snippet is one text node, whatever it holds', async () => {
    const hostile =
      '# atlas-duck\n- `atlas-duck ops list`\n<img src=x onerror="window.__pwned=1">\n<script>window.__pwned=1</script>\n[x](javascript:alert(1))';
    vi.mocked(onboardingText).mockResolvedValue({ text: hostile });
    const { container } = render(<Onboarding />);
    expect(screen.getByRole('status').textContent).toBe('Loading the instructions');
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Onboarding');
    const pre = screen.getByLabelText('Instructions for your agents');
    expect(pre.tagName).toBe('PRE');
    expect(pre.textContent).toBe(hostile);
    expect(pre.childNodes).toHaveLength(1);
    expect(pre.firstChild?.nodeType).toBe(Node.TEXT_NODE);
    expect(container.querySelector('img, script, a, [onerror]')).toBeNull();
    expect((window as unknown as Record<string, unknown>)['__pwned']).toBeUndefined();
    expect(onboardingText).toHaveBeenCalledTimes(1);
  });

  it('a failed load is a fixed alert with a retry', async () => {
    vi.mocked(onboardingText).mockRejectedValueOnce({ kind: 'internal' });
    render(<Onboarding />);
    await flush();
    expect(screen.getByRole('alert').textContent).toContain('Could not load the instructions');
    vi.mocked(onboardingText).mockResolvedValueOnce({ text: 'second try' });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    });
    await flush();
    expect(screen.getByLabelText('Instructions for your agents').textContent).toBe('second try');
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('two clicks on retry in one tick start one load, and the alert gives way to the status', async () => {
    vi.mocked(onboardingText).mockRejectedValueOnce({ kind: 'internal' });
    render(<Onboarding />);
    await flush();
    let resolve: (v: { text: string }) => void = () => undefined;
    vi.mocked(onboardingText).mockImplementationOnce(
      () => new Promise((r) => { resolve = r; }),
    );
    const retry = screen.getByRole('button', { name: 'Try again' });
    act(() => {
      retry.click();
      retry.click();
    });
    expect(onboardingText).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByRole('status').textContent).toBe('Loading the instructions');
    await act(async () => {
      resolve({ text: 'late' });
    });
    await flush();
    expect(screen.getByLabelText('Instructions for your agents').textContent).toBe('late');
  });
});

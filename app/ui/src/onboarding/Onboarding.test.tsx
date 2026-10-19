import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { onboardingText } from '../shared/ipc/invoke';
import { Onboarding } from './Onboarding';
import { OnboardingText, WIZARD_SECTION_IDS } from './OnboardingText';

vi.mock('../shared/ipc/invoke', () => ({ onboardingText: vi.fn() }));

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

const writeText = vi.fn<(text: string) => Promise<void>>();
const readText = vi.fn<() => Promise<string>>();

beforeEach(() => {
  vi.mocked(onboardingText).mockReset();
  writeText.mockReset();
  readText.mockReset();
  writeText.mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText, readText },
    configurable: true,
  });
});

afterEach(() => {
  Reflect.deleteProperty(navigator, 'clipboard');
});

const sections = (...texts: string[]) => ({
  sections: texts.map((text, i) => ({ id: `s${i}`, title: `Section ${i}`, text })),
});

describe('Onboarding page', () => {
  it('onboarding_sections_rendered_as_text: every section is one text node, whatever it holds', async () => {
    const hostile =
      '# atlas-duck\n- `atlas-duck ops list`\n<img src=x onerror="window.__pwned=1">\n<script>window.__pwned=1</script>\n[x](javascript:alert(1))';
    vi.mocked(onboardingText).mockResolvedValue({
      sections: [
        { id: 'commands', title: '<b>Commands</b>', text: hostile },
        { id: 'retry', title: 'Reading the status', text: 'branch on `status`' },
      ],
    });
    const { container } = render(<Onboarding />);
    expect(screen.getByRole('status').textContent).toBe('Loading the instructions');
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Onboarding');
    const headings = screen.getAllByRole('heading', { level: 2 });
    expect(headings.map((h) => h.textContent)).toEqual(['<b>Commands</b>', 'Reading the status']);
    const pre = screen.getByLabelText('<b>Commands</b>');
    expect(pre.tagName).toBe('PRE');
    expect(pre.textContent).toBe(hostile);
    expect(pre.childNodes).toHaveLength(1);
    expect(pre.firstChild?.nodeType).toBe(Node.TEXT_NODE);
    expect(screen.getByLabelText('Reading the status').textContent).toBe('branch on `status`');
    expect(container.querySelectorAll('pre')).toHaveLength(2);
    expect(container.querySelector('img, script, a, b, [onerror]')).toBeNull();
    expect((window as unknown as Record<string, unknown>)['__pwned']).toBeUndefined();
    expect(onboardingText).toHaveBeenCalledTimes(1);
  });

  it('a copy button per section writes that section only, on the click, and says so politely', async () => {
    vi.mocked(onboardingText).mockResolvedValue(sections('first text', 'second text'));
    render(<Onboarding />);
    await flush();
    // Nothing is written, and nothing read, until the user clicks.
    expect(writeText).not.toHaveBeenCalled();
    const buttons = screen.getAllByRole('button', { name: /^Copy / });
    expect(buttons.map((b) => b.getAttribute('aria-label'))).toEqual([
      'Copy Section 0',
      'Copy Section 1',
    ]);
    const status = screen.getByRole('status');
    expect(status.textContent).toBe('');
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy Section 1' }));
    });
    await flush();
    expect(writeText).toHaveBeenCalledTimes(1);
    expect(writeText).toHaveBeenCalledWith('second text');
    expect(status.textContent).toBe('Copied: Section 1');
    expect(readText).not.toHaveBeenCalled();
  });

  it('copying the same section twice clears the live line first so the second copy is announced', async () => {
    vi.mocked(onboardingText).mockResolvedValue(sections('text'));
    render(<Onboarding />);
    await flush();
    const status = screen.getByRole('status');
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy Section 0' }));
    });
    await flush();
    expect(status.textContent).toBe('Copied: Section 0');
    let resolve: () => void = () => undefined;
    writeText.mockImplementationOnce(() => new Promise<void>((r) => { resolve = r; }));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy Section 0' }));
    });
    expect(status.textContent).toBe('');
    await act(async () => {
      resolve();
    });
    await flush();
    expect(status.textContent).toBe('Copied: Section 0');
  });

  it('each text block is a named region, so its heading is exposed as its name', async () => {
    vi.mocked(onboardingText).mockResolvedValue(sections('a', 'b'));
    render(<Onboarding />);
    await flush();
    expect(screen.getByRole('region', { name: 'Section 0' }).textContent).toBe('a');
    expect(screen.getByRole('region', { name: 'Section 1' }).textContent).toBe('b');
  });

  it('the wizard subset shows exactly its seven sections of the full page, in the page order', async () => {
    const ids = [
      'commands', 'envelope', 'exit_matrix', 'timeouts', 'sessions', 'redaction', 'parallel',
      'paging', 'writes', 'retry', 'outcome_unknown', 'exit9', 'confluence', 'create_fields',
      'conflicts', 'windows_paths', 'wsl',
    ];
    vi.mocked(onboardingText).mockResolvedValue({
      sections: ids.map((id) => ({ id, title: `T ${id}`, text: id })),
    });
    render(<OnboardingText only={WIZARD_SECTION_IDS} level={3} />);
    await flush();
    expect(screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent)).toEqual(
      WIZARD_SECTION_IDS.map((id) => `T ${id}`),
    );
    expect(WIZARD_SECTION_IDS).toHaveLength(7);
  });

  it('a clipboard that refuses, or is missing, is a fixed line and the text stays selectable', async () => {
    vi.mocked(onboardingText).mockResolvedValue(sections('only text'));
    render(<Onboarding />);
    await flush();
    writeText.mockRejectedValueOnce(new Error('denied'));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy Section 0' }));
    });
    await flush();
    expect(screen.getByRole('status').textContent).toBe(
      'Could not copy. Select the text and copy it yourself.',
    );
    const pre = screen.getByLabelText('Section 0');
    expect(pre.getAttribute('tabindex')).toBe('0');
    Reflect.deleteProperty(navigator, 'clipboard');
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy Section 0' }));
    });
    await flush();
    expect(screen.getByRole('status').textContent).toBe(
      'Could not copy. Select the text and copy it yourself.',
    );
  });

  it('the exit-code section lines stay readable as lines', async () => {
    const text = '- exit 0: `succeeded`\n- exit 2: `failed/usage`\n';
    vi.mocked(onboardingText).mockResolvedValue({
      sections: [{ id: 'exit_matrix', title: 'Exit codes', text }],
    });
    render(<Onboarding />);
    await flush();
    const pre = screen.getByLabelText('Exit codes');
    expect(pre.textContent).toBe(text);
    expect(within(pre).queryAllByRole('listitem')).toHaveLength(0);
  });

  it('a failed load is a fixed alert with a retry', async () => {
    vi.mocked(onboardingText).mockRejectedValueOnce({ kind: 'internal' });
    render(<Onboarding />);
    await flush();
    expect(screen.getByRole('alert').textContent).toContain('Could not load the instructions');
    vi.mocked(onboardingText).mockResolvedValueOnce(sections('second try'));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    });
    await flush();
    expect(screen.getByLabelText('Section 0').textContent).toBe('second try');
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('two clicks on retry in one tick start one load, and the alert gives way to the status', async () => {
    vi.mocked(onboardingText).mockRejectedValueOnce({ kind: 'internal' });
    render(<Onboarding />);
    await flush();
    let resolve: (v: ReturnType<typeof sections>) => void = () => undefined;
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
    // The button that was focused is gone: focus moves to the status, not to the body.
    expect(document.activeElement).toBe(screen.getByRole('status'));
    await act(async () => {
      resolve(sections('late'));
    });
    await flush();
    expect(screen.getByLabelText('Section 0').textContent).toBe('late');
  });
});

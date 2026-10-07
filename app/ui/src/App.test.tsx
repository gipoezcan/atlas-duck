import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { App } from './App';

describe('App', () => {
  it('renders the heading atlas-duck as a single text node', () => {
    render(<App />);
    const heading = screen.getByRole('heading', { level: 1, name: 'atlas-duck' });
    expect(heading.childNodes).toHaveLength(1);
    const text = heading.firstChild;
    expect(text?.nodeType).toBe(Node.TEXT_NODE);
    expect(text?.nodeValue).toBe('atlas-duck');
  });

  it('contains no iframe or script element', () => {
    const { container } = render(<App />);
    expect(container.querySelector('iframe, script')).toBeNull();
  });
});

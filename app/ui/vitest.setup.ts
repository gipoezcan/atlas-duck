import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

// Vitest runs without globals, so Testing Library's auto-cleanup is not
// registered; unmount every rendered tree after each test.
afterEach(() => {
  cleanup();
});

import { createRoot } from 'react-dom/client';

import { WINDOW_TITLES } from '../shared/strings';

// Placeholder entry: a later task replaces it with the real window.
const root = document.getElementById('root');
if (root) {
  createRoot(root).render(<h1>{WINDOW_TITLES.setup}</h1>);
}

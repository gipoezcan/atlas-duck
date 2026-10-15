import { createRoot } from 'react-dom/client';

import { Running } from './Running';

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(<Running />);
}

import { createRoot } from 'react-dom/client';

import { Settings } from './Settings';

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(<Settings />);
}

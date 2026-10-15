import { createRoot } from 'react-dom/client';

import { markAlive } from '../shared/alive';
import { Settings } from './Settings';

markAlive();
const root = document.getElementById('root');
if (root) {
  createRoot(root).render(<Settings />);
}

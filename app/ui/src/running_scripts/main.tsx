import { createRoot } from 'react-dom/client';

import { markAlive } from '../shared/alive';
import { Running } from './Running';

markAlive();
const root = document.getElementById('root');
if (root) {
  createRoot(root).render(<Running />);
}

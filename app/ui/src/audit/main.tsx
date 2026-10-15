import { createRoot } from 'react-dom/client';

import { markAlive } from '../shared/alive';
import { Audit } from './Audit';

markAlive();
const root = document.getElementById('root');
if (root) {
  createRoot(root).render(<Audit />);
}

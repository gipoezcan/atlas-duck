import { createRoot } from 'react-dom/client';

import { markAlive } from '../shared/alive';
import { Wizard } from './Wizard';

markAlive();
const root = document.getElementById('root');
if (root) {
  createRoot(root).render(<Wizard />);
}

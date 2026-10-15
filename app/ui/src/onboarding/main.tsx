import { createRoot } from 'react-dom/client';

import { markAlive } from '../shared/alive';
import { Onboarding } from './Onboarding';

markAlive();
const root = document.getElementById('root');
if (root) {
  createRoot(root).render(<Onboarding />);
}

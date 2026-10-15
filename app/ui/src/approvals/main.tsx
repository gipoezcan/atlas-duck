import { createRoot } from 'react-dom/client';

import { markAlive } from '../shared/alive';
import { App } from './App';

markAlive();
const root = document.getElementById('root');
if (root) {
  createRoot(root).render(<App />);
}
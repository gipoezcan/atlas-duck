import { createRoot } from 'react-dom/client';

import { Wizard } from './Wizard';

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(<Wizard />);
}

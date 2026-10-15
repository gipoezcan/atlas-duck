import { createRoot } from 'react-dom/client';

import { Audit } from './Audit';

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(<Audit />);
}

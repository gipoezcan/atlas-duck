import { createRoot } from 'react-dom/client';

import { Onboarding } from './Onboarding';

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(<Onboarding />);
}

import { createRoot } from 'react-dom/client';

import { ServerApprovals } from './ServerApprovals';

const root = document.getElementById('root');
if (root) {
  const item = new URLSearchParams(window.location.search).get('item');
  createRoot(root).render(<ServerApprovals item={item} />);
}

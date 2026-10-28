import { createRoot } from 'react-dom/client';

import { ServerLangRoot } from '../shell/ServerLangRoot';
import { ServerApprovals } from './ServerApprovals';

const root = document.getElementById('root');
if (root) {
  const item = new URLSearchParams(window.location.search).get('item');
  createRoot(root).render(
    <ServerLangRoot>
      <ServerApprovals item={item} />
    </ServerLangRoot>,
  );
}

import { createRoot } from 'react-dom/client';

import { ServerLangRoot } from '../shell/ServerLangRoot';
import { Login } from './Login';

const root = document.getElementById('root');
if (root) {
  const next = new URLSearchParams(window.location.search).get('next');
  createRoot(root).render(
    <ServerLangRoot>
      <Login next={next} />
    </ServerLangRoot>,
  );
}

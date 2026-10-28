import { createRoot } from 'react-dom/client';

import { RequireSession } from '../shell/RequireSession';
import { ServerHeader } from '../shell/ServerHeader';
import { ServerLangRoot } from '../shell/ServerLangRoot';
import { AuditorPage } from './Users';

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <ServerLangRoot>
      <RequireSession>
        <ServerHeader />
        <AuditorPage />
      </RequireSession>
    </ServerLangRoot>,
  );
}

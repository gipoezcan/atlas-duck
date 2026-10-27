import { createRoot } from 'react-dom/client';

import { RequireSession } from '../shell/RequireSession';
import { ServerHeader } from '../shell/ServerHeader';
import { ApiKeys } from './ApiKeys';

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <RequireSession>
      <ServerHeader />
      <ApiKeys />
    </RequireSession>,
  );
}

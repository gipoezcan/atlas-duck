import { createRoot } from 'react-dom/client';

import { RequireSession } from '../shell/RequireSession';
import { ServerHeader } from '../shell/ServerHeader';
import { ConnectedApps } from './ConnectedApps';

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <RequireSession>
      <ServerHeader />
      <ConnectedApps />
    </RequireSession>,
  );
}

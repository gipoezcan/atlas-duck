import { createRoot } from 'react-dom/client';

import { RequireSession } from '../shell/RequireSession';
import { ServerHeader } from '../shell/ServerHeader';
import { ExportPanel } from '../export/ExportPanel';
import { OwnAudit } from './OwnAudit';

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <RequireSession>
      <ServerHeader />
      <OwnAudit exportPanel={<ExportPanel base="/api/me/audit/exports" />} />
    </RequireSession>,
  );
}

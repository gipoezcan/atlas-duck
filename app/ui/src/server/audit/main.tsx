import { createRoot } from 'react-dom/client';

import { RequireSession } from '../shell/RequireSession';
import { ServerHeader } from '../shell/ServerHeader';
import { ExportPanel } from '../export/ExportPanel';
import { ServerLangRoot } from '../shell/ServerLangRoot';
import { OwnAudit } from './OwnAudit';

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <ServerLangRoot>
      <RequireSession>
        <ServerHeader />
        <OwnAudit exportPanel={<ExportPanel base="/api/me/audit/exports" />} />
      </RequireSession>
    </ServerLangRoot>,
  );
}

import type { ReactNode } from 'react';

import { Audit } from '../../audit/Audit';

/**
 * The server's own-chain page (SM-6.4 first sentence, PD-251): the desktop Audit window's records,
 * trail and payload over the HTTP transport (`/api/cmd/audit_*`, the user's own store only), with
 * the desktop-only controls left out. `exportPanel` is the server export job's panel (T20).
 */
export function OwnAudit({ exportPanel = null }: { exportPanel?: ReactNode } = {}) {
  return <Audit mode="server" exportPanel={exportPanel} />;
}

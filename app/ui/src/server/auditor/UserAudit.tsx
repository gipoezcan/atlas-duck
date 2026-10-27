import { useState } from 'react';

import { Audit } from '../../audit/Audit';
import { setPageTransport } from '../../shared/ipc/transport';
import { httpTransportFor } from '../../shared/ipc/transport-http';
import { ExportPanel } from '../export/ExportPanel';
import type { AuditedUser } from './Users';

export const USER_AUDIT_TEXT = {
  banner: (username: string) =>
    `You are viewing ${username}'s audit chain. Every view is recorded in your own audit chain.`,
} as const;

/** The selected user's base path of the auditor API. */
export function auditorBase(userId: string): string {
  return `/api/auditor/users/${encodeURIComponent(userId)}`;
}

/**
 * One user's chain for an auditor: the desktop audit components in server mode, every command sent
 * to `/api/auditor/users/<id>/<cmd>` through the scoped transport (set before the first render, so
 * no read reaches `/api/cmd`), the recording banner and the export panel for that user.
 */
export function UserAudit({ user }: { user: AuditedUser }) {
  // Set once, before the audit components render and send their first query.
  useState(() => {
    setPageTransport(httpTransportFor(auditorBase(user.user_id)));
    return true;
  });
  return (
    <>
      <p role="note" aria-label="Recorded view" className="notice window">
        {USER_AUDIT_TEXT.banner(user.username)}
      </p>
      <Audit mode="server" exportPanel={<ExportPanel base={`${auditorBase(user.user_id)}/exports`} />} />
    </>
  );
}

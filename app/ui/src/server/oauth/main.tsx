import { createRoot } from 'react-dom/client';

import { RequireSession } from '../shell/RequireSession';
import { ServerHeader } from '../shell/ServerHeader';
import { Consent, ConsentError } from './Consent';

// `/oauth/consent?req=<id>` (signed in) or `?error=<code>` (our error page, no session needed:
// the authorization endpoint sends unvalidated clients here before any session check).
const params = new URLSearchParams(window.location.search);
const error = params.get('error');
const req = params.get('req');
const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    error !== null || req === null ? (
      <ConsentError code={error ?? 'invalid_request'} />
    ) : (
      <RequireSession>
        <ServerHeader />
        <Consent req={req} />
      </RequireSession>
    ),
  );
}

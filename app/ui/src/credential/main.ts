import './credential.css';
import { invoke, listen } from './ipc';
import { mountCredentialPage } from './page';

// Vanilla TypeScript on purpose (PD-71): nothing under src/credential/ may import from
// src/shared/, so the bundle shares no chunk with the main windows.
const root = document.getElementById('credential');
if (root) {
  mountCredentialPage(root, { invoke, listen });
}

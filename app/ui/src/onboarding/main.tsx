import { createRoot } from 'react-dom/client';

import { markAlive } from '../shared/alive';
import { DesktopLangRoot } from '../shared/i18n/DesktopLangRoot';
import { Onboarding } from './Onboarding';

markAlive();
const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <DesktopLangRoot>
      <Onboarding />
    </DesktopLangRoot>,
  );
}

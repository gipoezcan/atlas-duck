import { createRoot } from 'react-dom/client';

import { markAlive } from '../shared/alive';
import { DesktopLangRoot } from '../shared/i18n/DesktopLangRoot';
import { Wizard } from './Wizard';

markAlive();
const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <DesktopLangRoot>
      <Wizard />
    </DesktopLangRoot>,
  );
}

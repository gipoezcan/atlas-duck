import { useEffect, useState, type ReactNode } from 'react';

import { on } from '../ipc/events';
import { uiLangGet } from '../ipc/invoke';
import { LangProvider } from './context';
import type { Lang } from './index';

/**
 * The language of a desktop window (M15 T3, PD-294): Rust's `ui_lang_get`, read once and again on
 * every `lang_changed` (the payload is never trusted as state). Children render after the first
 * answer, in English when it fails; a switch re-renders the texts only, the tree stays mounted, so
 * open dialogs, drafts and focus survive it.
 */
export function DesktopLangRoot({ children }: { children: ReactNode }) {
  const [lang, setLang] = useState<Lang | null>(null);

  useEffect(() => {
    let live = true;
    let latest = 0;
    const refresh = () => {
      const mine = ++latest;
      uiLangGet().then(
        (v) => {
          if (live && mine === latest) setLang(v.lang);
        },
        () => {
          if (live && mine === latest) setLang((l) => l ?? 'en');
        },
      );
    };
    const unlisten = on('lang_changed', refresh, { thisWindow: true });
    // Read once the listener is attached, so a change between a read and a listener is not lost.
    void Promise.allSettled([unlisten]).then(() => {
      if (live) refresh();
    });
    return () => {
      live = false;
      void unlisten.then((off) => off()).catch(() => undefined);
    };
  }, []);

  if (lang === null) return null;
  return <LangProvider lang={lang}>{children}</LangProvider>;
}

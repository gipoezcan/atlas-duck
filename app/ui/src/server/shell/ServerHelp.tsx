import { useLang, useText } from '../../shared/i18n/context';
import type { Lang } from '../../shared/i18n';
import uiLinks from '../../../../../docs/user-guide/ui-links.json';

export type ServerPath = keyof typeof uiLinks.server;

/** The `page#anchor` of a server page from `docs/user-guide/ui-links.json`; none for any other path. */
export function serverTarget(path: string): string | undefined {
  return Object.hasOwn(uiLinks.server, path) ? uiLinks.server[path as ServerPath] : undefined;
}

/** `/docs/<lang>/<page>#<anchor>` (the guide's index without a target): a plain same-origin path. */
export function docsHref(lang: Lang, target: string | undefined): string {
  return `/docs/${lang}/${target ?? ''}`;
}

/** The "?" of a server page: the guide section `ui-links.json` names for `path`, in a new tab. */
export function ServerHelpLink({ path, label }: { path: ServerPath; label: string }) {
  const t = useText();
  const lang = useLang();
  return (
    <a
      className="help-link"
      href={docsHref(lang, serverTarget(path))}
      target="_blank"
      rel="noreferrer"
      aria-label={t.common.help_for(label)}
    >
      ?
    </a>
  );
}

/** The guide's index ("Help" in the header and on the login page). */
export function ServerHelpIndex() {
  const t = useText();
  const lang = useLang();
  return (
    <a href={docsHref(lang, undefined)} target="_blank" rel="noreferrer">
      {t.server.header.help}
    </a>
  );
}
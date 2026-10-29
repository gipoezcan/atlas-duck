import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import uiLinks from '../../../../../docs/user-guide/ui-links.json';
import { HelpButton, HelpLink } from '../../shared/HelpLink';
import { de } from '../../shared/i18n/dict';
import { LangProvider } from '../../shared/i18n/context';
import { ServerLangRoot } from './ServerLangRoot';
import { docsHref, ServerHelpLink, serverTarget } from './ServerHelp';

describe('server help links', () => {
  it('header_and_login_say_hilfe_in_german', () => {
    expect(de.server.header.help).toBe('Hilfe');
    expect(de.server.login.help).toBe('Hilfe');
  });

  it('docs_href_is_plain_and_per_language', () => {
    expect(docsHref('en', 'approvals#queue')).toBe('/docs/en/approvals#queue');
    expect(docsHref('de', 'getting-started-server#sign-in')).toBe('/docs/de/getting-started-server#sign-in');
    expect(docsHref('de', undefined)).toBe('/docs/de/');
  });

  it('server_target_knows_only_the_listed_pages', () => {
    for (const [path, target] of Object.entries(uiLinks.server)) expect(serverTarget(path)).toBe(target);
    for (const bad of ['/nowhere', '/docs/en/', '', '/__proto__', 'constructor']) expect(serverTarget(bad)).toBeUndefined();
  });

  it.each(Object.entries(uiLinks.server))('question_mark_for_%s_resolves_through_ui_links', (path, target) => {
    for (const [lang, name] of [
      ['en', 'Help: Name'],
      ['de', 'Hilfe: Name'],
    ] as const) {
      const { unmount } = render(
        <LangProvider lang={lang}>
          <ServerHelpLink path={path as keyof typeof uiLinks.server} label="Name" />
        </LangProvider>,
      );
      const a = screen.getByRole('link', { name });
      expect(a.getAttribute('href')).toBe(`/docs/${lang}/${target}`);
      expect(a.getAttribute('target')).toBe('_blank');
      expect(a.getAttribute('rel')).toBe('noreferrer');
      unmount();
    }
  });

  // The Audit and Approvals components are shared with the desktop windows: their desktop help
  // buttons (which call `help_open`) must not appear on a server page.
  it('desktop_help_controls_are_absent_under_the_server_root', () => {
    render(
      <ServerLangRoot>
        <HelpButton window="audit" />
        <HelpLink section="audit/verification" label="Verification" />
      </ServerLangRoot>,
    );
    expect(screen.queryByRole('button')).toBeNull();
  });
});
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { LangProvider } from '../shared/i18n/context';
import { de, en } from '../shared/i18n/dict';
import { ApiKeys, createError, validateKey } from './api_keys/ApiKeys';
import { ConnectedApps } from './connected_apps/ConnectedApps';
import { Credentials, patError } from './credentials/Credentials';
import { Login, loginError } from './login/Login';
import { Consent, ConsentError, errorText } from './oauth/Consent';
import { ServerHeader } from './shell/ServerHeader';

vi.mock('../shared/ipc/transport-http', () => ({ loadSession: vi.fn(), csrf: () => 'csrf-1' }));

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

const german = (ui: React.ReactNode) => render(<LangProvider lang="de">{ui}</LangProvider>);

let fetchMock: ReturnType<typeof vi.fn>;
beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('the server user pages in German (M15 T8)', () => {
  it('login_in_german: texts and the rate-limit sentence', async () => {
    fetchMock.mockResolvedValue(json(429, { error: { code: 'auth/rate_limited' } }, { 'Retry-After': '120' }));
    german(<Login next={null} />);
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Bei atlas-duck anmelden');
    fireEvent.change(screen.getByLabelText('Benutzername'), { target: { value: 'alice' } });
    fireEvent.change(screen.getByLabelText('Passwort'), { target: { value: 'secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'Anmelden' }));
    await flush();
    expect(screen.getByRole('alert').textContent).toBe('Zu viele Versuche. Versuchen Sie es in 2 Minuten erneut.');
    expect(loginError('auth/rate_limited', 60, de)).toBe('Zu viele Versuche. Versuchen Sie es in 1 Minute erneut.');
    expect(loginError('auth/invalid_credentials', null, de)).toBe('Benutzername oder Passwort ist falsch.');
    expect(loginError('auth/invalid_credentials', null)).toBe(en.server.login.invalid_credentials);
  });

  it('api_key_errors_in_german: server codes, own sentences and the page', async () => {
    expect(createError('api_key/limit_reached', de)).toBe(
      'Sie haben die Höchstzahl von 25 aktiven Schlüsseln erreicht. Widerrufen Sie zuerst einen.',
    );
    expect(createError(null, de)).toBe('Der Schlüssel konnte nicht erstellt werden. Versuchen Sie es erneut.');
    expect(validateKey('', ['read'], '30', de)).toBe(
      'Der Name muss 1 bis 64 Zeichen lang sein und darf keine Steuerzeichen enthalten.',
    );
    expect(validateKey('ok', [], '30', de)).toBe('Wählen Sie mindestens eine Berechtigung.');
    const view = {
      id: 'k1',
      name: 'laptop',
      prefix: 'adk_abc',
      scopes: ['read'],
      created_at: 0,
      expires_at: 4_102_444_800,
      last_used_at: 0,
      revoked_at: null,
    };
    fetchMock.mockResolvedValueOnce(json(200, [view]));
    german(<ApiKeys />);
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('API-Schlüssel');
    expect(screen.getByRole('columnheader', { name: 'Zuletzt verwendet' })).toBeTruthy();
    const row = screen.getAllByRole('row')[1] as HTMLElement;
    expect(row.textContent).toContain('01.01.1970, 00:00 UTC');
    expect(row.textContent).toContain('01.01.2100, 00:00 UTC');
    expect(within(row).getByText('Aktiv')).toBeTruthy();
    fetchMock.mockResolvedValueOnce(json(409, { error: { code: 'api_key/limit_reached' } }));
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'second' } });
    fireEvent.click(screen.getByRole('button', { name: 'Schlüssel erstellen' }));
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(
      'Sie haben die Höchstzahl von 25 aktiven Schlüsseln erreicht. Widerrufen Sie zuerst einen.',
    );
  });

  it('credentials_in_german', async () => {
    fetchMock.mockResolvedValueOnce(
      json(200, [
        { alias: 'wiki', product: 'confluence', base_url: 'https://wiki.example.test', is_default: true, pat: 'stored', identity: 'jdoe' },
      ]),
    );
    german(<Credentials />);
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Zugangsdaten');
    expect(screen.getByText('Token gespeichert (als jdoe)')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Token ersetzen' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Token ersetzen' }));
    expect(screen.getByLabelText('Persönliches Zugriffstoken für wiki')).toBeTruthy();
    expect(patError('pat/check_failed', 'other_user', de)).toBe(
      'Dieses Token gehört einem anderen Atlassian-Benutzer. Entfernen Sie zuerst das gespeicherte Token.',
    );
    expect(patError(null, null, de)).toBe('Das Speichern ist fehlgeschlagen. Versuchen Sie es erneut.');
  });

  it('connected_apps_in_german: states and dates', async () => {
    fetchMock.mockResolvedValueOnce(
      json(200, [
        {
          grant_id: 'g1',
          client_id: 'c1',
          client_name: 'Claude Code',
          redirect_hosts: ['localhost'],
          scopes: ['read'],
          created_at: 0,
          last_used_at: null,
          expires_at: 4_102_444_800,
          revoked_at: null,
        },
      ]),
    );
    german(<ConnectedApps />);
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Verbundene Apps');
    const row = screen.getAllByRole('row')[1] as HTMLElement;
    expect(row.textContent).toContain('01.01.1970, 00:00 UTC');
    expect(within(row).getByText('Aktiv')).toBeTruthy();
    expect(within(row).getByRole('button', { name: 'Widerrufen' })).toBeTruthy();
  });

  it('consent_in_german: client, redirect host, choices and fixed errors', async () => {
    fetchMock.mockResolvedValueOnce(
      json(200, {
        client_name: 'Claude Code',
        client_id: 'c1',
        redirect_host: 'localhost',
        redirect_uri: 'http://localhost/cb',
        scopes: [
          { name: 'read', text: 'read data' },
          { name: 'propose_write', text: 'propose' },
          { name: 'scripts', text: 'run scripts' },
        ],
        expires_at: '2026-10-27T10:10:00.000Z',
      }),
    );
    german(<Consent req="r1" />);
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Einer App die Nutzung von atlas-duck erlauben?');
    expect(screen.getByText('(ungeprüft, von der App gewählt)')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Erlauben' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Ablehnen' })).toBeTruthy();
    expect(screen.getByText('Immer enthalten.')).toBeTruthy();
    const list = document.body.textContent ?? '';
    expect(list).toContain('read: Jira- und Confluence-Daten lesen, die Sie lesen können, nachdem Sie sie freigegeben haben.');
    expect(list).toContain('propose_write: Änderungen vorschlagen. Jede Änderung braucht hier weiterhin Ihre Freigabe.');
    expect(list).toContain('scripts: Schreibgeschützte Skripte in der Sandbox ausführen; Sie geben jedes Endergebnis frei.');
    expect(list).not.toContain('read data');
    cleanup();
    german(<ConsentError code="invalid_client" />);
    expect(screen.getByRole('alert').textContent).toBe(
      'Diese App ist bei atlas-duck nicht registriert. Beginnen Sie erneut in der App.',
    );
    expect(errorText('anything', de)).toBe('Diese Autorisierungsanfrage ist ungültig.');
  });

  it('header_in_german: navigation and sign out', () => {
    german(<ServerHeader />);
    expect(screen.getByRole('navigation', { name: 'Seiten' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Freigaben' }).getAttribute('href')).toBe('/approvals');
    expect(screen.getByRole('link', { name: 'Zugangsdaten' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'API-Schlüssel' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Verbundene Apps' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Mein Audit-Protokoll' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Abmelden' })).toBeTruthy();
  });
});
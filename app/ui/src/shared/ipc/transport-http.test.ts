import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { httpTransport, loadSession, resetSessionForTests } from './transport-http';

const SESSION = {
  user: 'alice',
  roles: ['user'],
  csrf_token: 'tok-1',
  expires_at: '2026-10-26T18:00:00Z',
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** A fetch stub answering from `script` in order and recording each request. */
function stubFetch(script: Response[]) {
  const calls: { url: string; init: RequestInit | undefined }[] = [];
  const fn = vi.fn((url: string, init?: RequestInit) => {
    calls.push({ url, init });
    const next = script.shift();
    return next === undefined ? Promise.reject(new Error('unexpected fetch')) : Promise.resolve(next);
  });
  vi.stubGlobal('fetch', fn);
  return calls;
}

/** A minimal EventSource stand-in: listeners per name, `emit` from the test, `close` recorded. */
class FakeEventSource {
  static instances: FakeEventSource[] = [];
  readonly url: string;
  closed = false;
  listeners = new Map<string, Set<(e: MessageEvent<string>) => void>>();
  constructor(url: string) {
    this.url = url;
    FakeEventSource.instances.push(this);
  }
  addEventListener(name: string, fn: (e: MessageEvent<string>) => void) {
    let s = this.listeners.get(name);
    if (s === undefined) {
      s = new Set();
      this.listeners.set(name, s);
    }
    s.add(fn);
  }
  removeEventListener(name: string, fn: (e: MessageEvent<string>) => void) {
    this.listeners.get(name)?.delete(fn);
  }
  close() {
    this.closed = true;
  }
  emit(name: string, data: string) {
    for (const fn of this.listeners.get(name) ?? []) fn(new MessageEvent(name, { data }));
  }
}

let assign: ReturnType<typeof vi.fn>;

beforeEach(() => {
  resetSessionForTests();
  FakeEventSource.instances = [];
  vi.stubGlobal('EventSource', FakeEventSource);
  assign = vi.fn();
  vi.stubGlobal('location', { ...window.location, assign, pathname: '/approvals', search: '?item=req_x' });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('httpTransport.invoke', () => {
  it('posts to /api/cmd/<name> with the CSRF header and the body unchanged', async () => {
    const calls = stubFetch([json(200, SESSION), json(200, [])]);
    await loadSession();
    await expect(httpTransport.invoke('queue_list', {})).resolves.toEqual([]);
    const req = calls[1];
    expect(req?.url).toBe('/api/cmd/queue_list');
    expect(req?.init?.method).toBe('POST');
    expect(req?.init?.credentials).toBe('same-origin');
    expect((req?.init?.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok-1');
    expect(req?.init?.body).toBe('{}');
  });

  it('redirects to /login with next on 401 and rejects internal', async () => {
    stubFetch([json(401, { error: { code: 'auth/no_session', message: 'm' } })]);
    await expect(httpTransport.invoke('queue_list', {})).rejects.toEqual({ kind: 'internal' });
    expect(assign).toHaveBeenCalledWith('/login?next=' + encodeURIComponent('/approvals?item=req_x'));
  });

  it('refetches the session and retries exactly once on csrf_mismatch', async () => {
    const mismatch = () => json(403, { error: { code: 'auth/csrf_mismatch', message: 'm' } });
    const calls = stubFetch([mismatch(), json(200, SESSION), mismatch()]);
    await expect(httpTransport.invoke('decide', { a: 1 })).rejects.toEqual({ kind: 'internal' });
    expect(calls.map((c) => c.url)).toEqual(['/api/cmd/decide', '/api/session', '/api/cmd/decide']);
    expect((calls[2]?.init?.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok-1');
  });

  it('succeeds after one csrf retry', async () => {
    stubFetch([
      json(403, { error: { code: 'auth/csrf_mismatch', message: 'm' } }),
      json(200, SESSION),
      json(200, { request_id: 'r', status: 'released' }),
    ]);
    await expect(httpTransport.invoke('decide', {})).resolves.toEqual({ request_id: 'r', status: 'released' });
  });

  it('passes a desktop CommandError body through', async () => {
    stubFetch([json(404, { kind: 'not_found' })]);
    await expect(httpTransport.invoke('queue_get', {})).rejects.toEqual({ kind: 'not_found' });
  });

  it('maps other failures to internal', async () => {
    stubFetch([json(500, { error: { code: 'internal', message: 'm' } })]);
    await expect(httpTransport.invoke('queue_list', {})).rejects.toEqual({ kind: 'internal' });
  });
});

describe('httpTransport.listen', () => {
  it('delivers an SSE queue_changed payload to the handler', async () => {
    const handler = vi.fn();
    const off = await httpTransport.listen('queue_changed', handler, {});
    const es = FakeEventSource.instances[0];
    expect(es?.url).toBe('/api/events');
    es?.emit('queue_changed', '{"request_ids":["req_1"]}');
    expect(handler).toHaveBeenCalledWith({ request_ids: ['req_1'] });
    off();
  });

  it('turns resync into a queue_changed so the queue refetches', async () => {
    const handler = vi.fn();
    const off = await httpTransport.listen('queue_changed', handler, {});
    FakeEventSource.instances[0]?.emit('resync', '');
    expect(handler).toHaveBeenCalledWith({});
    off();
  });

  it('shares one stream and closes it after the last listener', async () => {
    const a = await httpTransport.listen('queue_changed', vi.fn(), {});
    const b = await httpTransport.listen('attention', vi.fn(), { thisWindow: true });
    expect(FakeEventSource.instances).toHaveLength(1);
    const es = FakeEventSource.instances[0];
    a();
    expect(es?.closed).toBe(false);
    b();
    expect(es?.closed).toBe(true);
  });
});

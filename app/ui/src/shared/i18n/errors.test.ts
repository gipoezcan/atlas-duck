import { describe, expect, it } from 'vitest';
import { de, en } from './dict';
import {
  CMD_ERROR_KINDS,
  ENVELOPE_ERROR_CODES,
  cmdErrorText,
  envelopeErrorText,
  serverErrorText,
} from './errors';
import { createError } from '../../server/api_keys/ApiKeys';
import { SERVER_ERROR_CODES } from '../../server/http';

const DICTS = { en, de } as const;

describe('error texts', () => {
  it('every_envelope_code_has_text_in_both', () => {
    expect(ENVELOPE_ERROR_CODES).toHaveLength(30);
    for (const [name, t] of Object.entries(DICTS)) {
      for (const code of ENVELOPE_ERROR_CODES) {
        const text = envelopeErrorText(t, code);
        expect(text.length, `${name} ${code}`).toBeGreaterThan(0);
        expect(text, `${name} ${code}`).not.toBe(t.errors.generic(code));
      }
    }
  });

  it('every_cmd_kind_and_server_code_has_text_in_both', () => {
    for (const [name, t] of Object.entries(DICTS)) {
      for (const kind of CMD_ERROR_KINDS) {
        expect(cmdErrorText(t, kind).length, `${name} ${kind}`).toBeGreaterThan(0);
        expect(cmdErrorText(t, kind), `${name} ${kind}`).not.toBe(t.errors.generic(kind));
      }
      for (const code of SERVER_ERROR_CODES) {
        expect(serverErrorText(t, code, null), `${name} ${code}`).not.toBe(t.errors.generic(code));
      }
    }
  });

  it('german texts differ from english ones', () => {
    for (const code of ENVELOPE_ERROR_CODES) {
      expect(envelopeErrorText(de, code), code).not.toBe(envelopeErrorText(en, code));
    }
    for (const code of SERVER_ERROR_CODES) {
      expect(serverErrorText(de, code, null), code).not.toBe(serverErrorText(en, code, null));
    }
  });

  it('unknown_code_shows_generic_text_and_code', () => {
    expect(envelopeErrorText(de, 'zzz')).toContain('zzz');
    expect(envelopeErrorText(en, 'zzz')).toContain('zzz');
    expect(cmdErrorText(de, 'zzz')).toContain('zzz');
    expect(serverErrorText(de, 'api/zzz', null)).toContain('api/zzz');
    expect(serverErrorText(en, 'api/zzz', null)).toContain('api/zzz');
    // Object.prototype members are not codes.
    expect(envelopeErrorText(en, 'toString')).toContain('toString');
    expect(serverErrorText(en, '__proto__', null)).toContain('__proto__');
  });

  it('a missing server code gives the generic text without parentheses', () => {
    expect(serverErrorText(en, null, null)).toBe(en.errors.generic(''));
    expect(en.errors.generic('')).not.toContain('()');
    expect(de.errors.generic('')).not.toContain('()');
  });
});

describe('createError', () => {
  it('keeps the English texts of the API-keys page', () => {
    expect(createError('api_key/limit_reached')).toBe(
      'You already have the maximum of 25 active keys. Revoke one first.',
    );
    expect(createError('api_key/expiry_out_of_range')).toBe(
      'The expiry must be a whole number of days from 1 to 90.',
    );
    expect(createError(null)).toBe('The key could not be created. Try again.');
  });

  it('answers in German with a German dictionary', () => {
    expect(createError('api_key/limit_reached', de)).not.toBe(createError('api_key/limit_reached', en));
  });
});

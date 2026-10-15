import { EDIT_ENTRY_ATTR } from './keyboard';
import { EDIT_TEXT } from '../shared/strings';

/** The result of reading a raw-JSON field's text. Only a syntax hint: Rust validates the value again. */
export type JsonRead = { ok: true; value: unknown } | { ok: false };

export function readJson(text: string): JsonRead {
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

interface JsonFallbackProps {
  id: string;
  value: string;
  onChange: (text: string) => void;
  /** The text does not parse: the hint is shown and the field is marked invalid. */
  invalid: boolean;
  hintId: string;
}

/**
 * The raw-JSON entry (spec 5.4 step 4): an input whose kind is `json`, and the way to enter a Jira
 * value a `choice` cannot name. The text is parsed locally only to show a syntax hint; what is sent
 * is decided by `buildEdits` and checked again by Rust.
 */
export function JsonFallback({ id, value, onChange, invalid, hintId }: JsonFallbackProps) {
  return (
    <>
      <textarea
        id={id}
        {...{ [EDIT_ENTRY_ATTR]: '' }}
        className="json-input"
        spellCheck={false}
        value={value}
        aria-invalid={invalid}
        aria-describedby={hintId}
        onChange={(e) => onChange(e.target.value)}
      />
      <span id={hintId} className="field-hint" role={invalid ? 'alert' : undefined}>
        {invalid ? EDIT_TEXT.json_invalid : ''}
      </span>
    </>
  );
}

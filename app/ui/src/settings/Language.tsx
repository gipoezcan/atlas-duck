import { settingsApply } from '../shared/ipc/invoke';
import { HelpLink } from '../shared/HelpLink';
import type { UiLang } from '../shared/ipc/types';
import { useText } from '../shared/i18n/context';
import { LANG_PREFS, type LangPref } from '../shared/i18n';
import { useAction } from './useAction';

/**
 * The UI language (M15 T3, PD-294): Automatic (the OS locale), Deutsch or English. Stored by Rust
 * outside the audit store; every window switches on `lang_changed`, this one also re-reads
 * `settings_get` on `settings_changed`.
 */
export function Language({ uiLang, onChanged }: { uiLang: UiLang; onChanged: () => void }) {
  const t = useText();
  const action = useAction();
  const label: Record<LangPref, string> = {
    auto: t.common.lang_auto,
    en: t.common.lang_en,
    de: t.common.lang_de,
  };
  const set = (value: LangPref) => {
    void action.run(() => settingsApply([{ key: 'ui_lang', value }])).then((v) => {
      if (v !== undefined) onChanged();
    });
  };
  return (
    <section aria-label={t.common.language}>
      <h2>{t.common.language}</h2>
      <HelpLink section="settings/language" label={t.common.language} />
      <div className="field">
        <label>
          {t.common.language}{' '}
          <select
            value={uiLang.pref}
            disabled={action.pending}
            onChange={(e) => {
              const value = LANG_PREFS.find((p) => p === e.target.value);
              if (value !== undefined) set(value);
            }}
          >
            {LANG_PREFS.map((p) => (
              <option key={p} value={p}>
                {label[p]}
              </option>
            ))}
          </select>
        </label>
      </div>
      {action.error === null ? null : <p role="alert">{action.error}</p>}
    </section>
  );
}

//! The UI language of the desktop app (M15, PD-291, PD-292): the two languages, the user's
//! preference and the OS locale `auto` follows. The same rule as the UI's `resolveLang`
//! (`app/ui/src/shared/i18n/index.ts`).
//!
//! M15 T10 (PD-292): the Rust-rendered user text (tray, native dialogs, toasts, status lines) is
//! a [`T`] pair per text, read with [`tr`] in the language of the moment. Every pair is built with
//! [`T::new`] and listed in [`ALL`]; the tests check both. Texts with values are functions of the
//! language next to their callers. German follows `app/ui/src/shared/i18n/GLOSSARY.md` ("Sie").

use serde::{Deserialize, Serialize};

/// One user-visible text in both languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T {
    pub en: &'static str,
    pub de: &'static str,
}

impl T {
    pub const fn new(en: &'static str, de: &'static str) -> T {
        T { en, de }
    }

    /// The text in `lang`.
    pub const fn get(&self, lang: Lang) -> &'static str {
        match lang {
            Lang::En => self.en,
            Lang::De => self.de,
        }
    }
}

/// [`T::get`] as a function.
pub fn tr(lang: Lang, t: &T) -> &'static str {
    t.get(lang)
}

/// Every [`T`] of the app, module by module (each module lists its own in `TEXTS`).
pub fn all() -> impl Iterator<Item = &'static T> {
    [
        crate::tray::TEXTS,
        crate::status::TEXTS,
        crate::startup::TEXTS,
        crate::wizard::TEXTS,
        crate::windows::TEXTS,
        crate::recovery_tier::TEXTS,
        crate::restore_flow::TEXTS,
        crate::commands::audit::TEXTS,
        crate::commands::credential::TEXTS,
        crate::commands::settings::TEXTS,
        crate::os_hooks::windows::TEXTS,
        crate::serve::TEXTS,
    ]
    .into_iter()
    .flatten()
    .copied()
}

/// The placeholders a [`T`] may carry; [`localize`] fills them from the English text.
const PLACEHOLDERS: [&str; 4] = ["<path>", "<host>", "<n>", "<reason>"];

/// `text` in `lang` when it is the English of one of [`all`] (`None` otherwise).
pub fn localize_static(lang: Lang, text: &str) -> Option<&'static str> {
    all().find(|t| t.en == text).map(|t| t.get(lang))
}

/// An English text this app rendered (a [`T`], or a [`T`] with one placeholder filled) in
/// `lang`: the placeholder's value is taken from `text` and put into the other language's form.
/// Any other text comes back unchanged (it is not ours, or it is already in `lang`).
pub fn localize(lang: Lang, text: &str) -> String {
    if lang == Lang::En {
        return text.to_owned();
    }
    if let Some(s) = localize_static(lang, text) {
        return s.to_owned();
    }
    for t in all() {
        for ph in PLACEHOLDERS {
            let Some((pre, post)) = t.en.split_once(ph) else {
                continue;
            };
            if text.len() > pre.len() + post.len()
                && text.starts_with(pre)
                && text.ends_with(post)
                && !post.contains(ph)
            {
                let value = &text[pre.len()..text.len() - post.len()];
                return t.get(lang).replacen(ph, value, 1);
            }
        }
    }
    text.to_owned()
}
/// A count as the UI writes it: English digits as they are (the texts the spec fixes), German with
/// a `.` every three digits (`12.345`), as the UI's `formatNumber('de', n)`.
pub fn count(lang: Lang, n: u64) -> String {
    let digits = n.to_string();
    if lang == Lang::En || digits.len() <= 3 {
        return digits;
    }
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push('.');
        }
        out.push(c);
    }
    out
}
/// Picks the English or German form of a text with values.
pub fn pick<S>(lang: Lang, en: S, de: S) -> S {
    match lang {
        Lang::En => en,
        Lang::De => de,
    }
}

/// A UI language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lang {
    #[default]
    En,
    De,
}

/// The user's choice in Settings: `auto` follows the OS locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LangPref {
    #[default]
    Auto,
    En,
    De,
}

impl LangPref {
    /// The word on the wire and in the `ui-lang` file.
    pub fn as_str(self) -> &'static str {
        match self {
            LangPref::Auto => "auto",
            LangPref::En => "en",
            LangPref::De => "de",
        }
    }

    /// The inverse of [`LangPref::as_str`]; anything else is `None`.
    pub fn parse(word: &str) -> Option<LangPref> {
        match word {
            "auto" => Some(LangPref::Auto),
            "en" => Some(LangPref::En),
            "de" => Some(LangPref::De),
            _ => None,
        }
    }
}

/// PD-291: `auto` is German iff the primary subtag of `locale` is `de` (BCP 47 `de-AT`,
/// `de-DE-u-co-phonebk`, POSIX `de_DE.UTF-8`, `de_CH@euro`; any case), else English.
pub fn resolve(pref: LangPref, locale: Option<&str>) -> Lang {
    match pref {
        LangPref::En => Lang::En,
        LangPref::De => Lang::De,
        LangPref::Auto => {
            let primary = locale
                .unwrap_or("")
                .trim()
                .split(['-', '_', '.', '@'])
                .next()
                .unwrap_or("");
            if primary.eq_ignore_ascii_case("de") {
                Lang::De
            } else {
                Lang::En
            }
        }
    }
}

/// The user's OS locale tag: `LC_ALL`, `LC_MESSAGES`, `LANG` (the first non-empty) on Linux and
/// the BSDs, the user's display language on Windows (`GetUserDefaultUILanguage`, named by
/// `LCIDToLocaleName`: an English Windows with German regional formats is English), the first
/// preferred language on macOS. `None` when the OS names none.
pub fn os_locale() -> Option<String> {
    os_locale_impl().filter(|tag| !tag.trim().is_empty())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn os_locale_impl() -> Option<String> {
    posix_locale(&|name| std::env::var(name).ok())
}

#[cfg(target_os = "macos")]
fn os_locale_impl() -> Option<String> {
    crate::os_hooks::macos::preferred_language()
}

#[cfg(windows)]
fn os_locale_impl() -> Option<String> {
    use windows_sys::Win32::Globalization::{GetUserDefaultUILanguage, LCIDToLocaleName};
    // SAFETY: no arguments; answers the user's UI language id.
    let langid = unsafe { GetUserDefaultUILanguage() };
    // MAKELCID(langid, SORT_DEFAULT): the sort id is 0.
    let lcid = u32::from(langid);
    // LOCALE_NAME_MAX_LENGTH, with the NUL.
    let mut buf = [0u16; 85];
    // SAFETY: `buf` is writable for its length, which is what the call is told; no flags.
    let len = unsafe { LCIDToLocaleName(lcid, buf.as_mut_ptr(), buf.len() as i32, 0) };
    // The answer counts the NUL; 0 is a failure.
    let chars = usize::try_from(len).ok()?.checked_sub(1)?;
    String::from_utf16(buf.get(..chars)?).ok()
}

/// The POSIX order of the locale variables: the first set and non-empty one wins.
#[cfg_attr(not(all(unix, not(target_os = "macos"))), allow(dead_code))]
fn posix_locale(var: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .filter_map(var)
        .find(|v| !v.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table of the UI's `resolve_accepts_posix_and_bcp47_tags` (T1), and the explicit choices.
    /// T10: every text has both languages; German differs from English unless the text is a
    /// product name or a code (none so far).
    #[test]
    fn every_entry_has_both_languages() {
        const SAME: &[&str] = &[];
        let mut n = 0;
        for t in all() {
            n += 1;
            assert!(!t.en.trim().is_empty() && !t.de.trim().is_empty(), "{t:?}");
            if !SAME.contains(&t.en) {
                assert_ne!(t.en, t.de, "de_differs_from_en_unless_allowlisted");
            }
            for ph in PLACEHOLDERS {
                assert_eq!(
                    t.en.matches(ph).count(),
                    t.de.matches(ph).count(),
                    "{ph} in {t:?}"
                );
            }
        }
        assert!(n > 0);
    }

    /// Every `T::new(` in the sources is listed in some module's `TEXTS` (so [`all`] sees it).
    #[test]
    fn every_text_is_listed() {
        fn walk(dir: &std::path::Path, out: &mut usize) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs")
                    && p.file_name().is_some_and(|f| f != "i18n.rs")
                {
                    let src = std::fs::read_to_string(&p).unwrap_or_default();
                    *out += src.matches("T::new(").count();
                }
            }
        }
        let mut written = 0;
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut written,
        );
        assert_eq!(
            all().count(),
            written,
            "a T::new( is missing from its module's TEXTS"
        );
    }

    #[test]
    fn localize_maps_our_english_texts_and_leaves_others() {
        use crate::startup::MSG_DATA_DIR_NOT_LOCAL;
        let en = MSG_DATA_DIR_NOT_LOCAL.en.replace("<path>", "/mnt/x");
        assert_eq!(
            localize(Lang::De, &en),
            "Datenverzeichnis /mnt/x liegt nicht auf einem lokalen Dateisystem"
        );
        assert_eq!(localize(Lang::En, &en), en);
        assert_eq!(localize(Lang::De, "not ours"), "not ours");
        assert_eq!(
            localize_static(Lang::De, crate::wizard::MSG_PIN_WRITE_FAILED),
            Some(crate::wizard::TEXT_PIN_WRITE_FAILED.de)
        );
    }

    /// T10: the native confirmations in German, with values and plurals in place.
    #[test]
    fn dialog_texts_de() {
        let set = crate::recovery_tier::anchor_dir_set_text(Lang::De, "D:\\anker", None, "c.jsonl");
        assert!(set.starts_with("D:\\anker als Anker-Verzeichnis"), "{set}");
        assert!(set.contains("c.jsonl"));
        assert!(
            crate::restore_flow::rollback_text(Lang::De, 1).contains("die letzten 1 Datensatz des")
        );
        assert!(
            crate::restore_flow::rollback_text(Lang::De, 1234)
                .contains("die letzten 1.234 Datensätze")
        );
        assert!(
            crate::removal::begin_text(Lang::De, &[])
                .starts_with("atlas-duck für die Deinstallation vorbereiten?")
        );
        assert!(crate::removal::finish_text(Lang::De).starts_with("Deinstallation abschließen?"));
        assert_eq!(
            crate::commands::audit::acknowledge_text(Lang::De, 7, "broken", "2026-10-29"),
            "Integritätsvorfall 7 (broken, erkannt 2026-10-29) zur Kenntnis nehmen? Das rote \
             Banner verschwindet für diesen Vorfall."
        );
        let keys: Vec<String> = (0..21).map(|i| format!("k{i}")).collect();
        assert!(
            crate::recovery_tier::forget_keys_text(Lang::De, "id", &keys)
                .contains(" und 1 weitere")
        );
        // English is what it was.
        assert!(crate::removal::finish_text(Lang::En).starts_with("Finish removal?"));
    }
    #[test]
    fn counts_group_in_german_only() {
        assert_eq!(count(Lang::En, 1_234_567), "1234567");
        assert_eq!(count(Lang::De, 1_234_567), "1.234.567");
        assert_eq!(count(Lang::De, 999), "999");
        assert_eq!(count(Lang::De, 1000), "1.000");
    }
    #[test]
    fn resolve_matches_ts_rule() {
        for tag in [
            "de_DE.UTF-8",
            "de-AT",
            "DE",
            "de-DE-u-co-phonebk",
            "de",
            "de_CH@euro",
        ] {
            assert_eq!(resolve(LangPref::Auto, Some(tag)), Lang::De, "{tag}");
        }
        for tag in ["en-US", "fr", "", "  ", "deu", "C", "POSIX"] {
            assert_eq!(resolve(LangPref::Auto, Some(tag)), Lang::En, "{tag}");
        }
        assert_eq!(resolve(LangPref::Auto, None), Lang::En);
        assert_eq!(resolve(LangPref::En, Some("de")), Lang::En);
        assert_eq!(resolve(LangPref::De, Some("en-US")), Lang::De);
        assert_eq!(resolve(LangPref::De, None), Lang::De);
    }

    #[test]
    fn posix_locale_takes_the_first_non_empty_variable() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        let all = env(&[("LC_ALL", "de_DE.UTF-8"), ("LANG", "en_US.UTF-8")]);
        assert_eq!(posix_locale(&all).as_deref(), Some("de_DE.UTF-8"));
        let messages = env(&[("LC_ALL", ""), ("LC_MESSAGES", "de_AT"), ("LANG", "en_US")]);
        assert_eq!(posix_locale(&messages).as_deref(), Some("de_AT"));
        let lang = env(&[("LANG", "en_GB.UTF-8")]);
        assert_eq!(posix_locale(&lang).as_deref(), Some("en_GB.UTF-8"));
        assert_eq!(posix_locale(&env(&[])), None);
        // Review m-4: the C locale wins over LANG and reads as English, through read and resolve.
        for c in ["C", "POSIX", "C.UTF-8"] {
            let pairs: &'static [(&'static str, &'static str)] = match c {
                "C" => &[("LC_ALL", "C"), ("LANG", "de_DE.UTF-8")],
                "POSIX" => &[("LC_MESSAGES", "POSIX"), ("LANG", "de_DE.UTF-8")],
                _ => &[("LANG", "C.UTF-8")],
            };
            let tag = posix_locale(&env(pairs));
            assert_eq!(tag.as_deref(), Some(c));
            assert_eq!(resolve(LangPref::Auto, tag.as_deref()), Lang::En, "{c}");
        }
        let de = posix_locale(&env(&[("LC_ALL", ""), ("LANG", "de_AT.UTF-8")]));
        assert_eq!(resolve(LangPref::Auto, de.as_deref()), Lang::De);
    }

    #[test]
    fn pref_words_roundtrip_and_serde_is_snake_case() {
        for p in [LangPref::Auto, LangPref::En, LangPref::De] {
            assert_eq!(LangPref::parse(p.as_str()), Some(p));
            assert_eq!(
                serde_json::to_value(p).ok(),
                Some(serde_json::Value::String(p.as_str().into()))
            );
        }
        assert_eq!(LangPref::parse("DE"), None);
        assert_eq!(LangPref::parse(""), None);
        assert_eq!(serde_json::to_value(Lang::De).ok(), Some("de".into()));
    }
}

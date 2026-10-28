//! The UI language of the desktop app (M15, PD-291, PD-292): the two languages, the user's
//! preference and the OS locale `auto` follows. The same rule as the UI's `resolveLang`
//! (`app/ui/src/shared/i18n/index.ts`). The text table of the Rust-rendered texts is T10's.

use serde::{Deserialize, Serialize};

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

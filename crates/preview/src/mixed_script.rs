//! §6.4 mixed-script detection (UTS #39 §5.1 "single script"), applied only to issue keys,
//! space keys, usernames and URL hosts. Callers never pass prose, titles or bodies.

use icu_properties::props::Script;
use icu_properties::script::ScriptWithExtensions;

/// True iff the augmented resolved script sets of `ident`'s characters have an empty
/// intersection. Each character's set is its Script_Extensions, where Common and Inherited mean
/// "all scripts", augmented per UTS #39 (Hani → Hanb, Jpan, Kore; Hira, Kana → Jpan;
/// Hang → Kore; Bopo → Hanb). Unassigned characters (Unknown) resolve to {Unknown}.
pub fn is_mixed_script(ident: &str) -> bool {
    let swe = ScriptWithExtensions::new();
    // `None` is the set of all scripts.
    let mut common: Option<Vec<Script>> = None;
    for c in ident.chars() {
        let scx = swe.get_script_extensions_val(c);
        if scx.contains(&Script::Common) || scx.contains(&Script::Inherited) {
            continue;
        }
        let set = augment(scx.iter());
        common = Some(match common {
            None => set,
            Some(prev) => prev.into_iter().filter(|s| set.contains(s)).collect(),
        });
        if common.as_ref().is_some_and(Vec::is_empty) {
            return true;
        }
    }
    false
}

fn augment(scripts: impl Iterator<Item = Script>) -> Vec<Script> {
    let mut out = Vec::new();
    let mut add = |s: Script| {
        if !out.contains(&s) {
            out.push(s);
        }
    };
    for s in scripts {
        add(s);
        match s {
            Script::Han => {
                add(Script::HanWithBopomofo);
                add(Script::Japanese);
                add(Script::Korean);
            }
            Script::Hiragana | Script::Katakana => add(Script::Japanese),
            Script::Hangul => add(Script::Korean),
            Script::Bopomofo => add(Script::HanWithBopomofo),
            _ => {}
        }
    }
    out
}

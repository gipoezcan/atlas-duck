//! `help_open` (M16, PD-328): opens the Help window at a page of the bundled user guide.
//!
//! Granted to the windows that carry a "Help" link (not `help` itself, which holds no app
//! permission, and not `credential`, which keeps its secrets-only surface). The page and the
//! anchor are checked against the bundled desktop manifest (the same file the guide's pages are
//! generated with), so the window can only be pointed at a page that exists; the language is the
//! resolved UI language, never an argument.

use std::sync::LazyLock;

use serde::{Deserialize, Deserializer};
use serde_json::Value;
use tauri::{AppHandle, Runtime};

use super::dto::{Args, refuse};
use super::{CommandError, blocking, finish};
use crate::i18n::Lang;
use crate::windows;

/// The desktop guide's manifest. The two languages carry the same pages and anchors.
const MANIFEST_EN: &str = include_str!("../../../ui/public/help/en/manifest.json");
#[cfg(test)]
const MANIFEST_DE: &str = include_str!("../../../ui/public/help/de/manifest.json");

/// [`MANIFEST_EN`], parsed once.
static EN: LazyLock<Value> =
    LazyLock::new(|| serde_json::from_str(MANIFEST_EN).unwrap_or(Value::Null));

/// `page`: a page id of the bundled manifest; anything else is refused with `field: "page"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpPage(String);

impl<'de> Deserialize<'de> for HelpPage {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d).map_err(|_| refuse::<D::Error>("page"))?;
        validate_in(&EN, &s, None).map_err(refuse::<D::Error>)?;
        Ok(HelpPage(s))
    }
}

/// `anchor`: the shape of an anchor (`[a-z0-9-]`, at most [`ANCHOR_MAX`]); that the page has it is
/// checked by [`HelpOpenArgs::check_anchor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpAnchor(String);

/// The longest anchor accepted.
const ANCHOR_MAX: usize = 64;

impl<'de> Deserialize<'de> for HelpAnchor {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d).map_err(|_| refuse::<D::Error>("anchor"))?;
        let shaped = !s.is_empty()
            && s.len() <= ANCHOR_MAX
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if shaped {
            Ok(HelpAnchor(s))
        } else {
            Err(refuse("anchor"))
        }
    }
}

/// `help_open {page, anchor?}`: `page` is a page id of the manifest, `anchor` one of its anchors.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelpOpenArgs {
    pub page: HelpPage,
    pub anchor: Option<HelpAnchor>,
}

impl HelpOpenArgs {
    /// Refuses an anchor the page does not have (`field: "anchor"`).
    pub fn check_anchor(&self) -> Result<(), CommandError> {
        let anchor = self.anchor.as_ref().map(|a| a.0.as_str());
        validate_in(&EN, &self.page.0, anchor)
            .map_err(|field| CommandError::InvalidArgument { field })
    }

    /// The asset path for `lang` (see [`help_url`]).
    pub fn url(&self, lang: Lang) -> String {
        help_url(
            lang,
            &self.page.0,
            self.anchor.as_ref().map(|a| a.0.as_str()),
        )
    }
}
/// The asset path of the guide page in `lang`: `help/<lang>/<page>.html[#<anchor>]`.
pub fn help_url(lang: Lang, page: &str, anchor: Option<&str>) -> String {
    let lang = windows::ui_lang_dir(lang);
    match anchor {
        Some(a) => format!("help/{lang}/{page}.html#{a}"),
        None => format!("help/{lang}/{page}.html"),
    }
}

/// The field a page or anchor the manifest does not list is refused with.
fn validate_in(doc: &Value, page: &str, anchor: Option<&str>) -> Result<(), &'static str> {
    let entry = doc
        .get("pages")
        .and_then(Value::as_array)
        .and_then(|pages| {
            pages
                .iter()
                .find(|p| p.get("id").and_then(Value::as_str) == Some(page))
        })
        .ok_or("page")?;
    if let Some(anchor) = anchor {
        let known = entry
            .get("anchors")
            .and_then(Value::as_array)
            .is_some_and(|all| all.iter().any(|a| a.as_str() == Some(anchor)));
        if !known {
            return Err("anchor");
        }
    }
    Ok(())
}
/// `help_open {page, anchor?}`: builds the Help window once, then navigates it and brings it up.
/// The build waits for the main thread, so it runs on the blocking pool.
#[tauri::command]
pub async fn help_open<R: Runtime>(
    app: AppHandle<R>,
    args: Args<HelpOpenArgs>,
) -> Result<(), CommandError> {
    let Args(args) = args;
    let handle = app.clone();
    let opened = blocking(move || {
        args.check_anchor()?;
        let path = args.url(windows::ui_lang(&handle));
        windows::open_help(&handle, &path).map_err(|_| CommandError::Internal)
    })
    .await;
    finish(&app, opened)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::commands::dto::{FIELD_PAYLOAD, parse};
    use crate::i18n::{LangPref, resolve};

    fn args(page: &str, anchor: Option<&str>) -> HelpOpenArgs {
        HelpOpenArgs {
            page: HelpPage(page.into()),
            anchor: anchor.map(|a| HelpAnchor(a.into())),
        }
    }

    #[test]
    fn help_url_uses_resolved_lang() {
        let de = resolve(LangPref::Auto, Some("de-DE"));
        assert_eq!(
            help_url(de, "approvals", Some("queue")),
            "help/de/approvals.html#queue"
        );
        let en = resolve(LangPref::Auto, Some("en-US"));
        assert_eq!(help_url(en, "index", None), "help/en/index.html");
        // An explicit choice beats the OS locale.
        let forced = resolve(LangPref::En, Some("de-DE"));
        assert_eq!(help_url(forced, "scripts", None), "help/en/scripts.html");
    }

    #[test]
    fn help_open_rejects_unknown_page_or_anchor() {
        let open =
            |body: Value| parse::<HelpOpenArgs>(&body).and_then(|a| a.check_anchor().map(|()| a));
        assert_eq!(
            open(json!({"page": "approvals", "anchor": "queue"})),
            Ok(args("approvals", Some("queue")))
        );
        let page = Err(CommandError::InvalidArgument { field: "page" });
        for bad in [
            "nope",
            "",
            "../approvals",
            "approvals.html",
            "Approvals",
            "index#x",
            // The server guide's pages are not the desktop's.
            "admin",
        ] {
            assert_eq!(parse::<HelpOpenArgs>(&json!({"page": bad})), page, "{bad}");
        }
        let huge = "x".repeat(1 << 20);
        assert_eq!(parse::<HelpOpenArgs>(&json!({ "page": huge })), page);
        let anchor = Err(CommandError::InvalidArgument { field: "anchor" });
        // Unknown anchors, and one that belongs to another page, are refused.
        for bad in ["nope", "", "queue\"><script>", "what-is-atlas-duck", &huge] {
            assert_eq!(
                open(json!({"page": "approvals", "anchor": bad})),
                anchor,
                "{bad}"
            );
        }
    }
    #[test]
    fn every_manifest_anchor_validates() -> Result<(), CommandError> {
        let doc: Value = serde_json::from_str(MANIFEST_EN).map_err(|_| CommandError::Internal)?;
        let pages = doc["pages"].as_array().ok_or(CommandError::Internal)?;
        assert!(!pages.is_empty());
        for p in pages {
            let id = p["id"].as_str().ok_or(CommandError::Internal)?;
            for a in p["anchors"].as_array().ok_or(CommandError::Internal)? {
                let a = a.as_str().ok_or(CommandError::Internal)?;
                validate_in(&EN, id, Some(a))
                    .map_err(|field| CommandError::InvalidArgument { field })?;
            }
        }
        Ok(())
    }

    /// The window validates against `en` only; the two languages must list the same pages and
    /// anchors, or a `de` page would open at the wrong place.
    #[test]
    fn de_manifest_matches_en() -> Result<(), CommandError> {
        let de: Value = serde_json::from_str(MANIFEST_DE).map_err(|_| CommandError::Internal)?;
        let shape = |doc: &Value| -> Vec<(String, Vec<String>)> {
            let strings = |v: &Value| -> Vec<String> {
                v.as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            doc["pages"]
                .as_array()
                .map(|pages| {
                    pages
                        .iter()
                        .map(|p| {
                            (
                                p["id"].as_str().unwrap_or_default().to_owned(),
                                strings(&p["anchors"]),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        assert!(!shape(&EN).is_empty());
        assert_eq!(shape(&EN), shape(&de));
        Ok(())
    }

    #[test]
    fn help_open_takes_a_page_and_an_optional_anchor() {
        assert_eq!(
            parse::<HelpOpenArgs>(&json!({"page": "index"})),
            Ok(args("index", None))
        );
        assert_eq!(
            parse::<HelpOpenArgs>(&json!({"page": "approvals", "anchor": "queue"})),
            Ok(args("approvals", Some("queue")))
        );
        let payload = Err(CommandError::InvalidArgument {
            field: FIELD_PAYLOAD,
        });
        for bad in [json!({"page": "index", "lang": "de"}), json!(["index"])] {
            assert_eq!(parse::<HelpOpenArgs>(&bad), payload, "{bad}");
        }
        // A missing or mistyped page, or anchor, names its own field.
        let page = Err(CommandError::InvalidArgument { field: "page" });
        for bad in [json!({}), json!({"page": 1}), json!({"page": null})] {
            assert_eq!(parse::<HelpOpenArgs>(&bad), page, "{bad}");
        }
        let anchor = Err(CommandError::InvalidArgument { field: "anchor" });
        assert_eq!(
            parse::<HelpOpenArgs>(&json!({"page": "index", "anchor": 1})),
            anchor
        );
    }
}

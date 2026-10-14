//! The isolation origin in the main-window CSP (§6.4, §15 V34; M6 T4).
//!
//! Tauri 2.12.1 serves the isolation iframe from `isolation-<uuid>://localhost` (macOS, Linux) or
//! `http://isolation-<uuid>.localhost` (Windows), with a uuid `tauri-codegen` mints on every build
//! (`AssetOptions::isolation_schema`), and patches that origin into `default-src` only. The §6.4
//! policy sets `frame-src` explicitly, so `tauri.conf.json` carries the literal
//! [`ISOLATION_ORIGIN_PLACEHOLDER`] there and [`patch_context`] replaces it with this build's
//! origin before the app is built. An HTML page with its own meta CSP (the credential page,
//! §10.3, whose `frame-src` must name the origin too) carries the same placeholder, and
//! [`OriginAssets`] replaces it whenever the page is served. Unpatched, the placeholder is not a
//! valid CSP source and the iframe stays blocked: every invoke fails, nothing opens up.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::borrow::Cow;

use tauri::utils::assets::{AssetKey, AssetsIter, CspHash};
use tauri::utils::config::Csp;
use tauri::{App, Assets, Context, Pattern, Runtime};

/// The `frame-src` source `tauri.conf.json` carries in place of the isolation origin (§6.4
/// notation; `ci/check-csp.mjs` checks the policy text around it).
pub const ISOLATION_ORIGIN_PLACEHOLDER: &str = "<isolation-origin>";

/// [`ISOLATION_ORIGIN_PLACEHOLDER`] as an HTML attribute value may spell it.
const PLACEHOLDER_ESCAPED: &str = "&lt;isolation-origin&gt;";

/// Why the CSP could not be completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CspError {
    /// The context does not use the isolation pattern.
    NotIsolation,
    /// `app.security.csp` is not set.
    NoPolicy,
    /// The policy does not name the placeholder exactly once.
    Placeholder,
}

/// The isolation iframe's origin for `schema`, as Tauri's `protocol::origin` forms it with
/// `use_https_scheme` off (the app never sets it, `ci/check-csp.mjs`).
pub fn origin_for(schema: &str, windows: bool) -> String {
    if windows {
        format!("http://{schema}.localhost")
    } else {
        format!("{schema}://localhost")
    }
}

/// This build's isolation origin, on this platform.
pub fn isolation_origin(pattern: &Pattern) -> Option<String> {
    match pattern {
        Pattern::Isolation { schema, .. } => Some(origin_for(schema, cfg!(windows))),
        Pattern::Brownfield => None,
    }
}

/// `policy` with its one placeholder replaced by `origin`.
pub fn substitute(policy: &str, origin: &str) -> Result<String, CspError> {
    if policy.matches(ISOLATION_ORIGIN_PLACEHOLDER).count() != 1 {
        return Err(CspError::Placeholder);
    }
    Ok(policy.replace(ISOLATION_ORIGIN_PLACEHOLDER, origin))
}

/// Puts this build's isolation origin into `app.security.csp` (and `devCsp`, if one is ever set)
/// and serves the frontend through [`OriginAssets`].
pub fn patch_context<R: Runtime>(context: &mut Context<R>) -> Result<(), CspError> {
    let origin = isolation_origin(context.pattern()).ok_or(CspError::NotIsolation)?;
    let security = &mut context.config_mut().app.security;
    for csp in [&mut security.csp, &mut security.dev_csp] {
        match csp {
            Some(Csp::Policy(policy)) => *policy = substitute(policy, &origin)?,
            Some(Csp::DirectiveMap(_)) => return Err(CspError::Placeholder),
            None => {}
        }
    }
    if security.csp.is_none() {
        return Err(CspError::NoPolicy);
    }
    let inner = context.set_assets(Box::new(NoAssets));
    context.set_assets(Box::new(OriginAssets { inner, origin }));
    Ok(())
}

/// The embedded frontend with this build's isolation origin in every HTML page that carries the
/// placeholder (in its meta CSP; no other HTML names it). Everything else passes unchanged.
pub struct OriginAssets<R: Runtime> {
    inner: Box<dyn Assets<R>>,
    origin: String,
}

impl<R: Runtime> OriginAssets<R> {
    pub fn new(inner: Box<dyn Assets<R>>, origin: String) -> Self {
        Self { inner, origin }
    }
}

impl<R: Runtime> Assets<R> for OriginAssets<R> {
    fn setup(&self, app: &App<R>) {
        self.inner.setup(app);
    }

    fn get(&self, key: &AssetKey) -> Option<Cow<'_, [u8]>> {
        let bytes = self.inner.get(key)?;
        if !key.as_ref().ends_with(".html") {
            return Some(bytes);
        }
        match std::str::from_utf8(&bytes) {
            Ok(text)
                if text.contains(ISOLATION_ORIGIN_PLACEHOLDER)
                    || text.contains(PLACEHOLDER_ESCAPED) =>
            {
                let text = text
                    .replace(ISOLATION_ORIGIN_PLACEHOLDER, &self.origin)
                    .replace(PLACEHOLDER_ESCAPED, &self.origin);
                Some(Cow::Owned(text.into_bytes()))
            }
            _ => Some(bytes),
        }
    }

    fn iter(&self) -> Box<AssetsIter<'_>> {
        self.inner.iter()
    }

    fn csp_hashes(&self, html_path: &AssetKey) -> Box<dyn Iterator<Item = CspHash<'_>> + '_> {
        self.inner.csp_hashes(html_path)
    }
}

/// Holds the context's asset slot while [`patch_context`] wraps the real assets.
struct NoAssets;

impl<R: Runtime> Assets<R> for NoAssets {
    fn get(&self, _key: &AssetKey) -> Option<Cow<'_, [u8]>> {
        None
    }

    fn iter(&self) -> Box<AssetsIter<'_>> {
        Box::new(std::iter::empty())
    }

    fn csp_hashes(&self, _html_path: &AssetKey) -> Box<dyn Iterator<Item = CspHash<'_>> + '_> {
        Box::new(std::iter::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN: &str = "default-src 'self'; frame-src 'self' <isolation-origin>; object-src 'none'";

    #[test]
    fn origin_per_platform() {
        let schema = "isolation-0b9e1d2c-3f4a-4b5c-8d6e-7f8091a2b3c4";
        assert_eq!(
            origin_for(schema, false),
            "isolation-0b9e1d2c-3f4a-4b5c-8d6e-7f8091a2b3c4://localhost"
        );
        assert_eq!(
            origin_for(schema, true),
            "http://isolation-0b9e1d2c-3f4a-4b5c-8d6e-7f8091a2b3c4.localhost"
        );
    }

    #[test]
    fn substitute_needs_exactly_one_placeholder() {
        assert_eq!(
            substitute(MAIN, "isolation-x://localhost"),
            Ok(
                "default-src 'self'; frame-src 'self' isolation-x://localhost; object-src 'none'"
                    .into()
            )
        );
        assert_eq!(
            substitute("frame-src 'self'", "o"),
            Err(CspError::Placeholder)
        );
        let twice = format!("{MAIN}; child-src {ISOLATION_ORIGIN_PLACEHOLDER}");
        assert_eq!(substitute(&twice, "o"), Err(CspError::Placeholder));
    }

    struct MapAssets(Vec<(&'static str, &'static str)>);

    impl Assets<tauri::test::MockRuntime> for MapAssets {
        fn get(&self, key: &AssetKey) -> Option<Cow<'_, [u8]>> {
            self.0
                .iter()
                .find(|(k, _)| AssetKey::from(*k) == *key)
                .map(|(_, v)| Cow::Borrowed(v.as_bytes()))
        }

        fn iter(&self) -> Box<AssetsIter<'_>> {
            Box::new(std::iter::empty())
        }

        fn csp_hashes(&self, _: &AssetKey) -> Box<dyn Iterator<Item = CspHash<'_>> + '_> {
            Box::new(std::iter::empty())
        }
    }

    #[test]
    fn html_pages_get_the_origin_and_nothing_else_changes() {
        let page =
            r#"<meta http-equiv="Content-Security-Policy" content="frame-src <isolation-origin>">"#;
        let escaped = r#"<meta http-equiv="Content-Security-Policy" content="frame-src &lt;isolation-origin&gt;">"#;
        let script = "const s = '<isolation-origin>';";
        let assets = OriginAssets::new(
            Box::new(MapAssets(vec![
                ("credential.html", page),
                ("credential-windows.html", escaped),
                ("index.html", "<p>no policy</p>"),
                ("assets/app.js", script),
            ])),
            "isolation-x://localhost".into(),
        );
        let get = |k: &str| {
            Assets::<tauri::test::MockRuntime>::get(&assets, &k.into())
                .map(|b| String::from_utf8_lossy(&b).into_owned())
        };
        let patched = r#"<meta http-equiv="Content-Security-Policy" content="frame-src isolation-x://localhost">"#;
        assert_eq!(get("credential.html").as_deref(), Some(patched));
        assert_eq!(get("/credential-windows.html").as_deref(), Some(patched));
        assert_eq!(get("index.html").as_deref(), Some("<p>no policy</p>"));
        assert_eq!(get("assets/app.js").as_deref(), Some(script));
        assert_eq!(get("missing.html"), None);
    }

    /// The shipped config with this build's generated context: the policy names the isolation
    /// origin Tauri serves the iframe from (`isolation-<uuid>`), and no placeholder survives.
    #[test]
    fn shipped_policy_gets_this_builds_isolation_origin() {
        let mut context: Context<tauri::test::MockRuntime> =
            tauri::generate_context!(assets = tauri::test::noop_assets(), test = true);
        let Pattern::Isolation { schema, .. } = context.pattern() else {
            panic!("tauri.conf.json must use the isolation pattern");
        };
        let schema = schema.clone();
        assert!(schema.starts_with("isolation-"), "{schema}");
        assert_eq!(patch_context(&mut context), Ok(()));
        let Some(Csp::Policy(policy)) = &context.config().app.security.csp else {
            panic!("the CSP is a policy string");
        };
        assert!(!policy.contains(ISOLATION_ORIGIN_PLACEHOLDER), "{policy}");
        let frame_src = policy
            .split(';')
            .map(str::trim)
            .find(|d| d.starts_with("frame-src "))
            .unwrap_or_default();
        assert_eq!(
            frame_src,
            format!("frame-src 'self' {}", origin_for(&schema, cfg!(windows)))
        );
        // A second patch finds no placeholder: the origin is set once.
        assert_eq!(patch_context(&mut context), Err(CspError::Placeholder));
    }
}

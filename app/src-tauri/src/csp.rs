//! The isolation origin in the main-window CSP (§6.4, §15 V34; M6 T4).
//!
//! Tauri 2.12.1 serves the isolation iframe from `isolation-<uuid>://localhost` (macOS, Linux) or
//! `http://isolation-<uuid>.localhost` (Windows), with a uuid `tauri-codegen` mints on every build
//! (`AssetOptions::isolation_schema`), and patches that origin into `default-src` only. The §6.4
//! policy sets `frame-src` explicitly, so `tauri.conf.json` carries the literal
//! [`ISOLATION_ORIGIN_PLACEHOLDER`] there and [`patch_context`] replaces it with this build's
//! origin before the app is built. The credential page's own meta CSP (§10.3), whose `frame-src`
//! must name the origin too, carries the same placeholder, and [`OriginAssets`] replaces it
//! whenever the page is served (or serves [`BROKEN_PAGE`]). Unpatched, the placeholder is not a
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

/// The pages [`OriginAssets`] serves with the origin substituted: the credential entry (§10.3,
/// PD-71), whose own meta CSP must name the isolation origin in `frame-src`. One page for every
/// platform; no other page is touched.
pub const ORIGIN_PAGES: [&str; 1] = ["credential.html"];

/// Served in place of an origin page whose placeholder cannot be completed: no script, no frame,
/// nothing to load, so the window can do nothing (fail closed; answering `None` would let Tauri
/// fall back to another page).
pub const BROKEN_PAGE: &str = "<!doctype html><html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'\"><title>atlas-duck</title></head><body></body></html>";

/// `page` with every placeholder, raw or attribute-escaped, replaced by `origin`. A page without
/// one is refused: its policy would block the isolation iframe or name no isolation origin.
pub fn substitute_page(page: &str, origin: &str) -> Result<String, CspError> {
    let found = page.matches(ISOLATION_ORIGIN_PLACEHOLDER).count()
        + page.matches(PLACEHOLDER_ESCAPED).count();
    if found == 0 || origin.contains(ISOLATION_ORIGIN_PLACEHOLDER) {
        return Err(CspError::Placeholder);
    }
    Ok(page
        .replace(ISOLATION_ORIGIN_PLACEHOLDER, origin)
        .replace(PLACEHOLDER_ESCAPED, origin))
}

/// The embedded frontend with this build's isolation origin in the [`ORIGIN_PAGES`]; everything
/// else passes unchanged.
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
        if !ORIGIN_PAGES.contains(&key.as_ref().trim_start_matches('/')) {
            return Some(bytes);
        }
        let page = std::str::from_utf8(&bytes)
            .map_err(|_| CspError::Placeholder)
            .and_then(|text| substitute_page(text, &self.origin));
        Some(match page {
            Ok(page) => Cow::Owned(page.into_bytes()),
            Err(_) => Cow::Borrowed(BROKEN_PAGE.as_bytes()),
        })
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
    fn substitute_page_replaces_every_placeholder_or_refuses() {
        let o = "isolation-x://localhost";
        assert_eq!(
            substitute_page(r#"content="frame-src <isolation-origin>""#, o),
            Ok(r#"content="frame-src isolation-x://localhost""#.into())
        );
        // The attribute-escaped spelling (how the source page writes it).
        assert_eq!(
            substitute_page(r#"content="frame-src &lt;isolation-origin&gt;""#, o),
            Ok(r#"content="frame-src isolation-x://localhost""#.into())
        );
        // Each occurrence is replaced once, by the origin, and none survives.
        let two = "a <isolation-origin> b &lt;isolation-origin&gt; c";
        let out = substitute_page(two, o).unwrap_or_default();
        assert_eq!(out, format!("a {o} b {o} c"));
        assert_eq!(out.matches(o).count(), 2);
        // No placeholder: refused, never served as is.
        for page in [
            "frame-src isolation://localhost",
            "",
            "&lt;isolation-origin",
        ] {
            assert_eq!(
                substitute_page(page, o),
                Err(CspError::Placeholder),
                "{page}"
            );
        }
        assert_eq!(
            substitute_page("<isolation-origin>", "<isolation-origin>"),
            Err(CspError::Placeholder)
        );
    }

    #[test]
    fn only_the_credential_page_is_rewritten_and_a_broken_one_fails_closed() {
        let page = r#"<meta http-equiv="Content-Security-Policy" content="frame-src &lt;isolation-origin&gt;">"#;
        let other = r#"<meta content="frame-src <isolation-origin>">"#;
        let get = |entries: Vec<(&'static str, &'static str)>, k: &str| {
            let assets = OriginAssets::new(
                Box::new(MapAssets(entries)),
                "isolation-x://localhost".into(),
            );
            Assets::<tauri::test::MockRuntime>::get(&assets, &k.into())
                .map(|b| String::from_utf8_lossy(&b).into_owned())
        };
        let patched = r#"<meta http-equiv="Content-Security-Policy" content="frame-src isolation-x://localhost">"#;
        let entries = vec![
            ("credential.html", page),
            ("approvals.html", other),
            ("assets/credential.js", "const s = '<isolation-origin>';"),
        ];
        assert_eq!(
            get(entries.clone(), "credential.html").as_deref(),
            Some(patched)
        );
        assert_eq!(
            get(entries.clone(), "/credential.html").as_deref(),
            Some(patched)
        );
        // Every other asset is served as built (an unpatched page stays blocked, never opened).
        assert_eq!(
            get(entries.clone(), "approvals.html").as_deref(),
            Some(other)
        );
        assert_eq!(
            get(entries.clone(), "assets/credential.js").as_deref(),
            Some("const s = '<isolation-origin>';")
        );
        assert_eq!(get(entries, "missing.html"), None);
        // A credential page without the placeholder is replaced by the inert page.
        let stale = vec![(
            "credential.html",
            "<meta content=\"frame-src isolation://localhost\">",
        )];
        assert_eq!(get(stale, "credential.html").as_deref(), Some(BROKEN_PAGE));
        assert!(!BROKEN_PAGE.contains("<script") && !BROKEN_PAGE.contains("<iframe"));
    }

    /// A policy without the placeholder is an error and stays as it was: `frame-src` is never
    /// widened to make up for it.
    #[test]
    fn unpatched_policy_is_an_error_and_unchanged() {
        let mut context: Context<tauri::test::MockRuntime> =
            tauri::generate_context!(assets = tauri::test::noop_assets(), test = true);
        let narrow = "default-src 'self'; frame-src 'self'";
        context.config_mut().app.security.csp = Some(Csp::Policy(narrow.into()));
        assert_eq!(patch_context(&mut context), Err(CspError::Placeholder));
        assert_eq!(
            context.config().app.security.csp,
            Some(Csp::Policy(narrow.into()))
        );
        context.config_mut().app.security.csp = None;
        assert_eq!(patch_context(&mut context), Err(CspError::NoPolicy));
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

    /// The `style-src` sources of `policy`.
    fn style_src(policy: &str) -> Vec<String> {
        policy
            .split(';')
            .map(str::trim)
            .find_map(|d| d.strip_prefix("style-src "))
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect()
    }

    /// M6 CI round 2, ruling B1 (§6.4's equivalent alternative): Tauri's isolation.js appends a
    /// `<style>` with `IFRAME_STYLE` to every page, and tauri-codegen puts its hash into the
    /// isolation page's policy only. Both of the app's policies admit exactly that style by its
    /// sha256 hash; a Tauri release that changes the text fails here, not as a CSP violation in a
    /// window.
    #[test]
    fn both_policies_admit_exactly_tauris_isolation_style() {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] =
            Sha256::digest(tauri::utils::pattern::isolation::IFRAME_STYLE.as_bytes()).into();
        let hash = format!(
            "'sha256-{}'",
            base64::engine::general_purpose::STANDARD.encode(digest)
        );
        let expected = vec!["'self'".to_owned(), hash];
        let context: Context<tauri::test::MockRuntime> =
            tauri::generate_context!(assets = tauri::test::noop_assets(), test = true);
        let Some(Csp::Policy(main)) = &context.config().app.security.csp else {
            panic!("the CSP is a policy string");
        };
        assert_eq!(style_src(main), expected, "tauri.conf.json: {main}");
        let page = include_str!("../../ui/credential.html");
        let meta = page
            .split("content=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default();
        assert_eq!(style_src(meta), expected, "credential.html: {meta}");
    }
}

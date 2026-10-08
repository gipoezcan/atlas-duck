use atlas_duck_atlassian::{
    BaseUrlError, OriginRefused, UrlHash, normalize_base_url, origin_guard, url_hash,
};
use proptest::prelude::*;

type R = Result<(), Box<dyn std::error::Error>>;

#[cfg(not(feature = "insecure-test-http"))]
#[test]
fn i02_normalize_rejects_http() {
    assert_eq!(
        normalize_base_url("http://jira.corp"),
        Err(BaseUrlError::InsecureScheme)
    );
}

#[test]
fn normalize_shapes() -> R {
    assert_eq!(
        normalize_base_url("https://Wiki.Corp:443/confluence/")?.as_str(),
        "https://wiki.corp/confluence"
    );
    let n = normalize_base_url("https://jira.corp:8443")?;
    assert_eq!(n.as_str(), "https://jira.corp:8443");
    assert_eq!(n.to_string(), "https://jira.corp:8443");
    assert!(n.is_https());
    assert_eq!(n.host(), "jira.corp");
    assert_eq!(n.context_path(), "");
    assert!(matches!(
        normalize_base_url("https://u:p@x"),
        Err(BaseUrlError::Invalid(_))
    ));
    assert!(matches!(
        normalize_base_url("https://x/?a=1"),
        Err(BaseUrlError::Invalid(_))
    ));
    assert!(matches!(
        normalize_base_url("ftp://x"),
        Err(BaseUrlError::Invalid(_))
    ));
    // Traversal in any spelling is refused on the raw text, before `url` can resolve it.
    for raw in [
        "https://x/a/../b",
        "https://x/a/%2e%2e/b",
        "https://x/a/%2E/b",
        "https://x/a/..;p=1/b",
        "https://x/a/..%2Fb",
        "https://x/a/..%5cb",
        r"https://x/a\..\b",
    ] {
        assert!(
            matches!(
                normalize_base_url(raw),
                Err(BaseUrlError::Invalid("dot segment"))
            ),
            "{raw}"
        );
    }
    // Why the raw check matters: `url` itself silently resolves these.
    assert_eq!(url::Url::parse("https://x/a/%2e%2e/b")?.path(), "/b");
    Ok(())
}

#[test]
fn url_hash_hex_roundtrip() -> R {
    let h = url_hash(&normalize_base_url("https://x/y")?);
    assert_eq!(UrlHash::from_hex(&h.to_hex()), Some(h));
    assert_eq!(UrlHash::from_hex("zz"), None);
    assert!(format!("{h:?}").contains(&h.to_hex()));
    assert_ne!(h, url_hash(&normalize_base_url("https://x/z")?));
    Ok(())
}

#[test]
fn refusal_kinds() -> R {
    let base = normalize_base_url("https://wiki.corp/confluence")?;
    let bound = url_hash(&base);
    let g = |u: &str| -> Result<Result<(), OriginRefused>, url::ParseError> {
        Ok(origin_guard(&url::Url::parse(u)?, &base, &bound))
    };
    assert_eq!(g("https://wiki.corp/confluence/rest/api")?, Ok(()));
    #[cfg(not(feature = "insecure-test-http"))]
    assert_eq!(
        g("http://wiki.corp/confluence/rest")?,
        Err(OriginRefused::NotHttps)
    );
    // With the test feature http passes the scheme check but never matches an https base.
    #[cfg(feature = "insecure-test-http")]
    assert_eq!(
        g("http://wiki.corp/confluence/rest")?,
        Err(OriginRefused::OutsideBase)
    );
    assert_eq!(
        g("https://u:p@wiki.corp/confluence/x")?,
        Err(OriginRefused::Userinfo)
    );
    assert_eq!(
        g("https://evil.corp/confluence/x")?,
        Err(OriginRefused::OutsideBase)
    );
    assert_eq!(
        g("https://wiki.corp/confluence2/x")?,
        Err(OriginRefused::OutsideBase)
    );
    assert_eq!(
        g("https://wiki.corp:8443/confluence/x")?,
        Err(OriginRefused::OutsideBase)
    );
    for traversal in [
        "https://wiki.corp/confluence/..;x/y",
        "https://wiki.corp/confluence/..%2Fy",
        "https://wiki.corp/confluence/a/..%5cy",
        "https://wiki.corp/confluence/%2e%2e%2fy",
        "https://wiki.corp/confluence/.%3Bx/y",
    ] {
        assert_eq!(
            g(traversal)?,
            Err(OriginRefused::OutsideBase),
            "{traversal}"
        );
    }
    assert_eq!(g("https://wiki.corp/confluence/a;x=1/b")?, Ok(()));
    let other = url_hash(&normalize_base_url("https://other.corp")?);
    assert_eq!(
        origin_guard(
            &url::Url::parse("https://wiki.corp/confluence/x")?,
            &base,
            &other
        ),
        Err(OriginRefused::BoundHashMismatch)
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn u04_no_pat_outside_bound_base_url(
        host in "[a-z]{1,8}\\.(corp|example)",
        port in proptest::option::of(1024u16..9000),
        ctx in proptest::collection::vec("[a-z]{1,6}", 0..3),
        kind in 0usize..13,
        tail in "[a-z]{1,6}",
    ) {
        let fail = |e: &dyn std::fmt::Display| TestCaseError::fail(e.to_string());
        let authority = |h: &str| match port {
            Some(p) => format!("{h}:{p}"),
            None => h.to_owned(),
        };
        let ctx_path: String = ctx.iter().map(|s| format!("/{s}")).collect();
        let root = format!("https://{}{ctx_path}", authority(&host));
        let origin = format!("https://{}", authority(&host));
        let base = normalize_base_url(&root).map_err(|e| fail(&e))?;
        let bound = url_hash(&base);
        // http is refused up front, except under the test feature, where the hash check decides.
        let not_https = if cfg!(feature = "insecure-test-http") {
            None
        } else {
            Some(OriginRefused::NotHttps)
        };
        let first = ctx.first().map(String::as_str).unwrap_or("");

        // (candidate, must the guard accept it with the right hash, expected refusal otherwise
        // with a wrong hash when not decided earlier)
        let (candidate, accepted, early) = match kind {
            0 => (format!("{root}/rest/{tail}"), true, None),
            // Same host, sibling context ("/confluence2"); under an empty context it is simply under the base.
            1 => (format!("{origin}/{first}2/rest/{tail}"), ctx.is_empty(), None),
            2 => (format!("{origin}/other/{tail}"), ctx.is_empty() || ctx == ["other"], None),
            3 => (format!("https://{}{ctx_path}/rest/{tail}", authority(&format!("x{host}"))), false, None),
            4 => (format!("{}/rest/{tail}", root.replacen("https://", "http://", 1)), false, not_https),
            5 => (format!("{}/rest/{tail}", root.replacen("https://", "https://u:p@", 1)), false, Some(OriginRefused::Userinfo)),
            6 => {
                // `_links.next`-style origin-relative path: `join` drops the context path.
                let joined = url::Url::parse(&format!("{root}/rest/x"))
                    .and_then(|u| u.join(&format!("/rest/{tail}")))
                    .map_err(|e| fail(&e))?;
                (joined.to_string(), ctx.is_empty(), None)
            }
            // Path-parameter and encoded-separator traversal: never accepted.
            8 => (format!("{root}/..;x/{tail}"), false, None),
            9 => (format!("{root}/..%2F{tail}"), false, None),
            10 => (format!("{root}/rest/..%5c..%5c{tail}"), false, None),
            11 => (format!("{root}/%2e%2e%2f{tail}"), false, None),
            // A path parameter on an ordinary segment is fine.
            12 => (format!("{root}/rest;jsessionid=x/{tail}"), true, None),
            // `url` resolves `..` first: the second one climbs out of a non-empty context.
            _ => (format!("{root}/rest/../../{tail}"), ctx.is_empty(), None),
        };
        let url = url::Url::parse(&candidate).map_err(|e| fail(&e))?;
        let got = origin_guard(&url, &base, &bound);
        prop_assert_eq!(got.is_ok(), accepted, "candidate {} got {:?}", candidate, got);

        // An instance edit changes the bound hash: always refused.
        let wrong = url_hash(&normalize_base_url("https://never.example/zzz").map_err(|e| fail(&e))?);
        let refused = origin_guard(&url, &base, &wrong);
        prop_assert_eq!(refused, Err(early.unwrap_or(OriginRefused::BoundHashMismatch)));
    }
}

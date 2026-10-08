use atlas_duck_atlassian::{TemplateError, build_url, normalize_base_url};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn build_url_encoding_is_pinned() -> TestResult {
    let b = normalize_base_url("https://jira.corp/jira")?;
    let t = "/rest/api/2/issue/{key}";
    // Path values: everything but ALPHA / DIGIT / - . _ ~ is %XX, uppercase hex, UTF-8 bytes.
    for (value, encoded) in [
        ("a?b", "a%3Fb"),
        ("a#b", "a%23b"),
        ("100%", "100%25"),
        ("a b", "a%20b"),
        ("a+b", "a%2Bb"),
        ("Ünï", "%C3%9Cn%C3%AF"),
        ("日本", "%E6%97%A5%E6%9C%AC"),
        ("a-b.c_d~e", "a-b.c_d~e"),
    ] {
        let u = build_url(&b, t, &json!({"key": value}), &[])?;
        assert_eq!(
            u.as_str(),
            format!("https://jira.corp/jira/rest/api/2/issue/{encoded}")
        );
        assert_eq!(u.query(), None);
        assert_eq!(u.fragment(), None);
    }
    // Query values are application/x-www-form-urlencoded (`Url::query_pairs_mut`): a space is
    // `+`, a literal `+` is `%2B`. Task 10 compares resolved URLs byte for byte against this.
    let q = vec![
        ("jql".to_owned(), "a b+c?d#e%f".to_owned()),
        ("é".to_owned(), "日".to_owned()),
    ];
    let u = build_url(&b, "/rest/api/2/field", &json!({}), &q)?;
    assert_eq!(u.query(), Some("jql=a+b%2Bc%3Fd%23e%25f&%C3%A9=%E6%97%A5"));
    Ok(())
}

#[test]
fn malformed_template_is_bad_template_not_bad_param() -> TestResult {
    let b = normalize_base_url("https://jira.corp/jira")?;
    for bad in [
        "rest/x", "//evil/x", "/x?y", "/x#y", "/x/../y", "/x/{k", "/x/k}",
    ] {
        assert_eq!(
            build_url(&b, bad, &json!({"k": "a"}), &[]),
            Err(TemplateError::BadTemplate),
            "{bad}"
        );
    }
    Ok(())
}

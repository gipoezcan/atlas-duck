use atlas_duck_atlassian::{
    PatSecret, StoredCredential, StoredIdentity, UrlHash, username_matches,
};

#[test]
fn i30_percent_email_and_case_match() {
    assert!(username_matches("jdoe%40corp.example", "jdoe@corp.example"));
    assert!(username_matches("JDoe", "jdoe"));
    assert!(username_matches(" jdoe ", "jdoe"));
    // Simple folding does not map ß to ss.
    assert!(!username_matches("Straße", "STRASSE"));
    assert!(username_matches("ǅ", "ǆ"));
    assert!(username_matches("e\u{301}", "é"));
}

#[test]
fn anonymous_never_matches() {
    assert!(!username_matches("anonymous", "anonymous"));
    assert!(!username_matches("ANONYMOUS", "anonymous"));
    assert!(!username_matches("anonymous%20", "anonymous "));
    assert!(!username_matches("", ""));
}

#[test]
fn literal_percent_without_triplet() {
    assert!(username_matches("50%", "50%"));
    assert!(username_matches("a%zz", "a%zz"));
    // Invalid UTF-8 after decoding fails closed.
    assert!(!username_matches("%FF", "%FF"));
}

#[test]
fn pat_secret_debug_redacts() {
    let s = format!("{:?}", PatSecret::new("tok".into()));
    assert!(s.contains("REDACTED"));
    assert!(!s.contains("tok"));
}

#[test]
fn stored_credential_debug_redacts() {
    let c = StoredCredential {
        pat: PatSecret::new("supersecret".into()),
        base_url_hash: UrlHash([7; 32]),
        identity: StoredIdentity {
            atlassian_user: "jdoe".into(),
            atlassian_user_key: "JIRAUSER1".into(),
        },
        expires_at: None,
    };
    let s = format!("{c:?}");
    assert!(s.contains("REDACTED"));
    assert!(!s.contains("supersecret"));
}

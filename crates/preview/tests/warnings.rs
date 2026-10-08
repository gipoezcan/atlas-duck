use atlas_duck_preview::warning::*;
use atlas_duck_preview::{
    CandidateRev, ERROR_TEXT_CAP_BYTES, PreviewBody, RAW_PAGE_BYTES, RawPager, cap_error_text,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const C6_CAUTION: [&str; 20] = [
    "restricted_comments",
    "security_level",
    "all_fields",
    "bidi_controls",
    "other_invisible",
    "mixed_script",
    "raw_only_diff",
    "lossy_update",
    "server_rendered_view",
    "possible_duplicate",
    "similar_request",
    "conflict",
    "missing_required_fields",
    "changed_since_review",
    "could_not_recheck",
    "token_changed",
    "token_identity_mismatch",
    "identity_header_lost",
    "user_renamed",
    "instance_url_changed",
];
const C6_INFO: [&str; 8] = [
    "linked_issue_summaries",
    "custom_fields",
    "truncated_by_cap",
    "host_calls_lossy",
    "unknown_macros",
    "unresolved_mention",
    "cql_broad",
    "source_formatting_removed",
];

#[test]
fn every_warning_id_has_exactly_one_level() -> TestResult {
    let mut caution = Vec::new();
    let mut info = Vec::new();
    for id in WarningId::ALL {
        let name = serde_json::to_value(id)?
            .as_str()
            .ok_or("id is a string")?
            .to_owned();
        let w = Warning::new(id, "x");
        assert_eq!(w.level, id.level());
        match id.level() {
            Level::Caution => caution.push(name),
            Level::Info => info.push(name),
        }
    }
    assert_eq!(caution, C6_CAUTION);
    assert_eq!(info, C6_INFO);
    let mut all = WarningId::ALL.to_vec();
    all.dedup();
    assert_eq!(all.len(), 28);
    Ok(())
}

#[test]
fn fixed_texts_verbatim() {
    assert_eq!(TEXT_ALL_FIELDS, "all fields requested (`*all`)");
    assert_eq!(TEXT_CHANGED_SINCE_REVIEW, "Changed since you reviewed");
    assert_eq!(TEXT_COULD_NOT_RECHECK, "Could not re-check target");
    assert_eq!(
        TEXT_IDENTITY_HEADER_LOST,
        "Jira did not send a matching X-AUSERNAME (possibly stripped by a reverse proxy); ask the Jira administrator"
    );
    assert_eq!(
        TEXT_RESTRICTED_COMMENTS,
        "includes restricted-visibility comments"
    );
    assert_eq!(TEXT_SECURITY_LEVEL, "issue has a security level");
    assert_eq!(
        TEXT_SERVER_RENDERED_VIEW,
        "server-rendered view: macros may include content from other pages"
    );
    assert_eq!(TEXT_UNKNOWN_MACROS, "body contains unknown macros");
    assert_eq!(TEXT_UNRESOLVED_MENTION, "mention could not be resolved");
    assert_eq!(TEXT_CQL_BROAD, "CQL may enumerate many results");
    assert_eq!(
        TEXT_SOURCE_FORMATTING_REMOVED,
        "source formatting removed (hidden/colour styling present)"
    );
}

#[test]
fn parameterized_texts() {
    assert_eq!(
        similar_request("req_x", "outcome unknown"),
        "similar to req_x outcome unknown"
    );
    assert_eq!(
        similar_request("req_x", "executed 14:02"),
        "similar to req_x executed 14:02"
    );
    assert_eq!(
        instance_url_changed("https://a", "https://b"),
        "instance URL changed: https://a → https://b"
    );
    assert_eq!(token_changed("bob"), "token changed: now executes as bob");
    assert_eq!(
        token_no_longer_resolves("bob"),
        "token no longer resolves to bob"
    );
    assert_eq!(user_renamed("a", "b"), "Atlassian username changed: a → b");
    assert_eq!(
        conflict(5, 6),
        "conflict: page changed since the agent read it (v5 → v6)"
    );
    assert_eq!(possible_duplicate("req_1"), "possible duplicate of req_1");
    assert_eq!(
        bidi_controls(2),
        "contains 2 bidirectional control characters"
    );
    assert_eq!(other_invisible(3), "contains 3 other invisible characters");
    assert_eq!(mixed_script("ABC-1"), "mixed-script identifier: ABC-1");
    assert_eq!(
        missing_required_fields("Team (customfield_10200, option)"),
        "missing required fields: Team (customfield_10200, option)"
    );
    assert_eq!(truncated_by_cap(5, 9), "result truncated by cap (5 of 9)");
    assert_eq!(
        lossy_update(1, 2, 3),
        "this update will remove 1 macros / 2 images / 3 links"
    );
}

#[test]
fn candidate_rev_round_trips_as_lowercase_hex() -> TestResult {
    let rev = CandidateRev {
        counter: 3,
        candidate_hash: [0xab; 32],
    };
    let j = serde_json::to_value(rev)?;
    assert_eq!(j["candidate_hash"], "ab".repeat(32));
    assert_eq!(serde_json::from_value::<CandidateRev>(j)?, rev);
    for bad in ["AB".repeat(32), "ab".repeat(31), "zz".repeat(32)] {
        let r = serde_json::from_value::<CandidateRev>(
            serde_json::json!({"counter": 1, "candidate_hash": bad}),
        );
        assert!(r.is_err(), "{bad}");
    }
    Ok(())
}

#[test]
fn upstream_error_text_is_capped_at_a_char_boundary() {
    assert_eq!(cap_error_text("short"), "short");
    let long = "é".repeat(5000);
    let capped = cap_error_text(&long);
    assert!(capped.len() <= ERROR_TEXT_CAP_BYTES);
    assert!(capped.ends_with('…'));
    assert!(capped.len() > ERROR_TEXT_CAP_BYTES - 4);
    let exact = "a".repeat(ERROR_TEXT_CAP_BYTES);
    assert_eq!(cap_error_text(&exact), exact);
    match PreviewBody::upstream_error(500, &"a".repeat(3000)) {
        PreviewBody::UpstreamError {
            error_messages_text,
            ..
        } => assert_eq!(error_messages_text.len(), ERROR_TEXT_CAP_BYTES),
        _ => unreachable!(),
    }
}

#[test]
fn raw_pager_pages() {
    assert_eq!(RawPager::for_total(0).page_count, 1);
    assert_eq!(RawPager::for_total(RAW_PAGE_BYTES).page_count, 1);
    assert_eq!(RawPager::for_total(RAW_PAGE_BYTES + 1).page_count, 2);
    assert_eq!(RawPager::for_total(5).page_bytes, RAW_PAGE_BYTES);
}

use atlas_duck_preview::warning::*;
use atlas_duck_preview::{
    CandidateRev, ERROR_TEXT_CAP_BYTES, PreviewBody, RAW_PAGE_BYTES, RawPager, cap_error_text,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const C6_CAUTION: [&str; 25] = [
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
    "diff_truncated",
    "no_current_value",
    "link_type_inward_phrase",
    // M7 Δ2 (PD-105): a page with the create's title exists in the space.
    "duplicate_title",
    "script_rendered_copies",
];
const C6_INFO: [&str; 9] = [
    "linked_issue_summaries",
    "custom_fields",
    "truncated_by_cap",
    "host_calls_lossy",
    "unknown_macros",
    "unresolved_mention",
    "cql_broad",
    "source_formatting_removed",
    "required_field_list_incomplete",
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
    assert_eq!(all.len(), 34);
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
    assert_eq!(
        TEXT_SCRIPT_RENDERED_COPIES,
        "this result may contain rendered copies of fields (renderedFields); dropping a field does not drop its copy; use mask in every occurrence"
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
    // T12 review M10 (PD-49): the createmeta field pages past the cap.
    assert_eq!(
        required_field_list_incomplete(4, Some(20)),
        "required-field list incomplete: 4 of 20 pages read"
    );
    assert_eq!(
        required_field_list_incomplete(4, None),
        "required-field list incomplete: 4 of more than 4 pages read"
    );
    // T13 (T6 handoff): an edit diff cut at its caps.
    assert_eq!(
        diff_truncated(12),
        "diff truncated: 12 bytes not shown (see Request)"
    );
    // T13 review M-1: an edit section without the current value.
    assert_eq!(
        no_current_value(2),
        "2 fields shown as sent, without their current value"
    );
    // T16 review I1: a link type named by its inward phrase.
    assert_eq!(
        link_type_inward_phrase("is blocked by", "blocks"),
        "link type named by its inward phrase 'is blocked by': the inward issue gets the outward phrase 'blocks'"
    );
    assert_eq!(
        lossy_update(1, 2, 3, 0),
        "this update will remove 1 macros / 2 images / 3 links"
    );
    // M7 lead ruling Q10 (PD-104): lost layouts are appended only when there are any.
    assert_eq!(
        lossy_update(0, 0, 1, 2),
        "this update will remove 0 macros / 0 images / 1 links, 2 layouts"
    );
    // M7 PD-105: a page with the create's title exists.
    assert_eq!(
        duplicate_title("Release plan", "DEV"),
        "a page titled 'Release plan' already exists in DEV"
    );
    assert_eq!(WarningId::DuplicateTitle.level(), Level::Caution);
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

/// M8 ZWJ review I-2 / M-7: the cap of a display-escaped error text (the Recent list, the
/// upstream and enrichment error cards) never ends inside an emoji sequence (a raw U+200D the
/// kept text flags) or inside a `⟨U+XXXX⟩` escape (unmarked half of one); it moves back to the
/// start of either.
#[test]
fn error_text_cap_never_splits_a_sequence_or_an_escape() {
    use atlas_duck_preview::invisible::{escape_for_display, flags};
    let end = ERROR_TEXT_CAP_BYTES - '…'.len_utf8();
    // The old cut fell right after the U+200D of 👩‍💻.
    let seq = escape_for_display(&("x".repeat(end - 7) + "👩\u{200D}💻 tail"));
    assert_eq!(&seq[end - 3..end], "\u{200D}");
    let capped = cap_error_text(&seq);
    assert_eq!(capped, "x".repeat(end - 7) + "…");
    assert!(!flags(&capped).contains(&true), "{capped:?}");
    // The old cut fell inside the escape of U+202E.
    let esc = escape_for_display(&("x".repeat(end - 5) + "\u{202E}tail"));
    assert_eq!(&esc[end - 5..end + 7], "⟨U+202E⟩");
    assert_eq!(cap_error_text(&esc), "x".repeat(end - 5) + "…");
    // A cut at the very end of a sequence or an escape keeps it.
    let whole = "x".repeat(end - 11) + "👩\u{200D}💻 tail";
    assert_eq!(
        cap_error_text(&whole),
        "x".repeat(end - 11) + "👩\u{200D}💻…"
    );
    let whole = escape_for_display(&("x".repeat(end - 12) + "\u{202E}tail"));
    assert_eq!(cap_error_text(&whole), "x".repeat(end - 12) + "⟨U+202E⟩…");
}

#[test]
fn raw_pager_pages() {
    assert_eq!(RawPager::for_total(0).page_count, 1);
    assert_eq!(RawPager::for_total(RAW_PAGE_BYTES).page_count, 1);
    assert_eq!(RawPager::for_total(RAW_PAGE_BYTES + 1).page_count, 2);
    assert_eq!(RawPager::for_total(5).page_bytes, RAW_PAGE_BYTES);
}

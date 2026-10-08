//! Sentinel in every field that can carry a body, URL, username, token or header value: none of
//! it may reach `Debug` output (§7.7).

use atlas_duck_atlassian::{
    ApprovedWrite, BodyFailure, Captured, ConnClass, ExpectedBody, FetchFailure, FetchOutcome,
    GetCall, HttpRequestSpec, IdentityObserved, PagedCall, PatSecret, PostSendKind, SearchCall,
    StoredCredential, StoredIdentity, SuccessExpectation, UnavailableReason, UnknownReason,
    UpstreamResponse, WriteOutcome, normalize_base_url, url_hash,
};
use serde_json::json;

const S: &str = "SENTINEL-4711";

fn resp() -> UpstreamResponse {
    UpstreamResponse {
        status: 200,
        content_type: Some("application/json".into()),
        body: S.as_bytes().to_vec(),
    }
}

#[test]
fn debug_output_never_contains_sentinel() -> Result<(), Box<dyn std::error::Error>> {
    let spec = HttpRequestSpec {
        index: 1,
        method: "PUT".into(),
        resolved_url: format!("https://jira.corp/x?{S}=1"),
        content_type: Some("application/json".into()),
        body: S.as_bytes().to_vec(),
    };
    let get = GetCall {
        endpoint_template: "/rest/api/2/issue/{key}".into(),
        params: json!({"key": S}),
        query: vec![(S.to_owned(), S.to_owned())],
    };
    let mut dumps: Vec<String> = vec![
        format!("{:?}", resp()),
        format!("{spec:?}"),
        format!("{get:?}"),
        format!(
            "{:?}",
            PagedCall {
                get: get.clone(),
                items_key: "issues".into(),
                offset_param: "startAt".into(),
                limit_param: "maxResults".into(),
                page_size: 1,
                start: 0,
            }
        ),
        format!(
            "{:?}",
            SearchCall {
                endpoint_template: "/rest/api/2/search".into(),
                body: json!({"jql": S}),
            }
        ),
        format!(
            "{:?}",
            ApprovedWrite {
                requests: vec![spec],
                success: SuccessExpectation {
                    statuses: None,
                    body: ExpectedBody::Json,
                },
            }
        ),
        format!("{:?}", IdentityObserved::Other(S.into())),
        format!(
            "{:?}",
            UnknownReason::IdentityMismatch {
                server_user: Some(S.into()),
            }
        ),
        format!(
            "{:?}",
            Captured {
                sent: true,
                pages: vec![resp()],
                partial: S.as_bytes().to_vec(),
            }
        ),
        format!(
            "{:?}",
            StoredIdentity {
                atlassian_user: S.into(),
                atlassian_user_key: S.into(),
            }
        ),
        format!("{:?}", PatSecret::new(S.into())),
        format!(
            "{:?}",
            StoredCredential {
                pat: PatSecret::new(S.into()),
                base_url_hash: url_hash(&normalize_base_url("https://jira.corp")?),
                identity: StoredIdentity {
                    atlassian_user: S.into(),
                    atlassian_user_key: S.into(),
                },
                expires_at: None,
            }
        ),
    ];
    for w in [
        WriteOutcome::Executed {
            response: resp(),
            server_user: Some(S.into()),
            request_index: 0,
        },
        WriteOutcome::Failed4xx {
            response: resp(),
            request_index: 0,
        },
        WriteOutcome::OutcomeUnknown {
            reason: UnknownReason::IdentityMismatch {
                server_user: Some(S.into()),
            },
            request_index: 0,
        },
    ] {
        dumps.push(format!("{w:?}"));
    }
    for f in [
        FetchFailure::PostSend {
            kind: PostSendKind::NetworkError,
            received: S.as_bytes().to_vec(),
        },
        FetchFailure::CancelledInFlight {
            bytes_received: S.as_bytes().to_vec(),
        },
        FetchFailure::BodyDecided {
            kind: BodyFailure::ReadError,
            response: resp(),
        },
        FetchFailure::StatusHeaderDecided {
            reason: UnavailableReason::NonJson2xx,
            response: resp(),
        },
        FetchFailure::IdentityCheckFailed {
            observed: IdentityObserved::Other(S.into()),
            response: resp(),
        },
        FetchFailure::PreSendConnection(ConnClass::Dns),
    ] {
        dumps.push(format!("{:?}", FetchOutcome::Failed(f)));
    }
    dumps.push(format!("{:?}", FetchOutcome::Response(resp())));
    for d in &dumps {
        assert!(!d.contains("SENTINEL"), "{d}");
    }
    // The redaction keeps the length, so a mismatch stays diagnosable.
    assert_eq!(
        format!("{:?}", IdentityObserved::Other("jdoe".into())),
        "Other(<redacted:4 chars>)"
    );
    Ok(())
}

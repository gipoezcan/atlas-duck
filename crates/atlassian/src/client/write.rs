//! Approved write execution (§5.1 invariant 3, §5.4 step 6, §7.2 declared write success, I-25).
//!
//! The only code that mutates Atlassian data. It writes exactly the approved request: the method
//! guard compares the very `reqwest::Request` handed to the connection with the list entry, byte
//! for byte (`send.rs`, `guard.rs`), on every attempt; any difference refuses the write before
//! anything leaves.

use reqwest::header::CONTENT_TYPE;
use tokio::time::Instant;

use super::classify::is_json_content_type;
use super::send::{
    BodyRead, Exchange, MAX_RESPONSE_BYTES, OneRequest, Target, ausernames, header_text, read_body,
};
use super::{FetchControl, InstanceClient, Product};
use crate::cover::AuditCover;
use crate::identity::check_jira_header;
use crate::types::{
    ApprovedWrite, ExpectedBody, FetchFailure, HttpRequestSpec, IdentityObserved, NotSentReason,
    PostSendKind, SuccessExpectation, UnknownReason, UpstreamResponse, WriteOutcome,
};

/// §5.4 step 6: connection errors before any byte was sent are retried once.
const MAX_PRESEND_RETRIES: u32 = 1;

impl InstanceClient {
    /// `send_approved_ctl` with a fresh control.
    pub async fn send_approved(&self, cover: &AuditCover, w: &ApprovedWrite) -> WriteOutcome {
        self.send_approved_ctl(cover, w, &FetchControl::new()).await
    }

    /// Sends the approved request, exactly as listed, within the 60 s write budget
    /// (`Timeouts.write`; 429 waits and the pre-send retry included), and classifies the answer.
    ///
    /// §5.1 invariant 3: every v1 write maps to exactly one HTTP request. A list with no entry or
    /// with several is refused whole (`RefusedMismatch`, nothing sent): a single `WriteOutcome`
    /// cannot say which requests of a partly executed list took effect.
    pub async fn send_approved_ctl(
        &self,
        cover: &AuditCover,
        w: &ApprovedWrite,
        ctl: &FetchControl,
    ) -> WriteOutcome {
        let [spec] = w.requests.as_slice() else {
            return WriteOutcome::RefusedMismatch {
                request_index: w.requests.first().map_or(0, |s| s.index),
            };
        };
        let budget_end = Instant::now() + self.cfg.timeouts.write;
        let req = OneRequest {
            target: Target::Approved(spec),
            overall: Some((budget_end, PostSendKind::PerCallTimeout)),
            max_response_bytes: MAX_RESPONSE_BYTES,
            cap_kind: PostSendKind::ResponseCap32MiB,
        };
        let mut retries = 0;
        loop {
            match self.exchange(cover, &req, ctl).await {
                Ok(ex) => return self.finish_write(ex, spec, &w.success, ctl).await,
                Err(FetchFailure::PreSendConnection(_))
                    if retries < MAX_PRESEND_RETRIES && Instant::now() < budget_end =>
                {
                    retries += 1;
                }
                Err(f) => return not_answered(f, spec.index),
            }
        }
    }

    /// Classifies the write response (§5.4 step 6, §7.2).
    async fn finish_write(
        &self,
        ex: Exchange<'_>,
        spec: &HttpRequestSpec,
        success: &SuccessExpectation,
        ctl: &FetchControl,
    ) -> WriteOutcome {
        let Exchange {
            resp,
            permit,
            cred,
            deadline,
            deadline_kind: _,
        } = ex;
        let request_index = spec.index;
        let status = resp.status().as_u16();
        let content_type = header_text(resp.headers(), CONTENT_TYPE).map(str::to_owned);
        let json = is_json_content_type(content_type.as_deref());
        let auser = ausernames(resp.headers());
        let unknown = |reason| WriteOutcome::OutcomeUnknown {
            reason,
            request_index,
        };

        // Only `Executed` and `Failed4xx` carry the response. On every other answered outcome
        // the body stays in the control for the outcome event (§7.2: such bodies are audit-only;
        // core reads them with `take_captured().partial`).
        let read = read_body(resp, ctl, deadline, MAX_RESPONSE_BYTES).await;
        drop(permit);

        // Redirects are never followed and never a success (§7.2); the body was read (capped,
        // read errors ignored) for the audit record only.
        if (300..400).contains(&status) {
            return WriteOutcome::Unavailable3xx { request_index };
        }
        let client_error = (400..500).contains(&status);
        match read {
            BodyRead::Complete => {}
            // The control keeps the bytes for `take_captured`.
            BodyRead::Cancelled => return unknown(UnknownReason::Cancelled),
            // A 4xx already says the write was refused; its (partial) body is only the reason.
            _ if client_error => {}
            _ if status >= 500 => return unknown(UnknownReason::ServerError5xx),
            BodyRead::Deadline => return unknown(UnknownReason::Timeout),
            BodyRead::Error => return unknown(UnknownReason::ResetAfterSend),
            BodyRead::OverCap => return unknown(UnknownReason::UndeclaredSuccess),
        }
        // A copy: the two outcomes that carry it clear the control when they return.
        let response = UpstreamResponse {
            status,
            content_type,
            body: ctl.snapshot_partial(),
        };

        // Decided before any JSON parse: a declared empty success may carry any content type,
        // a JSON one included (Task 9 review, minor 7).
        let declared = (200..300).contains(&status)
            && success
                .statuses
                .as_ref()
                .is_none_or(|s| s.contains(&status))
            && match success.body {
                ExpectedBody::Empty => response.body.is_empty(),
                ExpectedBody::Json => json && parses(&response.body),
            };

        // A JSON 401 is the token verdict (`X-AUSERNAME` is `anonymous` there by nature).
        if status == 401 && json {
            return WriteOutcome::NeedsToken;
        }

        // §7.2: a Jira response not attributed to the PAT's user never counts as a success, and
        // its body is audit-only (never a `Failed4xx` the agent would see): every declared
        // success and every JSON answer is checked.
        if self.cfg.product == Product::Jira
            && (declared || json)
            && let Err(observed) = check_jira_header(&auser, &cred.identity.atlassian_user)
        {
            let server_user = match observed {
                IdentityObserved::Missing => None,
                IdentityObserved::Anonymous | IdentityObserved::Other(_) => Some(auser.join(", ")),
            };
            return unknown(UnknownReason::IdentityMismatch { server_user });
        }

        if declared {
            ctl.clear_partial();
            return WriteOutcome::Executed {
                server_user: match auser.as_slice() {
                    [one] => Some(one.clone()),
                    _ => None,
                },
                response,
                request_index,
            };
        }
        if (200..300).contains(&status) {
            return unknown(UnknownReason::UndeclaredSuccess);
        }
        // Lost-update protection is Confluence's optimistic lock (§5.4 steps 2 and 6).
        if self.cfg.product == Product::Confluence
            && (status == 409 || (status == 400 && is_version_conflict(&response.body)))
        {
            return WriteOutcome::VersionConflict { request_index };
        }
        if client_error {
            ctl.clear_partial();
            return WriteOutcome::Failed4xx {
                response,
                request_index,
            };
        }
        if status >= 500 {
            return unknown(UnknownReason::ServerError5xx);
        }
        unknown(UnknownReason::UndeclaredSuccess)
    }
}

fn parses(body: &[u8]) -> bool {
    serde_json::from_slice::<serde::de::IgnoredAny>(body).is_ok()
}

/// The write got no answer to classify.
fn not_answered(f: FetchFailure, request_index: u32) -> WriteOutcome {
    let unknown = |reason| WriteOutcome::OutcomeUnknown {
        reason,
        request_index,
    };
    match f {
        // Nothing of the request left.
        FetchFailure::PreSendConnection(class) => WriteOutcome::NotSent {
            reason: NotSentReason::Connection(class),
        },
        FetchFailure::BudgetExpiredBeforeSend => WriteOutcome::NotSent {
            reason: NotSentReason::BudgetExpired,
        },
        FetchFailure::CancelledBeforeSend => WriteOutcome::NotSent {
            reason: NotSentReason::Cancelled,
        },
        FetchFailure::MethodGuardRefused => WriteOutcome::RefusedMismatch { request_index },
        FetchFailure::OriginGuardRefused => WriteOutcome::OriginGuardRefused,
        FetchFailure::NeedsToken => WriteOutcome::NeedsToken,
        // The request may have reached the server.
        FetchFailure::PostSend {
            kind: PostSendKind::PerCallTimeout | PostSendKind::ReadBudget120s,
            ..
        } => unknown(UnknownReason::Timeout),
        FetchFailure::PostSend {
            kind: PostSendKind::NetworkError,
            ..
        } => unknown(UnknownReason::ResetAfterSend),
        FetchFailure::CancelledInFlight { .. } => unknown(UnknownReason::Cancelled),
        // Body classes are `finish_write`'s; `exchange` never returns them. Unknown is the safe
        // reading should that change.
        FetchFailure::PostSend {
            kind: PostSendKind::ResponseCap32MiB | PostSendKind::FetchCap50MiB,
            ..
        }
        | FetchFailure::StatusHeaderDecided { .. }
        | FetchFailure::BodyDecided { .. }
        | FetchFailure::IdentityCheckFailed { .. } => unknown(UnknownReason::UndeclaredSuccess),
    }
}

/// Confluence's 400 form of a stale `version.number`: `message` or an `errorMessages` entry that
/// mentions "version" and "conflict", "must be incremented" or "stale", case-insensitively
/// (V04/V06 confirm the texts in M7).
fn is_version_conflict(body: &[u8]) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let message = v.get("message").and_then(serde_json::Value::as_str);
    let listed = v
        .get("errorMessages")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str);
    message.into_iter().chain(listed).any(|m| {
        let m = m.to_lowercase();
        m.contains("version")
            && (m.contains("conflict") || m.contains("must be incremented") || m.contains("stale"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_conflict_texts() {
        for yes in [
            r#"{"message":"Version must be incremented on update. Current version is: 8"}"#,
            r#"{"errorMessages":["x","Version CONFLICT"]}"#,
            r#"{"message":"stale version"}"#,
        ] {
            assert!(is_version_conflict(yes.as_bytes()), "{yes}");
        }
        for no in [
            r#"{"message":"Invalid version"}"#,
            r#"{"message":"conflict"}"#,
            r#"{"errors":{"version":"stale conflict"}}"#,
            r#"{"errorMessages":[1, "version"]}"#,
            "version conflict",
            "",
        ] {
            assert!(!is_version_conflict(no.as_bytes()), "{no}");
        }
    }

    #[test]
    fn unanswered_writes_are_not_sent_only_when_nothing_left() {
        use crate::types::ConnClass;
        assert_eq!(
            not_answered(FetchFailure::PreSendConnection(ConnClass::Dns), 2),
            WriteOutcome::NotSent {
                reason: NotSentReason::Connection(ConnClass::Dns)
            }
        );
        // Post-send failures may have executed the write.
        for (f, reason) in [
            (
                FetchFailure::PostSend {
                    kind: PostSendKind::NetworkError,
                    received: vec![],
                },
                UnknownReason::ResetAfterSend,
            ),
            (
                FetchFailure::PostSend {
                    kind: PostSendKind::PerCallTimeout,
                    received: vec![],
                },
                UnknownReason::Timeout,
            ),
            (
                FetchFailure::CancelledInFlight {
                    bytes_received: vec![],
                },
                UnknownReason::Cancelled,
            ),
        ] {
            assert_eq!(
                not_answered(f, 2),
                WriteOutcome::OutcomeUnknown {
                    reason,
                    request_index: 2
                }
            );
        }
    }
}

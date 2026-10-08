//! One request (§7.2, plan Task 9 "Classification algorithm"; the step numbers below are the
//! plan's): guards, limiter, `429` retries, deadlines, classification, body reading with the
//! per-response cap and cancel capture, `Date` reporting and the Jira identity check.

use std::time::SystemTime;

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, DATE, HeaderMap, HeaderValue, RETRY_AFTER};
use tokio::time::{Instant, sleep_until};
use zeroize::Zeroizing;

use super::classify::{ConnFlags, execute_error_class, is_json_content_type, retry_after_wait};
use super::limiter::Acquired;
use super::{FetchControl, InstanceClient, Product};
use crate::cover::AuditCover;
use crate::credentials::{PatSecret, StoredCredential};
use crate::guard::{SendMode, method_guard};
use crate::identity::check_jira_header;
use crate::origin::origin_guard;
use crate::types::{
    BodyFailure, FetchFailure, FetchOutcome, PostSendKind, UnavailableReason, UpstreamResponse,
};
use crate::url::build_url;

/// §7.2: 32 MiB per HTTP response.
pub(crate) const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
/// §7.2: at most 3 retries of a `429`.
const MAX_429_RETRIES: u32 = 3;

pub(crate) struct OneRequest<'a> {
    pub(crate) method: reqwest::Method,
    pub(crate) template: &'a str,
    pub(crate) params: &'a serde_json::Value,
    pub(crate) query: &'a [(String, String)],
    /// Sent with `Content-Type: application/json`.
    pub(crate) json_body: Option<Vec<u8>>,
    pub(crate) mode: SendMode<'a>,
    /// The call's overall budget and the class its expiry gets (Task 10 threads the 120 s read
    /// budget through here); `None` = only the per-call deadline of each attempt.
    pub(crate) overall: Option<(Instant, PostSendKind)>,
    pub(crate) max_response_bytes: u64,
}

enum BodyRead {
    Complete,
    Cancelled,
    Deadline,
    OverCap,
    Error,
}

fn failed(f: FetchFailure) -> FetchOutcome {
    FetchOutcome::Failed(f)
}

/// §5.2 step 3: before `sent` nothing left; after it, whatever arrived so far is reported.
fn cancelled(ctl: &FetchControl) -> FetchOutcome {
    if ctl.is_sent() {
        failed(FetchFailure::CancelledInFlight {
            bytes_received: ctl.snapshot_partial(),
        })
    } else {
        failed(FetchFailure::CancelledBeforeSend)
    }
}

/// The overall budget ran out before this attempt was handed to the connection. If an earlier
/// attempt of the call was sent (a retried 429), the expiry is post-send.
fn budget_expired(ctl: &FetchControl, req: &OneRequest<'_>) -> FetchOutcome {
    match req.overall {
        Some((_, kind)) if ctl.is_sent() => failed(FetchFailure::PostSend {
            kind,
            received: Vec::new(),
        }),
        _ => failed(FetchFailure::BudgetExpiredBeforeSend),
    }
}

/// The header value is marked sensitive; the formatted copy is zeroized.
fn bearer(pat: &PatSecret) -> Option<HeaderValue> {
    let text = Zeroizing::new(format!("Bearer {}", pat.expose_secret()));
    let mut v = HeaderValue::from_str(&text).ok()?;
    v.set_sensitive(true);
    Some(v)
}

fn header_text(headers: &HeaderMap, name: impl reqwest::header::AsHeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

impl InstanceClient {
    pub(crate) async fn send_one(
        &self,
        cover: &AuditCover,
        req: OneRequest<'_>,
        ctl: &FetchControl,
    ) -> FetchOutcome {
        // Holding a cover is the proof of a committed start record (§5.1 inv. 1).
        let _ = cover;

        // Step 1: URL, method guard, credential, origin guard. Nothing leaves on a refusal. A URL
        // that cannot be built under the base is refused like an origin mismatch.
        let Ok(url) = build_url(&self.cfg.base, req.template, req.params, req.query) else {
            return failed(FetchFailure::OriginGuardRefused);
        };
        if method_guard(&req.mode, req.method.as_str(), req.template).is_err() {
            return failed(FetchFailure::MethodGuardRefused);
        }
        // A keychain error fails closed as well; its state is `core`'s concern.
        let Ok(Some(cred)) = self.creds.load(&self.cfg.instance_id) else {
            return failed(FetchFailure::NeedsToken);
        };
        if origin_guard(&url, &self.cfg.base, &cred.base_url_hash).is_err() {
            return failed(FetchFailure::OriginGuardRefused);
        }
        // A stored PAT that cannot be a header value is unusable.
        let Some(auth) = bearer(&cred.pat) else {
            return failed(FetchFailure::NeedsToken);
        };

        let mut retries = 0;
        loop {
            // Step 2: limiter permit (cancel-aware, bounded by the overall budget).
            let permit = match self
                .limiter
                .acquire(ctl, req.overall.map(|(end, _)| end))
                .await
            {
                Acquired::Permit(p) => p,
                Acquired::Cancelled => return cancelled(ctl),
                Acquired::Expired => return budget_expired(ctl, &req),
            };
            let now = Instant::now();
            let mut deadline = now + self.cfg.timeouts.per_call;
            let mut deadline_kind = PostSendKind::PerCallTimeout;
            if let Some((end, kind)) = req.overall {
                if now >= end {
                    return budget_expired(ctl, &req);
                }
                if end < deadline {
                    deadline = end;
                    deadline_kind = kind;
                }
            }
            // The Authorization header exists only on this one request (never a default header).
            let mut b = self
                .http
                .request(req.method.clone(), url.clone())
                .header(AUTHORIZATION, auth.clone());
            if req.method != reqwest::Method::GET {
                b = b.header("X-Atlassian-Token", "no-check");
            }
            if let Some(body) = &req.json_body {
                b = b
                    .header(CONTENT_TYPE, "application/json")
                    .body(body.clone());
            }
            let Ok(request) = b.build() else {
                return failed(FetchFailure::OriginGuardRefused);
            };

            // Step 3: from here on the request counts as sent (a cancel during connect reports an
            // empty in-flight capture, the safe over-report direction).
            ctl.clear_partial();
            ctl.mark_sent();
            let executed = tokio::select! {
                biased;
                () = ctl.cancelled() => return cancelled(ctl),
                () = sleep_until(deadline) => {
                    return failed(FetchFailure::PostSend { kind: deadline_kind, received: Vec::new() });
                }
                r = self.http.execute(request) => r,
            };
            let resp = match executed {
                Ok(r) => r,
                Err(e) => {
                    // Only a connector error is pre-send; an I/O timeout after the request was
                    // written (`is_timeout()` without `is_connect()`) may have reached the server.
                    let flags = ConnFlags {
                        timeout: e.is_timeout(),
                        dns: e.is_dns(),
                    };
                    return failed(match execute_error_class(&e, e.is_connect(), flags) {
                        Some(class) => FetchFailure::PreSendConnection(class),
                        None => FetchFailure::PostSend {
                            kind: PostSendKind::NetworkError,
                            received: Vec::new(),
                        },
                    });
                }
            };

            // Step 4: report `Date` and remember rate-limit pacing, for every response.
            self.observe_response(resp.headers());

            // Step 5: bounded 429 retries; the permit is not held while waiting.
            if resp.status().as_u16() == 429 && retries < MAX_429_RETRIES {
                let wait =
                    retry_after_wait(header_text(resp.headers(), RETRY_AFTER), SystemTime::now());
                let until = Instant::now() + wait;
                if req.overall.is_none_or(|(end, _)| until < end) {
                    drop(resp);
                    drop(permit);
                    retries += 1;
                    tokio::select! {
                        biased;
                        () = ctl.cancelled() => return cancelled(ctl),
                        () = sleep_until(until) => {}
                    }
                    continue;
                }
            }

            let outcome = self
                .finish(resp, &req, &cred, ctl, deadline, deadline_kind)
                .await;
            drop(permit);
            return outcome;
        }
    }

    fn observe_response(&self, headers: &HeaderMap) {
        if let Some(date) =
            header_text(headers, DATE).and_then(|v| httpdate::parse_http_date(v).ok())
        {
            self.dates
                .observe(&self.cfg.instance_id, date, std::time::Instant::now());
        }
        self.limiter.observe(headers);
    }

    /// Steps 6 to 10 for the response that is not retried.
    async fn finish(
        &self,
        resp: reqwest::Response,
        req: &OneRequest<'_>,
        cred: &StoredCredential,
        ctl: &FetchControl,
        deadline: Instant,
        deadline_kind: PostSendKind,
    ) -> FetchOutcome {
        let status = resp.status().as_u16();
        let content_type = header_text(resp.headers(), CONTENT_TYPE).map(str::to_owned);
        let json = is_json_content_type(content_type.as_deref());
        let success = (200..300).contains(&status);
        let auser: Vec<String> = resp
            .headers()
            .get_all("x-ausername")
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect();
        let response = |body: Vec<u8>| UpstreamResponse {
            status,
            content_type: content_type.clone(),
            body,
        };

        // Step 6: decided from status and headers alone; the body is read for the audit record
        // only (caps apply, read errors and the deadline just end it).
        let header_decided = if (300..400).contains(&status) {
            Some(UnavailableReason::Redirect3xx)
        } else if success && !json {
            Some(UnavailableReason::NonJson2xx)
        } else if status == 401 && !json {
            Some(UnavailableReason::NonJson401)
        } else {
            None
        };

        // Step 7: the body.
        let read = read_body(resp, ctl, deadline, req.max_response_bytes).await;
        if let Some(reason) = header_decided {
            return match read {
                BodyRead::Cancelled => cancelled(ctl),
                _ => failed(FetchFailure::StatusHeaderDecided {
                    reason,
                    response: response(ctl.take_partial()),
                }),
            };
        }
        match read {
            BodyRead::Complete => {}
            BodyRead::Cancelled => return cancelled(ctl),
            BodyRead::Deadline => {
                return failed(FetchFailure::PostSend {
                    kind: deadline_kind,
                    received: ctl.take_partial(),
                });
            }
            BodyRead::OverCap => {
                return failed(FetchFailure::PostSend {
                    kind: PostSendKind::ResponseCap32MiB,
                    received: ctl.take_partial(),
                });
            }
            // Review Focus 2: once a JSON 2xx was seen, a failure is body-decided (gated).
            BodyRead::Error if success && json => {
                return failed(FetchFailure::BodyDecided {
                    kind: BodyFailure::ReadError,
                    response: response(ctl.take_partial()),
                });
            }
            BodyRead::Error => {
                return failed(FetchFailure::PostSend {
                    kind: PostSendKind::NetworkError,
                    received: ctl.take_partial(),
                });
            }
        }
        let body = ctl.take_partial();

        // Step 8: a JSON 2xx must parse; an error status that does not is still content (§11.2).
        if json && success && serde_json::from_slice::<serde::de::IgnoredAny>(&body).is_err() {
            return failed(FetchFailure::BodyDecided {
                kind: BodyFailure::ParseFailure,
                response: response(body),
            });
        }

        // Step 9: Jira identity check on every JSON response, error statuses included.
        if self.cfg.product == Product::Jira
            && json
            && let Err(observed) = check_jira_header(&auser, &cred.identity.atlassian_user)
        {
            return failed(FetchFailure::IdentityCheckFailed {
                observed,
                response: response(body),
            });
        }

        // Step 10.
        FetchOutcome::Response(response(body))
    }
}

/// Appends every chunk to the control's shared buffer until the end, the cap, the deadline, a
/// read error or a cancel; the bytes stay in the control.
async fn read_body(
    mut resp: reqwest::Response,
    ctl: &FetchControl,
    deadline: Instant,
    cap: u64,
) -> BodyRead {
    loop {
        let next = tokio::select! {
            biased;
            () = ctl.cancelled() => return BodyRead::Cancelled,
            () = sleep_until(deadline) => return BodyRead::Deadline,
            c = resp.chunk() => c,
        };
        match next {
            Ok(Some(chunk)) => {
                let len = ctl.append_partial(&chunk);
                if u64::try_from(len).unwrap_or(u64::MAX) > cap {
                    return BodyRead::OverCap;
                }
            }
            Ok(None) => return BodyRead::Complete,
            Err(_) => return BodyRead::Error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_budget(overall: Option<(Instant, PostSendKind)>) -> OneRequest<'static> {
        OneRequest {
            method: reqwest::Method::GET,
            template: "/rest/api/2/myself",
            params: &serde_json::Value::Null,
            query: &[],
            json_body: None,
            mode: SendMode::Read,
            overall,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }

    #[test]
    fn budget_expiry_before_send_is_presend() {
        let req = with_budget(Some((Instant::now(), PostSendKind::ReadBudget120s)));
        let ctl = FetchControl::new();
        assert_eq!(
            budget_expired(&ctl, &req),
            FetchOutcome::Failed(FetchFailure::BudgetExpiredBeforeSend)
        );
        // An earlier attempt of the call (a retried 429) was sent: post-send.
        ctl.mark_sent();
        assert_eq!(
            budget_expired(&ctl, &req),
            FetchOutcome::Failed(FetchFailure::PostSend {
                kind: PostSendKind::ReadBudget120s,
                received: Vec::new(),
            })
        );
    }
}

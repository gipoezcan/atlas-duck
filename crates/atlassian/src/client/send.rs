//! One request (§7.2, plan Task 9 "Classification algorithm"; the step numbers below are the
//! plan's): guards, limiter, `429` retries, deadlines, classification, body reading with the
//! per-response cap and cancel capture, `Date` reporting and the Jira identity check.
//!
//! Steps 1 to 5 (`exchange`) are shared by reads and approved writes; steps 6 to 10 (`finish`)
//! classify a read response, `write.rs` classifies a write response.

use std::time::{Duration, SystemTime};

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, DATE, HeaderMap, HeaderValue, RETRY_AFTER};
use tokio::sync::SemaphorePermit;
use tokio::time::{Instant, sleep_until};
use zeroize::Zeroizing;

use super::classify::{ConnFlags, execute_error_class, is_json_content_type, retry_after_wait};
use super::limiter::Acquired;
use super::{FetchControl, InstanceClient, Product, Timeouts};
use crate::cover::AuditCover;
use crate::credentials::{PatSecret, StoredCredential};
use crate::guard::{Outgoing, SendMode, method_guard};
use crate::identity::check_jira_header;
use crate::origin::origin_guard;
use crate::types::{
    BodyFailure, FetchFailure, FetchOutcome, HttpRequestSpec, PostSendKind, UnavailableReason,
    UpstreamResponse,
};
use crate::url::build_url;

/// §7.2: 32 MiB per HTTP response.
pub(crate) const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
/// §7.2: at most 3 retries of a `429`.
const MAX_429_RETRIES: u32 = 3;

/// What one call writes.
pub(crate) enum Target<'a> {
    /// A read: `GET`, or the allowlisted search `POST`, built from an endpoint template under the
    /// base URL.
    Template {
        method: reqwest::Method,
        template: &'a str,
        params: &'a serde_json::Value,
        query: &'a [(String, String)],
        /// Sent with `Content-Type: application/json`.
        json_body: Option<Vec<u8>>,
    },
    /// One approved write request, written exactly as listed (§5.1 invariant 3).
    Approved(&'a HttpRequestSpec),
}

impl Target<'_> {
    fn mode(&self) -> SendMode<'_> {
        match self {
            Target::Template { template, .. } => SendMode::Read {
                path_template: template,
            },
            Target::Approved(spec) => SendMode::ApprovedWrite(spec),
        }
    }

    /// §7.2: 30 s per HTTP call, 60 s per write.
    fn per_call(&self, t: &Timeouts) -> Duration {
        match self {
            Target::Template { .. } => t.per_call,
            Target::Approved(_) => t.write,
        }
    }
}

pub(crate) struct OneRequest<'a> {
    pub(crate) target: Target<'a>,
    /// The call's overall budget and the class its expiry gets (the 120 s read budget, the 60 s
    /// write budget); `None` = only the per-call deadline of each attempt.
    pub(crate) overall: Option<(Instant, PostSendKind)>,
    pub(crate) max_response_bytes: u64,
    /// The class of a body over `max_response_bytes`: `ResponseCap32MiB`, or `FetchCap50MiB`
    /// when the rest of a paginated read's fetch budget is the smaller limit.
    pub(crate) cap_kind: PostSendKind,
}

/// A response whose status and headers arrived, before its body was read (steps 1 to 5 done).
pub(crate) struct Exchange<'c> {
    pub(crate) resp: reqwest::Response,
    /// Held until the body has been read.
    pub(crate) permit: SemaphorePermit<'c>,
    pub(crate) cred: StoredCredential,
    pub(crate) deadline: Instant,
    pub(crate) deadline_kind: PostSendKind,
}

pub(crate) enum BodyRead {
    Complete,
    Cancelled,
    Deadline,
    OverCap,
    Error,
}

fn failed(f: FetchFailure) -> FetchOutcome {
    FetchOutcome::Failed(f)
}

/// §5.2 step 3: before this call handed a request to the connection nothing left; after it,
/// whatever arrived so far is reported. `sent` is this call's own flag: the control's flag is
/// sticky across calls (and stays set after a pre-send connection failure).
pub(crate) fn cancelled(ctl: &FetchControl, sent: bool) -> FetchFailure {
    if sent {
        FetchFailure::CancelledInFlight {
            bytes_received: ctl.snapshot_partial(),
        }
    } else {
        FetchFailure::CancelledBeforeSend
    }
}

/// The overall budget ran out before an attempt was handed to the connection. If an earlier
/// attempt of this call was sent (a retried 429), the expiry is post-send.
fn budget_expired(sent: bool, overall: Option<(Instant, PostSendKind)>) -> FetchFailure {
    match overall {
        Some((_, kind)) if sent => FetchFailure::PostSend {
            kind,
            received: Vec::new(),
        },
        _ => FetchFailure::BudgetExpiredBeforeSend,
    }
}

/// The header value is marked sensitive; the formatted copy is zeroized.
fn bearer(pat: &PatSecret) -> Option<HeaderValue> {
    let text = Zeroizing::new(format!("Bearer {}", pat.expose_secret()));
    let mut v = HeaderValue::from_str(&text).ok()?;
    v.set_sensitive(true);
    Some(v)
}

pub(crate) fn header_text(
    headers: &HeaderMap,
    name: impl reqwest::header::AsHeaderName,
) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Every `X-AUSERNAME` value (lossy UTF-8), in order.
pub(crate) fn ausernames(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all("x-ausername")
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .collect()
}

/// The method guard (§5.1 invariant 3) on the request exactly as it will be written.
fn guard(mode: &SendMode<'_>, request: &reqwest::Request) -> Result<(), FetchFailure> {
    let content_types: Vec<&[u8]> = request
        .headers()
        .get_all(CONTENT_TYPE)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    let out = Outgoing {
        method: request.method().as_str(),
        url: request.url().as_str(),
        content_types: &content_types,
        body: request.body().and_then(reqwest::Body::as_bytes),
    };
    method_guard(mode, &out).map_err(|_| FetchFailure::MethodGuardRefused)
}

const X_ATLASSIAN_TOKEN: &str = "X-Atlassian-Token";

impl InstanceClient {
    pub(crate) async fn send_one(
        &self,
        cover: &AuditCover,
        req: OneRequest<'_>,
        ctl: &FetchControl,
    ) -> FetchOutcome {
        let ex = match self.exchange(cover, &req, ctl).await {
            Ok(ex) => ex,
            Err(f) => return failed(f),
        };
        let Exchange {
            resp,
            permit,
            cred,
            deadline,
            deadline_kind,
        } = ex;
        let outcome = self
            .finish(resp, &req, &cred, ctl, deadline, deadline_kind)
            .await;
        drop(permit);
        outcome
    }

    /// The request exactly as it will be written, without `Authorization` (added per attempt
    /// once the origin guard passed).
    fn build_request(&self, target: &Target<'_>) -> Result<reqwest::Request, FetchFailure> {
        match target {
            Target::Template {
                method,
                template,
                params,
                query,
                json_body,
            } => {
                // A URL that cannot be built under the base is refused like an origin mismatch.
                fn refused<E>(_: E) -> FetchFailure {
                    FetchFailure::OriginGuardRefused
                }
                let url = build_url(&self.cfg.base, template, params, query).map_err(refused)?;
                let mut b = self.http.request(method.clone(), url);
                if *method != reqwest::Method::GET {
                    b = b.header(X_ATLASSIAN_TOKEN, "no-check");
                }
                if let Some(body) = json_body {
                    b = b
                        .header(CONTENT_TYPE, "application/json")
                        .body(body.clone());
                }
                b.build().map_err(refused)
            }
            Target::Approved(spec) => {
                // Whatever cannot be written exactly as listed is a mismatch; nothing leaves.
                fn refused<E>(_: E) -> FetchFailure {
                    FetchFailure::MethodGuardRefused
                }
                let method =
                    reqwest::Method::from_bytes(spec.method.as_bytes()).map_err(refused)?;
                let url = url::Url::parse(&spec.resolved_url).map_err(refused)?;
                let mut b = self.http.request(method.clone(), url);
                if method != reqwest::Method::GET {
                    b = b.header(X_ATLASSIAN_TOKEN, "no-check");
                }
                if let Some(ct) = &spec.content_type {
                    b = b.header(CONTENT_TYPE, HeaderValue::from_str(ct).map_err(refused)?);
                }
                // Always a body, an empty one included, so the guard compares bytes, not presence.
                b.body(spec.body.clone()).build().map_err(refused)
            }
        }
    }

    /// Steps 1 to 5: guards, limiter, send, `Date`, `429` retries. Every `Err` is a complete
    /// failure; `Ok` holds the response that is not retried, its body unread.
    pub(crate) async fn exchange(
        &self,
        cover: &AuditCover,
        req: &OneRequest<'_>,
        ctl: &FetchControl,
    ) -> Result<Exchange<'_>, FetchFailure> {
        // Holding a cover is the proof of a committed start record (§5.1 inv. 1).
        let _ = cover;
        let mode = req.target.mode();

        // Step 1: the request as it will be written, the method guard on it, the credential, the
        // origin guard. Nothing leaves on a refusal.
        let prepared = self.build_request(&req.target)?;
        guard(&mode, &prepared)?;
        // A keychain error fails closed as well; its state is `core`'s concern.
        let Ok(Some(cred)) = self.creds.load(&self.cfg.instance_id) else {
            return Err(FetchFailure::NeedsToken);
        };
        if origin_guard(prepared.url(), &self.cfg.base, &cred.base_url_hash).is_err() {
            return Err(FetchFailure::OriginGuardRefused);
        }
        // A stored PAT that cannot be a header value is unusable.
        let Some(auth) = bearer(&cred.pat) else {
            return Err(FetchFailure::NeedsToken);
        };
        let per_call = req.target.per_call(&self.cfg.timeouts);

        // Whether this call handed a request to the connection.
        let mut sent = false;
        let mut retries = 0;
        loop {
            // Step 2: limiter permit (cancel-aware, bounded by the overall budget).
            let permit = match self
                .limiter
                .acquire(ctl, req.overall.map(|(end, _)| end))
                .await
            {
                Acquired::Permit(p) => p,
                Acquired::Cancelled => return Err(cancelled(ctl, sent)),
                Acquired::Expired => return Err(budget_expired(sent, req.overall)),
            };
            let now = Instant::now();
            let mut deadline = now + per_call;
            let mut deadline_kind = PostSendKind::PerCallTimeout;
            if let Some((end, kind)) = req.overall {
                if now >= end {
                    return Err(budget_expired(sent, req.overall));
                }
                if end < deadline {
                    deadline = end;
                    deadline_kind = kind;
                }
            }
            // Every attempt writes a copy of the guarded request; the Authorization header
            // exists only on it (never a default header), and the guard runs again on the very
            // request handed to the connection.
            let Some(mut request) = prepared.try_clone() else {
                return Err(FetchFailure::MethodGuardRefused);
            };
            request.headers_mut().insert(AUTHORIZATION, auth.clone());
            guard(&mode, &request)?;

            // Step 3: from here on the request counts as sent (a cancel during connect reports an
            // empty in-flight capture, the safe over-report direction).
            ctl.clear_partial();
            ctl.mark_sent();
            sent = true;
            let executed = tokio::select! {
                biased;
                () = ctl.cancelled() => return Err(cancelled(ctl, sent)),
                () = sleep_until(deadline) => {
                    return Err(FetchFailure::PostSend { kind: deadline_kind, received: Vec::new() });
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
                    return Err(match execute_error_class(&e, e.is_connect(), flags) {
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
                        () = ctl.cancelled() => return Err(cancelled(ctl, sent)),
                        () = sleep_until(until) => {}
                    }
                    continue;
                }
            }

            return Ok(Exchange {
                resp,
                permit,
                cred,
                deadline,
                deadline_kind,
            });
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

    /// Steps 6 to 10 for the read response that is not retried.
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
        let auser = ausernames(resp.headers());
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
                BodyRead::Cancelled => failed(cancelled(ctl, true)),
                _ => failed(FetchFailure::StatusHeaderDecided {
                    reason,
                    response: response(ctl.take_partial()),
                }),
            };
        }
        match read {
            BodyRead::Complete => {}
            BodyRead::Cancelled => return failed(cancelled(ctl, true)),
            BodyRead::Deadline => {
                return failed(FetchFailure::PostSend {
                    kind: deadline_kind,
                    received: ctl.take_partial(),
                });
            }
            BodyRead::OverCap => {
                return failed(FetchFailure::PostSend {
                    kind: req.cap_kind,
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
pub(crate) async fn read_body(
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

    #[test]
    fn budget_expiry_before_send_is_presend() {
        let overall = Some((Instant::now(), PostSendKind::ReadBudget120s));
        assert_eq!(
            budget_expired(false, overall),
            FetchFailure::BudgetExpiredBeforeSend
        );
        // An earlier attempt of the call (a retried 429) was sent: post-send.
        assert_eq!(
            budget_expired(true, overall),
            FetchFailure::PostSend {
                kind: PostSendKind::ReadBudget120s,
                received: Vec::new(),
            }
        );
    }

    #[test]
    fn cancel_before_this_call_sent_is_presend() {
        // The control's flag may be set by an earlier call; only this call's flag decides.
        let ctl = FetchControl::new();
        ctl.mark_sent();
        assert_eq!(cancelled(&ctl, false), FetchFailure::CancelledBeforeSend);
        ctl.append_partial(b"ab");
        assert_eq!(
            cancelled(&ctl, true),
            FetchFailure::CancelledInFlight {
                bytes_received: b"ab".to_vec()
            }
        );
    }
}

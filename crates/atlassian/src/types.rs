//! Request and response types shared with `core` (C.4, amended by PD-07).
//!
//! `Debug` on everything that can hold request or response data prints status, method, content
//! type and lengths only, never a URL, query, body or params (§7.7).

use std::fmt;
use std::time::Duration;

/// One outgoing write request, the five §5.1 invariant 3 fields.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequestSpec {
    pub index: u32,
    pub method: String,
    pub resolved_url: String,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpRequestSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequestSpec")
            .field("index", &self.index)
            .field("method", &self.method)
            .field("content_type", &self.content_type)
            .field("body", &format_args!("len={}", self.body.len()))
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectedBody {
    Json,
    Empty,
}

/// `core` copies it from the registry `SuccessShape`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessExpectation {
    /// `None` = any 2xx.
    pub statuses: Option<Vec<u16>>,
    pub body: ExpectedBody,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedWrite {
    pub requests: Vec<HttpRequestSpec>,
    pub success: SuccessExpectation,
}

/// `core` copies the template string from registry data.
#[derive(Clone, PartialEq)]
pub struct GetCall {
    pub endpoint_template: String,
    /// Values for the template's `{name}` placeholders only (`build_url`).
    pub params: serde_json::Value,
    /// Query pairs in send order (Task 9 addition, Δ C.4); pagination appends its own.
    pub query: Vec<(String, String)>,
}

impl fmt::Debug for GetCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GetCall")
            .field("endpoint_template", &self.endpoint_template)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PagedCall {
    pub get: GetCall,
    pub items_key: String,
    pub offset_param: String,
    pub limit_param: String,
    pub page_size: u32,
    /// The agent's `start`.
    pub start: u64,
}

/// The `jira.search` request body.
#[derive(Clone, PartialEq)]
pub struct SearchCall {
    pub endpoint_template: String,
    pub body: serde_json::Value,
}

impl fmt::Debug for SearchCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SearchCall")
            .field("endpoint_template", &self.endpoint_template)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadBudget {
    pub total: Duration,
    pub max_bytes: u64,
    pub max_response_bytes: u64,
}

impl Default for ReadBudget {
    fn default() -> Self {
        ReadBudget {
            total: Duration::from_secs(120),
            max_bytes: 50 * 1024 * 1024,
            max_response_bytes: 32 * 1024 * 1024,
        }
    }
}

/// `atlassian` consumes `Retry-After`, `Date` and `X-AUSERNAME` itself and drops other headers.
#[derive(Clone, PartialEq, Eq)]
pub struct UpstreamResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

impl fmt::Debug for UpstreamResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamResponse")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("body", &format_args!("len={}", self.body.len()))
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchOutcome {
    Response(UpstreamResponse),
    Failed(FetchFailure),
}

/// What an unauthorised or unusable answer looked like (§7.2 identity check).
#[derive(Clone, PartialEq, Eq)]
pub enum IdentityObserved {
    Missing,
    Anonymous,
    Other(String),
}

/// A server-supplied username never appears in `Debug` output (§7.7); only its length does.
pub(crate) fn redacted_name(name: &str) -> String {
    format!("<redacted:{} chars>", name.chars().count())
}

fn redacted_opt(name: &Option<String>) -> Option<String> {
    name.as_deref().map(redacted_name)
}

impl fmt::Debug for IdentityObserved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityObserved::Missing => f.write_str("Missing"),
            IdentityObserved::Anonymous => f.write_str("Anonymous"),
            IdentityObserved::Other(n) => write!(f, "Other({})", redacted_name(n)),
        }
    }
}

/// Failed before any byte of the request left (§11.2 picks the hint from the class).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnClass {
    Dns,
    Connect,
    ConnectTimeout,
    TlsHandshake,
    TlsUnknownIssuer,
    TlsCertificate,
    ProxyConnect,
    ProxyConnect407,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnavailableReason {
    Redirect3xx,
    NonJson2xx,
    NonJson401,
    IdentityHeaderMissing,
    IdentityHeaderMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyFailure {
    ParseFailure,
    ReadError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostSendKind {
    PerCallTimeout,
    NetworkError,
    ResponseCap32MiB,
    FetchCap50MiB,
    ReadBudget120s,
}

/// The §7.2 / §11.2 classes. Every variant that received bytes carries them (PD-07).
#[derive(Clone, PartialEq, Eq)]
pub enum FetchFailure {
    PreSendConnection(ConnClass),
    StatusHeaderDecided {
        reason: UnavailableReason,
        /// Audit-only body.
        response: UpstreamResponse,
    },
    BodyDecided {
        kind: BodyFailure,
        response: UpstreamResponse,
    },
    PostSend {
        kind: PostSendKind,
        received: Vec<u8>,
    },
    OriginGuardRefused,
    /// Jira only (§7.2): checked on every JSON response, so `response.status` can be 401 (a JSON
    /// 401 normally says `anonymous`) or 429. Core distinguishes a JSON 401 from a header
    /// mismatch by the status before the §7.1 recheck branches.
    IdentityCheckFailed {
        observed: IdentityObserved,
        response: UpstreamResponse,
    },
    CancelledInFlight {
        bytes_received: Vec<u8>,
    },
    CancelledBeforeSend,
    /// The call's overall budget (Task 10: read budget or write timeout) ran out in the limiter
    /// or pacing wait before any request of the call was handed to the connection: nothing left,
    /// data-free (Task 9 review, Δ C.4). Once a request of the call was sent, an expiry is
    /// `PostSend` with the budget's kind.
    BudgetExpiredBeforeSend,
    NeedsToken,
    MethodGuardRefused,
}

impl fmt::Debug for FetchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = |b: &Vec<u8>| format!("len={}", b.len());
        match self {
            FetchFailure::PreSendConnection(c) => {
                f.debug_tuple("PreSendConnection").field(c).finish()
            }
            FetchFailure::StatusHeaderDecided { reason, response } => f
                .debug_struct("StatusHeaderDecided")
                .field("reason", reason)
                .field("response", response)
                .finish(),
            FetchFailure::BodyDecided { kind, response } => f
                .debug_struct("BodyDecided")
                .field("kind", kind)
                .field("response", response)
                .finish(),
            FetchFailure::PostSend { kind, received } => f
                .debug_struct("PostSend")
                .field("kind", kind)
                .field("received", &format_args!("{}", len(received)))
                .finish(),
            FetchFailure::OriginGuardRefused => f.write_str("OriginGuardRefused"),
            FetchFailure::IdentityCheckFailed { observed, response } => f
                .debug_struct("IdentityCheckFailed")
                .field("observed", observed)
                .field("response", response)
                .finish(),
            FetchFailure::CancelledInFlight { bytes_received } => f
                .debug_struct("CancelledInFlight")
                .field("bytes_received", &format_args!("{}", len(bytes_received)))
                .finish(),
            FetchFailure::CancelledBeforeSend => f.write_str("CancelledBeforeSend"),
            FetchFailure::BudgetExpiredBeforeSend => f.write_str("BudgetExpiredBeforeSend"),
            FetchFailure::NeedsToken => f.write_str("NeedsToken"),
            FetchFailure::MethodGuardRefused => f.write_str("MethodGuardRefused"),
        }
    }
}

/// How a paginated read ended (§7.2, §7.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageEnd {
    /// The server reported the end of the results (`next_start` is `None`).
    ResultsEnded,
    /// `max_items` reached before the results ended.
    MaxReached,
    /// The 50 MiB fetch cap (`ReadBudget.max_bytes`) was exceeded during a page.
    FetchCap50MiB,
    /// The read budget (`ReadBudget.total`, all pages and 429 waits) ran out.
    ReadBudget120s,
    /// Any other end: `failure` holds the failure, or, when `failure` is `None`, the last entry
    /// of `pages` is the non-2xx response (an upstream error, a final 429) that ended paging.
    Failed,
}

/// Every page a paginated read fetched (Task 10). `next_start` is the server-arithmetic
/// continuation (§7.5): `None` only when the server reported the end of the results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PagedOutcome {
    /// Every complete page, in order (for `READ_FETCHED`); see `PageEnd::Failed`.
    pub pages: Vec<UpstreamResponse>,
    /// Items across the 2xx pages, before redaction.
    pub items_fetched: u64,
    pub end: PageEnd,
    /// The failure that ended paging early, if any, with its received bytes inside.
    pub failure: Option<FetchFailure>,
    pub next_start: Option<u64>,
    /// `total` (Jira) or `totalSize` (Confluence search) of the last 2xx page, if reported.
    pub server_total: Option<u64>,
}

/// Why nothing of an approved write left (Δ C.4, Task 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotSentReason {
    /// A connection-level failure before any byte was written, after the one retry (§5.4 step 6).
    Connection(ConnClass),
    /// The 60 s write budget ran out in the limiter or rate-limit wait.
    BudgetExpired,
    /// The control was cancelled before the request was handed to the connection.
    Cancelled,
}

#[derive(Clone, PartialEq, Eq)]
pub enum UnknownReason {
    Timeout,
    ResetAfterSend,
    ServerError5xx,
    UndeclaredSuccess,
    IdentityMismatch {
        server_user: Option<String>,
    },
    /// The control was cancelled after the request was handed to the connection (additive,
    /// Task 10).
    Cancelled,
}

impl fmt::Debug for UnknownReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnknownReason::Timeout => f.write_str("Timeout"),
            UnknownReason::ResetAfterSend => f.write_str("ResetAfterSend"),
            UnknownReason::ServerError5xx => f.write_str("ServerError5xx"),
            UnknownReason::UndeclaredSuccess => f.write_str("UndeclaredSuccess"),
            UnknownReason::IdentityMismatch { server_user } => f
                .debug_struct("IdentityMismatch")
                .field("server_user", &redacted_opt(server_user))
                .finish(),
            UnknownReason::Cancelled => f.write_str("Cancelled"),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    Executed {
        response: UpstreamResponse,
        server_user: Option<String>,
        request_index: u32,
    },
    Failed4xx {
        response: UpstreamResponse,
        request_index: u32,
    },
    Unavailable3xx {
        request_index: u32,
    },
    VersionConflict {
        request_index: u32,
    },
    OutcomeUnknown {
        reason: UnknownReason,
        request_index: u32,
    },
    NeedsToken,
    OriginGuardRefused,
    /// An outgoing request differed from its list entry; nothing was written.
    RefusedMismatch {
        request_index: u32,
    },
    /// Nothing of the request left (Δ C.4, Task 10: the reason replaces the bare `ConnClass`).
    NotSent {
        reason: NotSentReason,
    },
}

impl fmt::Debug for WriteOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteOutcome::Executed {
                response,
                server_user,
                request_index,
            } => f
                .debug_struct("Executed")
                .field("response", response)
                .field("server_user", &redacted_opt(server_user))
                .field("request_index", request_index)
                .finish(),
            WriteOutcome::Failed4xx {
                response,
                request_index,
            } => f
                .debug_struct("Failed4xx")
                .field("response", response)
                .field("request_index", request_index)
                .finish(),
            WriteOutcome::Unavailable3xx { request_index } => f
                .debug_struct("Unavailable3xx")
                .field("request_index", request_index)
                .finish(),
            WriteOutcome::VersionConflict { request_index } => f
                .debug_struct("VersionConflict")
                .field("request_index", request_index)
                .finish(),
            WriteOutcome::OutcomeUnknown {
                reason,
                request_index,
            } => f
                .debug_struct("OutcomeUnknown")
                .field("reason", reason)
                .field("request_index", request_index)
                .finish(),
            WriteOutcome::NeedsToken => f.write_str("NeedsToken"),
            WriteOutcome::OriginGuardRefused => f.write_str("OriginGuardRefused"),
            WriteOutcome::RefusedMismatch { request_index } => f
                .debug_struct("RefusedMismatch")
                .field("request_index", request_index)
                .finish(),
            WriteOutcome::NotSent { reason } => {
                f.debug_struct("NotSent").field("reason", reason).finish()
            }
        }
    }
}

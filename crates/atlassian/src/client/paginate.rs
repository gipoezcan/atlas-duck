//! Offset pagination (§7.2, §7.5). Every page is rebuilt from the op's own endpoint template (or
//! the search body template) under the configured base URL; `_links.next` is never read. The
//! page arithmetic is the server's: Confluence `start += size`, Jira `startAt += returned items`.

use serde_json::Value;
use tokio::time::Instant;

use super::send::{OneRequest, Target};
use super::{FetchControl, InstanceClient, Product};
use crate::cover::AuditCover;
use crate::types::{
    FetchFailure, FetchOutcome, PageEnd, PagedCall, PagedOutcome, PostSendKind, ReadBudget,
    SearchCall,
};

/// `jira.search` when its body names no page size.
const DEFAULT_SEARCH_PAGE_SIZE: u64 = 50;

/// Where the pages come from.
enum PageSource<'a> {
    Get(&'a PagedCall),
    /// `POST /rest/api/2/search`: `startAt`/`maxResults` are rewritten in the body per page.
    Search {
        call: &'a SearchCall,
        items_key: &'a str,
    },
}

/// What one 2xx page says about the results.
struct PageFacts {
    /// Items in the page's `items_key` array.
    items: u64,
    /// Confluence `size`.
    size: Option<u64>,
    /// `limit` (Confluence) or `maxResults` (Jira): the page size the server applied.
    limit: Option<u64>,
    /// `total` (Jira) or `totalSize` (Confluence search).
    total: Option<u64>,
    is_last: Option<bool>,
}

impl PageFacts {
    fn read(body: &[u8], items_key: &str) -> PageFacts {
        // `send_one` only returns a 2xx JSON body that parsed; a body without the items array
        // counts as zero items, which ends the results.
        let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let num = |k: &str| v.get(k).and_then(Value::as_u64);
        PageFacts {
            items: v
                .get(items_key)
                .and_then(Value::as_array)
                .map_or(0, |a| u64::try_from(a.len()).unwrap_or(u64::MAX)),
            size: num("size"),
            limit: num("limit").or_else(|| num("maxResults")),
            total: num("total").or_else(|| num("totalSize")),
            is_last: v.get("isLast").and_then(Value::as_bool),
        }
    }
}

impl InstanceClient {
    /// `read_paginated_ctl` with a fresh control and no item limit (until the results end or a
    /// cap or the budget stops it).
    pub async fn read_paginated(
        &self,
        cover: &AuditCover,
        call: &PagedCall,
        budget: &ReadBudget,
    ) -> PagedOutcome {
        self.read_paginated_ctl(cover, call, budget, u64::MAX, &FetchControl::new())
            .await
    }

    /// Pages from `call.start` up to `max_items` items (§5.2 step 2). Every completed page is also
    /// kept in the control (`take_captured().pages`).
    pub async fn read_paginated_ctl(
        &self,
        cover: &AuditCover,
        call: &PagedCall,
        budget: &ReadBudget,
        max_items: u64,
        ctl: &FetchControl,
    ) -> PagedOutcome {
        self.paginate(cover, PageSource::Get(call), budget, max_items, ctl)
            .await
    }

    /// `jira.search` pagination: the one allowlisted read `POST`, its body's `startAt` and
    /// `maxResults` rebuilt per page from the call's body (they also give the first page's offset
    /// and the page size, 0 and 50 when absent). Jira arithmetic: `startAt += returned items`.
    pub async fn read_paginated_search_ctl(
        &self,
        cover: &AuditCover,
        call: &SearchCall,
        items_key: &str,
        budget: &ReadBudget,
        max_items: u64,
        ctl: &FetchControl,
    ) -> PagedOutcome {
        let source = PageSource::Search { call, items_key };
        self.paginate(cover, source, budget, max_items, ctl).await
    }

    async fn paginate(
        &self,
        cover: &AuditCover,
        source: PageSource<'_>,
        budget: &ReadBudget,
        max_items: u64,
        ctl: &FetchControl,
    ) -> PagedOutcome {
        // One deadline for all pages and every 429 wait (§7.2: 120 s per read request).
        let deadline = Instant::now() + budget.total;
        let (mut start, page_size, items_key, jira_arithmetic) = match &source {
            PageSource::Get(call) => (
                call.start,
                u64::from(call.page_size),
                call.items_key.as_str(),
                self.cfg.product == Product::Jira,
            ),
            PageSource::Search { call, items_key } => (
                call.body
                    .get("startAt")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                call.body
                    .get("maxResults")
                    .and_then(Value::as_u64)
                    .unwrap_or(DEFAULT_SEARCH_PAGE_SIZE),
                *items_key,
                true,
            ),
        };
        let mut out = PagedOutcome {
            pages: Vec::new(),
            items_fetched: 0,
            end: PageEnd::MaxReached,
            failure: None,
            next_start: Some(start),
            server_total: None,
        };
        let mut fetched_bytes: u64 = 0;
        // The page size the server applies (§7.2); lowered when it clamps a request.
        let mut page_limit = page_size.max(1);

        loop {
            if out.items_fetched >= max_items {
                out.end = PageEnd::MaxReached;
                out.next_start = Some(start);
                return out;
            }
            let want = (max_items - out.items_fetched).min(page_limit);
            // §7.2: 32 MiB per response, 50 MiB per paginated read; whichever is closer cuts.
            let left = budget.max_bytes.saturating_sub(fetched_bytes);
            let (cap, cap_kind) = if left < budget.max_response_bytes {
                (left, PostSendKind::FetchCap50MiB)
            } else {
                (budget.max_response_bytes, PostSendKind::ResponseCap32MiB)
            };
            let overall = Some((deadline, PostSendKind::ReadBudget120s));

            let outcome = match &source {
                PageSource::Get(call) => {
                    let mut query = call.get.query.clone();
                    query.push((call.offset_param.clone(), start.to_string()));
                    query.push((call.limit_param.clone(), want.to_string()));
                    let req = OneRequest {
                        target: Target::Template {
                            method: reqwest::Method::GET,
                            template: &call.get.endpoint_template,
                            params: &call.get.params,
                            query: &query,
                            json_body: None,
                        },
                        overall,
                        max_response_bytes: cap,
                        cap_kind,
                    };
                    self.send_one(cover, req, ctl).await
                }
                PageSource::Search { call, .. } => {
                    let mut body = call.body.clone();
                    // A body that is not an object has no page fields to rebuild.
                    let Some(obj) = body.as_object_mut() else {
                        return ended(out, start, FetchFailure::MethodGuardRefused);
                    };
                    obj.insert("startAt".to_owned(), start.into());
                    obj.insert("maxResults".to_owned(), want.into());
                    let Ok(bytes) = serde_json::to_vec(&body) else {
                        return ended(out, start, FetchFailure::MethodGuardRefused);
                    };
                    let req = OneRequest {
                        target: Target::Template {
                            method: reqwest::Method::POST,
                            template: &call.endpoint_template,
                            params: &Value::Null,
                            query: &[],
                            json_body: Some(bytes),
                        },
                        overall,
                        max_response_bytes: cap,
                        cap_kind,
                    };
                    self.send_one(cover, req, ctl).await
                }
            };

            let page = match outcome {
                FetchOutcome::Response(r) if (200..300).contains(&r.status) => r,
                // An upstream error (or the final 429) ends paging; it is the last page.
                FetchOutcome::Response(r) => {
                    ctl.push_page(r.clone());
                    out.pages.push(r);
                    out.end = PageEnd::Failed;
                    out.next_start = Some(start);
                    return out;
                }
                FetchOutcome::Failed(f) => return ended(out, start, f),
            };

            let facts = PageFacts::read(&page.body, items_key);
            fetched_bytes =
                fetched_bytes.saturating_add(u64::try_from(page.body.len()).unwrap_or(u64::MAX));
            ctl.push_page(page.clone());
            out.pages.push(page);
            out.items_fetched = out.items_fetched.saturating_add(facts.items);
            if facts.total.is_some() {
                out.server_total = facts.total;
            }
            let returned = if jira_arithmetic {
                facts.items
            } else {
                facts.size.unwrap_or(facts.items)
            };
            start = start.saturating_add(returned);

            // End-of-results signals (§7.2); `_links.next` is not one we read.
            let ended = facts.items == 0
                || returned == 0
                || facts.is_last == Some(true)
                || facts.limit.is_some_and(|l| returned < l)
                || facts.total.is_some_and(|t| start >= t);
            if ended {
                out.end = PageEnd::ResultsEnded;
                out.next_start = None;
                return out;
            }
            // The server clamped the page: ask for its size from now on.
            if let Some(l) = facts.limit.filter(|l| *l > 0 && *l < want) {
                page_limit = l;
            }
        }
    }
}

/// A failure ended paging; the continuation is where the last complete page ended.
fn ended(mut out: PagedOutcome, start: u64, failure: FetchFailure) -> PagedOutcome {
    let some_page_sent = !out.pages.is_empty();
    out.end = match &failure {
        FetchFailure::PostSend {
            kind: PostSendKind::ReadBudget120s,
            ..
        }
        | FetchFailure::BudgetExpiredBeforeSend => PageEnd::ReadBudget120s,
        FetchFailure::PostSend {
            kind: PostSendKind::FetchCap50MiB,
            ..
        } => PageEnd::FetchCap50MiB,
        _ => PageEnd::Failed,
    };
    // A page of this read was sent already, so for the read as a whole the expiry or cancel
    // is post-send (each page's `send_one` only knows about its own request).
    out.failure = Some(match failure {
        FetchFailure::BudgetExpiredBeforeSend if some_page_sent => FetchFailure::PostSend {
            kind: PostSendKind::ReadBudget120s,
            received: Vec::new(),
        },
        FetchFailure::CancelledBeforeSend if some_page_sent => FetchFailure::CancelledInFlight {
            bytes_received: Vec::new(),
        },
        f => f,
    });
    out.next_start = Some(start);
    out
}

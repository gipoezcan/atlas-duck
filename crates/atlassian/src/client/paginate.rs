//! Offset pagination (§7.2, §7.5). Every page is rebuilt from the op's own endpoint template (or
//! the search body template) under the configured base URL; `_links.next` is never read. The
//! page arithmetic is the server's: Confluence `start += size`, Jira `startAt += returned items`.

use std::fmt;

use serde::Deserialize;
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
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
#[derive(Default)]
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
    /// One pass over the body, no value tree (T10 minor 9): the items are counted as they go by,
    /// the five facts are read where they stand, everything else is skipped. `send_one` only
    /// returns a 2xx JSON body that parsed; a body without the items array counts as zero items,
    /// which ends the results. A fact of another type is absent, the last of a repeated key wins.
    ///
    /// Equal to the reading of a `serde_json::Value` on well-formed pages. On a malformed one that
    /// step 8 of `send_one` accepts (a lone surrogate, a byte that is not UTF-8 or nesting deeper
    /// than 128 inside an item) it is stricter and better: the items are counted, where the value
    /// tree failed and read as zero items, a silently truncated result. The parse of the body in
    /// `core` fails closed on such a page.
    fn read(body: &[u8], items_key: &str) -> PageFacts {
        let mut de = serde_json::Deserializer::from_slice(body);
        PageFactsSeed { items_key }
            .deserialize(&mut de)
            .ok()
            .filter(|_| de.end().is_ok())
            .unwrap_or_default()
    }
}

/// The page object with the name of its items array.
struct PageFactsSeed<'a> {
    items_key: &'a str,
}

impl<'de> DeserializeSeed<'de> for PageFactsSeed<'_> {
    type Value = PageFacts;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<PageFacts, D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for PageFactsSeed<'_> {
    type Value = PageFacts;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a page object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<PageFacts, A::Error> {
        let mut facts = PageFacts::default();
        let (mut limit, mut max_results) = (None, None);
        let (mut total, mut total_size) = (None, None);
        while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
            let leaf = map.next_value::<Leaf>()?;
            if key == self.items_key {
                // Not an array: no items (a key that is also a fact keeps both readings).
                facts.items = leaf.len.unwrap_or(0);
            }
            match key.as_ref() {
                "size" => facts.size = leaf.num,
                "limit" => limit = leaf.num,
                "maxResults" => max_results = leaf.num,
                "total" => total = leaf.num,
                "totalSize" => total_size = leaf.num,
                "isLast" => facts.is_last = leaf.flag,
                _ => {}
            }
        }
        facts.limit = limit.or(max_results);
        facts.total = total.or(total_size);
        Ok(facts)
    }
}

/// A value of the page object seen without building it: what `Value::as_u64`, `as_bool` and
/// `as_array().len()` would say of it. Containers are walked and dropped.
#[derive(Default)]
struct Leaf {
    num: Option<u64>,
    flag: Option<bool>,
    len: Option<u64>,
}

impl<'de> Deserialize<'de> for Leaf {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Leaf, D::Error> {
        d.deserialize_any(LeafVisitor)
    }
}

struct LeafVisitor;

impl<'de> Visitor<'de> for LeafVisitor {
    type Value = Leaf;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any value")
    }

    fn visit_u64<E>(self, v: u64) -> Result<Leaf, E> {
        Ok(Leaf {
            num: Some(v),
            ..Leaf::default()
        })
    }

    fn visit_i64<E>(self, v: i64) -> Result<Leaf, E> {
        Ok(Leaf {
            num: u64::try_from(v).ok(),
            ..Leaf::default()
        })
    }

    fn visit_bool<E>(self, v: bool) -> Result<Leaf, E> {
        Ok(Leaf {
            flag: Some(v),
            ..Leaf::default()
        })
    }

    fn visit_f64<E>(self, _: f64) -> Result<Leaf, E> {
        Ok(Leaf::default())
    }

    fn visit_str<E>(self, _: &str) -> Result<Leaf, E> {
        Ok(Leaf::default())
    }

    fn visit_unit<E>(self) -> Result<Leaf, E> {
        Ok(Leaf::default())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Leaf, A::Error> {
        let mut n: u64 = 0;
        while seq.next_element::<IgnoredAny>()?.is_some() {
            n = n.saturating_add(1);
        }
        Ok(Leaf {
            len: Some(n),
            ..Leaf::default()
        })
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Leaf, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Leaf::default())
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
                            cover,
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
                    self.send_one(req, ctl).await
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
                            cover,
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
                    self.send_one(req, ctl).await
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

            // End-of-results signals (§7.2); `_links.next` is not one we read. A page is short
            // against what was asked and what the server applies, whichever is smaller (V05: a
            // server may echo a larger page size than the request's).
            let ended = facts.items == 0
                || returned == 0
                || facts.is_last == Some(true)
                || facts.limit.is_some_and(|l| returned < l.min(want))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// What the page facts were while they came from a `serde_json::Value` of the body.
    fn by_value(body: &[u8], items_key: &str) -> PageFacts {
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

    #[test]
    fn facts_read_in_one_pass_equal_the_value_reading_on_well_formed_pages() {
        let bodies = [
            r#"{"results":[{"a":[1,2]},{"b":{"c":null}},3],"size":3,"limit":25,"totalSize":9,"start":0}"#,
            r#"{"values":[],"maxResults":50,"isLast":true,"total":0}"#,
            r#"{"issues":[1],"maxResults":-5,"total":2.5,"isLast":"yes"}"#,
            r#"{"limit":"25","maxResults":10,"total":{"x":[1]},"totalSize":7,"size":-1}"#,
            r#"{"results":{"not":"an array"},"size":1}"#,
            r#"{"results":[1,2],"results":[1],"size":1,"size":2}"#,
            r#"{"results":[1],"size":18446744073709551615,"total":18446744073709551616}"#,
            r#"{"isLast":false,"nested":{"results":[1,2,3],"size":9},"results":[7]}"#,
            r#"[1,2,3]"#,
            r#"null"#,
            r#""text""#,
            r#"{}"#,
            r#"{"results":[1]} trailing"#,
            "",
        ];
        for key in ["results", "values", "issues", "size"] {
            for body in bodies {
                let (got, want) = (
                    PageFacts::read(body.as_bytes(), key),
                    by_value(body.as_bytes(), key),
                );
                assert_eq!(
                    (got.items, got.size, got.limit, got.total, got.is_last),
                    (want.items, want.size, want.limit, want.total, want.is_last),
                    "{key} in {body}"
                );
            }
        }
    }

    /// T21 fix M3: pages that step 8 of `send_one` accepts but a `Value` does not parse. The old
    /// reading saw zero items (the results ended silently); the streaming one counts the items
    /// and reads the facts, in line with step 8 (`core` then fails closed on the body). None of
    /// them panics or overflows the stack, however deep the nesting.
    #[test]
    fn facts_of_malformed_pages_are_counted_not_dropped() {
        let tail = br#"],"isLast":false,"total":5}"#;
        let mut lone_surrogate = br#"{"values":[{"a":"\uD800"}"#.to_vec();
        lone_surrogate.extend_from_slice(tail);
        let mut raw_ff = br#"{"values":[{"a":""#.to_vec();
        raw_ff.push(0xFF);
        raw_ff.extend_from_slice(br#""}"#);
        raw_ff.extend_from_slice(tail);
        let mut deep = br#"{"values":["#.to_vec();
        deep.extend(std::iter::repeat_n(b'[', 200));
        deep.extend(std::iter::repeat_n(b']', 200));
        deep.extend_from_slice(tail);
        let mut very_deep = br#"{"values":["#.to_vec();
        very_deep.extend(std::iter::repeat_n(b'[', 200_000));
        very_deep.extend(std::iter::repeat_n(b']', 200_000));
        very_deep.extend_from_slice(tail);
        for (name, body) in [
            ("lone surrogate", lone_surrogate),
            ("raw 0xFF", raw_ff),
            ("nesting 200", deep),
            ("nesting 200000", very_deep),
        ] {
            let got = PageFacts::read(&body, "values");
            assert_eq!(
                (got.items, got.total, got.is_last),
                (1, Some(5), Some(false)),
                "{name}"
            );
            // The value reading failed on each of them: zero items.
            assert_eq!(by_value(&body, "values").items, 0, "{name} (old reading)");
        }
    }
}

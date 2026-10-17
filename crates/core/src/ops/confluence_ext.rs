//! The Confluence writes M7 completes beyond `confluence.page.update`:
//! - `confluence.page.create` (Task 16, PD-105): the space resolved by its key, the parent page by
//!   id or by title within that space ([`resolve_parent`], shared with `page.move`), and the
//!   duplicate-title check, so a create is sent only into the space and under the page the
//!   approver saw;
//! - `confluence.page.move` (Task 17, PD-106): the page with its version, the new parent resolved
//!   within the page's own space (the same `resolve_parent`), and the hold of a move under the
//!   page itself or one of its descendants, so a move is sent only as the approver saw it;
//! - `confluence.comment.add` (Task 18, PD-107): the container type from the enrichment and the
//!   `reply_to` resolution (a comment on this very content), so a reply is never sent unchecked;
//! - the label writes (Task 19, PD-108): one request each, the content's current labels read for
//!   the card only;
//! - `confluence.attachment.upload` (Task 20a, PD-109): the filename lookup (the collision hold
//!   without `replace`, the one attachment a replace targets), the deterministic multipart body
//!   and the sniffed type of its file part.

use atlas_duck_atlassian::{GetCall, HttpRequestSpec};
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::warning::{self, Warning, WarningId};
use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::confluence::content_version;
use super::confluence_body::{EmptyBody, storage_text};
use super::generic::find_bytes;
use super::jira::{MAX_CANDIDATES, capped, unresolved};
use super::{
    ConfluenceFacts, EnrichCtx, EnrichPurpose, EnrichRule, EnrichStep, EnrichVerdict, ExecCtx,
    ExecError, ExecPlan, ExistingAttachment, PageRef, WriteSummaryFacts, get_call, json_request,
    method_name, resolve_url, single_round, str_param,
};
use crate::lifecycle::model::Hold;
use crate::validate::invalid;

// ---- confluence.page.create --------------------------------------------------------------------

/// Stage 1: the space, by its key (§7.4: `space` is a key; never searched by name).
const SPACE_PATH: &str = "/rest/api/space/{space}";

/// Stage 2 by id: the parent page with its space and ancestors.
const PARENT_PATH: &str = "/rest/api/content/{parent}";

/// Stage 2 by title and stage 3: the content of a space with a given title.
const CONTENT_LOOKUP_PATH: &str = "/rest/api/content";

/// `expand` of both parent lookups: the space proves the page is in the write's space, the
/// ancestors give the card's path (and `page.move` its cycle check).
const PARENT_EXPAND: &str = "space,ancestors";

/// `limit` of the parent lookup by title (T16 review m-4): enough for a real match count and the
/// [`MAX_CANDIDATES`] cap; a full page that pins no match is held (a match may lie beyond it).
const PARENT_LOOKUP_LIMIT: usize = 50;

/// PD-105: stage 1 resolves the space by its key (`resolve`); stage 2, only with `parent`, the
/// parent page within that space ([`parent_call`], `resolve`); stage 3 looks for a page of the
/// same title in the space (`enrich`, the duplicate-title Caution). An unresolved space or parent
/// ends the plan (`Judge`, no further GET). No stale rule (§5.4 step 5: an additive write);
/// `title` and `body` are the params an approver edit re-enriches (space and parent are target
/// params, read-only).
pub static PAGE_CREATE_ENRICH: EnrichRule = EnrichRule {
    plan: create_plan,
    judge: create_judge,
};

/// The parent page a create (or a move, Task 17) is put under, as resolution read it (raw
/// server text: escaped where it is shown).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Parent {
    pub id: String,
    pub title: String,
    /// The parent's own ancestors, root first.
    pub ancestors: Vec<PageRef>,
}

/// An all-digit `parent` is a page id (PD-105): never also looked up as a title, so a page whose
/// title is all digits is named by its id (lead ruling Q2: no guessing between the two).
fn is_page_id(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())
}

fn text_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// The agent's `parent` (a page id or a title, Δ4 a).
fn parent_param(params: &Value) -> Option<&str> {
    text_of(params, "parent")
}

/// The space key of a content answer (`expand=space`).
fn space_key_of(v: &Value) -> Option<&str> {
    v.get("space").and_then(|s| text_of(s, "key"))
}

/// PD-105 stage 2: the GET that resolves the `parent` param within the space `space_key` (the
/// key the space answer named): an all-digit value by id, any other by title (current pages, at
/// most [`PARENT_LOOKUP_LIMIT`]: one resolves, more are ambiguous). `None` without a `parent`.
pub(crate) fn parent_call(params: &Value, space_key: &str) -> Option<(EnrichPurpose, GetCall)> {
    let parent = parent_param(params)?;
    let call = if is_page_id(parent) {
        get_call(PARENT_PATH, params, &[("expand", PARENT_EXPAND)])
    } else {
        let limit = PARENT_LOOKUP_LIMIT.to_string();
        get_call(
            CONTENT_LOOKUP_PATH,
            params,
            &[
                ("spaceKey", space_key),
                ("title", parent),
                ("type", "page"),
                ("status", "current"),
                ("expand", PARENT_EXPAND),
                ("limit", limit.as_str()),
            ],
        )
    };
    Some((EnrichPurpose::Resolve, call))
}

/// PD-105 / I-35: the page the `parent` param names in the space `space_key`, from the answer to
/// [`parent_call`]; otherwise the verdict that holds the write. Never a guess:
/// - by id: the answer must be that id; a page that is not `current`, not a `page` or in another
///   space is no match ("no page '<v>' in space <KEY>");
/// - by title: only `current` pages of the answer count (the query asks for them; the filter is a
///   backstop); none, or one whose title is not exactly the value, is no match (its title the
///   candidate); two or more are ambiguous (the count is theirs, the candidates their titles, at
///   most [`MAX_CANDIDATES`]); the one match must be in the space too.
///
/// A page without a `status` is not current (T16 review m-8). An answer that lacks what the rule
/// reads (the id, the space, the title, `results`, an `ancestors` array whose entries all carry a
/// page id: `page.move`'s cycle check reads them), or a full lookup page that pins no match,
/// fails closed (`unusable`, an "enrichment failed" hold). A JSON 404 never reaches here: the
/// engine holds a non-2xx enrichment answer before the judge.
pub(crate) fn resolve_parent(
    params: &Value,
    space_key: &str,
    answer: &Value,
) -> Result<Parent, Box<EnrichVerdict>> {
    let value = str_param(params, "parent");
    let no_match = |candidates: Vec<String>| Box::new(unresolved("parent", value, 0, candidates));
    let is_current_page =
        |p: &Value| text_of(p, "type") == Some("page") && text_of(p, "status") == Some("current");
    let found = if is_page_id(value) {
        if id_text(answer.get("id")).as_deref() != Some(value) {
            return Err(Box::new(EnrichVerdict::unusable()));
        }
        if !is_current_page(answer) {
            return Err(no_match(Vec::new()));
        }
        answer
    } else {
        let Some(results) = answer.get("results").and_then(Value::as_array) else {
            return Err(Box::new(EnrichVerdict::unusable()));
        };
        let pages: Vec<&Value> = results.iter().filter(|p| is_current_page(p)).collect();
        if results.len() >= PARENT_LOOKUP_LIMIT && pages.len() < 2 {
            return Err(Box::new(EnrichVerdict::unusable()));
        }
        let titles = |pages: &[&Value]| -> Vec<String> {
            pages
                .iter()
                .filter_map(|p| text_of(p, "title"))
                .map(capped)
                .take(MAX_CANDIDATES)
                .collect()
        };
        match pages.as_slice() {
            [one] if text_of(one, "title") == Some(value) => *one,
            [_] | [] => return Err(no_match(titles(&pages))),
            more => {
                let n = u64::try_from(more.len()).unwrap_or(u64::MAX);
                return Err(Box::new(unresolved("parent", value, n, titles(more))));
            }
        }
    };
    let (Some(id), Some(title), Some(key)) = (
        id_text(found.get("id")).filter(|id| is_page_id(id)),
        text_of(found, "title"),
        space_key_of(found),
    ) else {
        return Err(Box::new(EnrichVerdict::unusable()));
    };
    if !key.eq_ignore_ascii_case(space_key) {
        return Err(no_match(Vec::new()));
    }
    let ancestors = page_refs(found).ok_or_else(|| Box::new(EnrichVerdict::unusable()))?;
    Ok(Parent {
        id,
        title: title.to_owned(),
        ancestors,
    })
}

/// The `ancestors` of a content answer (`expand=ancestors`), root first, titles cut to the name
/// cap; `None` (fail closed) when it is no array or an entry lacks an all-digit page id, since the
/// `page.move` cycle check reads every id.
fn page_refs(content: &Value) -> Option<Vec<PageRef>> {
    content
        .get("ancestors")?
        .as_array()?
        .iter()
        .map(|a| {
            Some(PageRef {
                id: id_text(a.get("id")).filter(|id| is_page_id(id))?,
                title: text_of(a, "title").map(capped).unwrap_or_default(),
            })
        })
        .collect()
}

/// The space the `space` param names, from the stage-1 answer: its key (the server's spelling,
/// which the body sends) and name. A key that is not the param's (ASCII case-insensitively) is no
/// match ("no space '<v>'"); an answer without a key fails closed.
fn resolve_space(
    params: &Value,
    answer: &Value,
) -> Result<(String, Option<String>), Box<EnrichVerdict>> {
    let value = str_param(params, "space");
    let Some(key) = text_of(answer, "key") else {
        return Err(Box::new(EnrichVerdict::unusable()));
    };
    if !key.eq_ignore_ascii_case(value) {
        return Err(Box::new(unresolved("space", value, 0, Vec::new())));
    }
    Ok((key.to_owned(), text_of(answer, "name").map(str::to_owned)))
}

/// Stage 3: pages of the space titled like the new page (one is enough to warn).
fn duplicate_call(params: &Value, space_key: &str) -> (EnrichPurpose, GetCall) {
    let call = get_call(
        CONTENT_LOOKUP_PATH,
        params,
        &[
            ("spaceKey", space_key),
            ("title", str_param(params, "title")),
            ("type", "page"),
            ("limit", "1"),
        ],
    );
    (EnrichPurpose::Enrich, call)
}

fn create_plan(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichStep {
    let params = ctx.params;
    let Some(space) = answers.first() else {
        return fetch(EnrichPurpose::Resolve, get_call(SPACE_PATH, params, &[]));
    };
    let Ok((key, _)) = resolve_space(params, space) else {
        return EnrichStep::Judge;
    };
    match (answers, parent_call(params, &key)) {
        ([_], Some(parent)) => EnrichStep::Fetch(vec![parent]),
        ([_], None) => EnrichStep::Fetch(vec![duplicate_call(params, &key)]),
        ([_, parent], Some(_)) => match resolve_parent(params, &key, parent) {
            Ok(_) => EnrichStep::Fetch(vec![duplicate_call(params, &key)]),
            Err(_) => EnrichStep::Judge,
        },
        _ => EnrichStep::Judge,
    }
}

fn create_judge(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichVerdict {
    let params = ctx.params;
    let Some(space) = answers.first() else {
        return EnrichVerdict::unusable();
    };
    let (key, space_name) = match resolve_space(params, space) {
        Ok(found) => found,
        Err(held) => return *held,
    };
    let parent = match parent_param(params) {
        None => None,
        Some(_) => {
            // The plan asked for the parent only after a resolved space, so a missing answer is
            // a short response list: fail closed.
            let Some(answer) = answers.get(1) else {
                return EnrichVerdict::unusable();
            };
            match resolve_parent(params, &key, answer) {
                Ok(p) => Some(p),
                Err(held) => return *held,
            }
        }
    };
    let duplicates = answers
        .get(if parent.is_some() { 2 } else { 1 })
        .and_then(|a| a.get("results"))
        .and_then(Value::as_array);
    let Some(duplicates) = duplicates else {
        return EnrichVerdict::unusable();
    };
    let title = str_param(params, "title");

    let mut resolved = Map::new();
    resolved.insert("space".to_owned(), Value::from(str_param(params, "space")));
    resolved.insert("space_key".to_owned(), Value::from(key.as_str()));
    resolved.insert("title".to_owned(), Value::from(title));
    let mut baseline = Map::new();
    baseline.insert("space_key".to_owned(), Value::from(key.as_str()));
    if let (Some(p), Some(value)) = (&parent, parent_param(params)) {
        resolved.insert("parent".to_owned(), Value::from(value));
        resolved.insert("parent_id".to_owned(), Value::from(p.id.as_str()));
        baseline.insert("parent_id".to_owned(), Value::from(p.id.as_str()));
    }
    let mut verdict = EnrichVerdict::preview(Value::Object(baseline), resolved);
    let duplicate_title = !duplicates.is_empty();
    if duplicate_title {
        verdict.warnings.push(Warning::new(
            WarningId::DuplicateTitle,
            warning::duplicate_title(&escape_for_display(title), &escape_for_display(&key)),
        ));
    }
    // Where the new page goes: the parent's ancestors, then the parent (the card's path row).
    let to_path = parent
        .as_ref()
        .map(|p| {
            p.ancestors
                .iter()
                .map(|a| a.title.clone())
                .chain([capped(&p.title)])
                .collect()
        })
        .unwrap_or_default();
    verdict.summary = Some(WriteSummaryFacts {
        confluence: Some(ConfluenceFacts {
            space_key: capped(&key),
            space_name: space_name.as_deref().map(capped),
            parent: parent.map(|p| PageRef {
                id: p.id,
                title: capped(&p.title),
            }),
            to_path,
            duplicate_title,
            ..ConfluenceFacts::default()
        }),
        ..WriteSummaryFacts::default()
    });
    verdict
}

/// `POST /rest/api/content` with the PD-105 body: `{"type":"page","title","space":{"key":<the
/// resolved key>},"ancestors":[{"id":<the resolved parent id>}] (only with `parent`),"body":
/// {"storage":…}}`. The body checks answer first (the Task 9 rule: the validation dry call
/// refuses a placeholder or a refused storage before any enrichment GET; a page may be empty).
/// Then only a `Preview` verdict for these very params renders a request: the space key and the
/// parent id are the ones enrichment resolved for this space, parent and title (an approver edit
/// of the title re-enriches first), never a param sent unchecked.
pub fn page_create_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    resolve_url(ctx.base, ctx.spec.endpoint.path, ctx.params, &[])?;
    let storage = storage_text(ctx, EmptyBody::Allow)?;
    let verdict = ctx
        .enrichment
        .filter(|v| v.hold == Hold::Preview)
        .ok_or(ExecError::EnrichmentRequired)?;
    let resolved = |name: &str| verdict.resolved.get(name).and_then(Value::as_str);
    let params = ctx.params;
    let space = str_param(params, "space");
    let title = str_param(params, "title");
    let parent = parent_param(params);
    if resolved("space") != Some(space)
        || resolved("title") != Some(title)
        || resolved("parent") != parent
    {
        return Err(ExecError::EnrichmentRequired);
    }
    let key = resolved("space_key")
        .filter(|k| k.eq_ignore_ascii_case(space))
        .ok_or(ExecError::EnrichmentRequired)?;
    let parent_id = match parent {
        None => None,
        Some(_) => Some(
            resolved("parent_id")
                .filter(|id| is_page_id(id))
                .ok_or(ExecError::EnrichmentRequired)?,
        ),
    };
    let mut body = json!({
        "type": "page",
        "title": title,
        "space": {"key": key},
        "body": {"storage": {"value": storage, "representation": "storage"}},
    });
    if let (Some(id), Some(map)) = (parent_id, body.as_object_mut()) {
        map.insert("ancestors".to_owned(), json!([{ "id": id }]));
    }
    json_request(ctx, &body)
}

// ---- confluence.page.move ----------------------------------------------------------------------

/// Stage 1: the page that moves.
const PAGE_PATH: &str = "/rest/api/content/{id}";

/// `expand` of stage 1: the version the `PUT` increments (and the stale rule compares), the space
/// the parent must be in, the ancestors of the old path.
const PAGE_EXPAND: &str = "version,space,ancestors";

/// PD-106 (plan text): the card of a move under the page itself or one of its descendants.
pub(crate) const TEXT_MOVE_INTO_OWN_SUBTREE: &str =
    "a page cannot be moved under itself or one of its descendants";

/// PD-106: stage 1 reads the page with its version, space and ancestors (`enrich`); stage 2
/// resolves the `parent` param within that page's own space ([`parent_call`], `resolve`): a page
/// of another space is no match (cross-space moves are a non-goal, §1.3). A parent that is the
/// page itself or has it among its ancestors is held ([`TEXT_MOVE_INTO_OWN_SUBTREE`]). A stage-1
/// answer the judge cannot use ends the plan (`Judge`, no parent lookup). The stale rule is
/// `stale::PAGE_MOVE` (`version.number` unchanged); `parent` is the one param an approver edit
/// re-enriches (`id` is the target param, read-only).
pub static PAGE_MOVE_ENRICH: EnrichRule = EnrichRule {
    plan: move_plan,
    judge: move_judge,
};

/// The page a move is about, as stage 1 read it (raw server text).
struct MovedPage {
    title: String,
    version: u64,
    space_key: String,
    space_name: Option<String>,
    ancestors: Vec<PageRef>,
}

/// Stage 1's answer when it is this very page (the `id` param, as a string or a number), a
/// current `page` with a version, a title, a space key and ancestors that all carry a page id;
/// `None` otherwise (fail closed: the old path and the version the `PUT` increments come from it).
fn moved_page(params: &Value, answer: &Value) -> Option<MovedPage> {
    let is_this_page = id_text(answer.get("id")).as_deref() == Some(str_param(params, "id"))
        && text_of(answer, "type") == Some("page")
        && text_of(answer, "status") == Some("current");
    if !is_this_page {
        return None;
    }
    let space = answer.get("space")?;
    Some(MovedPage {
        title: text_of(answer, "title")?.to_owned(),
        version: content_version(answer)?,
        space_key: text_of(space, "key")?.to_owned(),
        space_name: text_of(space, "name").map(str::to_owned),
        ancestors: page_refs(answer)?,
    })
}

/// Two all-digit page ids name the same page (leading zeros aside: the cycle check must not miss
/// the page over a spelling).
fn same_page(a: &str, b: &str) -> bool {
    a.trim_start_matches('0') == b.trim_start_matches('0')
}

fn move_plan(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichStep {
    let params = ctx.params;
    match answers {
        [] => fetch(
            EnrichPurpose::Enrich,
            get_call(PAGE_PATH, params, &[("expand", PAGE_EXPAND)]),
        ),
        [page] => match moved_page(params, page).and_then(|p| parent_call(params, &p.space_key)) {
            Some(parent) => EnrichStep::Fetch(vec![parent]),
            None => EnrichStep::Judge,
        },
        _ => EnrichStep::Judge,
    }
}

fn move_judge(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichVerdict {
    let params = ctx.params;
    let Some(page) = answers.first().and_then(|a| moved_page(params, a)) else {
        return EnrichVerdict::unusable();
    };
    // The plan asked for the parent only after a usable page, so a missing answer is a short
    // response list: fail closed.
    let Some(answer) = answers.get(1) else {
        return EnrichVerdict::unusable();
    };
    let parent = match resolve_parent(params, &page.space_key, answer) {
        Ok(p) => p,
        Err(held) => return *held,
    };
    let id = str_param(params, "id");
    let mut facts = ConfluenceFacts {
        space_key: capped(&page.space_key),
        space_name: page.space_name.as_deref().map(capped),
        page: Some(PageRef {
            id: id.to_owned(),
            title: page.title.clone(),
        }),
        ..ConfluenceFacts::default()
    };
    // PD-106: under the page itself or one of its descendants. `resolve_parent` guarantees every
    // ancestor carries a page id (T16 review m-5), so the whole chain is compared.
    if same_page(&parent.id, id) || parent.ancestors.iter().any(|a| same_page(&a.id, id)) {
        facts.into_own_subtree = true;
        let mut held = EnrichVerdict {
            hold: Hold::EnrichmentError,
            ..EnrichVerdict::preview(Value::Null, Map::new())
        };
        held.summary = Some(WriteSummaryFacts {
            confluence: Some(facts),
            ..WriteSummaryFacts::default()
        });
        return held;
    }

    let mut resolved = Map::new();
    resolved.insert("id".to_owned(), Value::from(id));
    resolved.insert("title".to_owned(), Value::from(page.title.as_str()));
    if let Some(value) = parent_param(params) {
        resolved.insert("parent".to_owned(), Value::from(value));
    }
    resolved.insert("parent_id".to_owned(), Value::from(parent.id.as_str()));
    // The stale rule compares `version` (`stale::PAGE_MOVE`); the `PUT` sends it + 1.
    // `from_parent_id` is the page's current parent (its last ancestor, none for a root page),
    // `to_parent_id` the destination.
    let baseline = json!({
        "version": page.version,
        "title": page.title,
        "space_key": page.space_key,
        "from_parent_id": page.ancestors.last().map(|a| a.id.as_str()),
        "to_parent_id": parent.id,
    });
    let mut verdict = EnrichVerdict::preview(baseline, resolved);
    facts.from_path = page.ancestors.into_iter().map(|a| a.title).collect();
    facts.to_path = parent
        .ancestors
        .iter()
        .map(|a| a.title.clone())
        .chain([parent.title.clone()])
        .collect();
    facts.parent = Some(PageRef {
        id: parent.id,
        title: parent.title,
    });
    verdict.summary = Some(WriteSummaryFacts {
        confluence: Some(facts),
        ..WriteSummaryFacts::default()
    });
    verdict
}

/// `PUT /rest/api/content/{id}` with the PD-106 body: `{"id","type":"page","title":<current
/// title>,"version":{"number":<current + 1>},"ancestors":[{"id":<resolved parent id>}]}`, no
/// `body` (lead ruling Q4; the live probe `v_page_move_keeps_body` decides). Only a `Preview`
/// verdict for these very params renders it: the parent id is the one enrichment resolved (and
/// checked against the cycle) for this `parent`, the version the one the stale rule compares.
pub fn page_move_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    resolve_url(ctx.base, ctx.spec.endpoint.path, ctx.params, &[])?;
    let verdict = ctx
        .enrichment
        .filter(|v| v.hold == Hold::Preview)
        .ok_or(ExecError::EnrichmentRequired)?;
    let resolved = |name: &str| verdict.resolved.get(name).and_then(Value::as_str);
    let id = str_param(ctx.params, "id");
    if resolved("id") != Some(id) || resolved("parent") != parent_param(ctx.params) {
        return Err(ExecError::EnrichmentRequired);
    }
    let parent_id = resolved("parent_id")
        .filter(|p| is_page_id(p) && !same_page(p, id))
        .ok_or(ExecError::EnrichmentRequired)?;
    let title = resolved("title").ok_or(ExecError::EnrichmentRequired)?;
    let next = verdict
        .baseline
        .get("version")
        .and_then(Value::as_u64)
        .and_then(|v| v.checked_add(1))
        .ok_or(ExecError::EnrichmentRequired)?;
    let body = json!({
        "id": id,
        "type": "page",
        "title": title,
        "version": {"number": next},
        "ancestors": [{ "id": parent_id }],
    });
    json_request(ctx, &body)
}

// ---- confluence.comment.add --------------------------------------------------------------------

/// Stage 1: the content the comment goes on.
const CONTAINER_PATH: &str = "/rest/api/content/{content_id}";

/// Stage 2, only with `reply_to`: the comment replied to.
const REPLY_PATH: &str = "/rest/api/content/{reply_to}";

/// PD-107: stage 1 reads the content with its space (`enrich`: its `type` is the container type
/// the request sends), stage 2 reads the `reply_to` comment with its container (`resolve`) and
/// requires it to be a comment on that same content. Content of another type ends the plan after
/// stage 1 (`Judge`, no further GET); so does a comment with no reply. No stale rule (§5.4
/// step 5: an additive write); `reply_to` is the one param an approver edit re-enriches.
pub static COMMENT_ADD_ENRICH: EnrichRule = EnrichRule {
    plan: comment_plan,
    judge: comment_judge,
};

/// The agent's `reply_to`, when it names a comment.
fn reply_to(params: &Value) -> Option<&str> {
    params.get("reply_to").and_then(Value::as_str)
}

/// `type` of a content answer when it is a place for a comment (§7.4: `page` or `blogpost`).
fn container_type(answer: &Value) -> Option<&str> {
    answer
        .get("type")
        .and_then(Value::as_str)
        .filter(|t| matches!(*t, "page" | "blogpost"))
}

/// An id as text: a string as sent, a number in decimal (Confluence may send either).
fn id_text(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn fetch(purpose: EnrichPurpose, call: GetCall) -> EnrichStep {
    EnrichStep::Fetch(vec![(purpose, call)])
}

fn comment_plan(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichStep {
    match answers {
        [] => fetch(
            EnrichPurpose::Enrich,
            get_call(CONTAINER_PATH, ctx.params, &[("expand", "space")]),
        ),
        [container] if reply_to(ctx.params).is_some() && container_type(container).is_some() => {
            fetch(
                EnrichPurpose::Resolve,
                get_call(REPLY_PATH, ctx.params, &[("expand", "container")]),
            )
        }
        _ => EnrichStep::Judge,
    }
}

fn comment_judge(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichVerdict {
    let Some(container) = answers.first() else {
        return EnrichVerdict::unusable();
    };
    let Some(kind) = container_type(container) else {
        return EnrichVerdict::unusable();
    };
    let content_id = str_param(ctx.params, "content_id");
    let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    let space = container.get("space");
    let title = text(container, "title");

    let mut resolved = Map::new();
    resolved.insert("content_id".to_owned(), Value::from(content_id));
    resolved.insert("container_type".to_owned(), Value::from(kind));
    if let Some(reply) = reply_to(ctx.params) {
        // The plan asked for the reply only after a usable container, so a missing answer is a
        // short response list: fail closed.
        let Some(parent) = answers.get(1) else {
            return EnrichVerdict::unusable();
        };
        let on_this_content = parent.get("type").and_then(Value::as_str) == Some("comment")
            && id_text(parent.get("container").and_then(|c| c.get("id"))).as_deref()
                == Some(content_id);
        if !on_this_content {
            return unresolved("reply_to", reply, 0, Vec::new());
        }
        resolved.insert("reply_to".to_owned(), Value::from(reply));
    }

    let mut verdict = EnrichVerdict::preview(json!({ "container_type": kind }), resolved);
    verdict.summary = Some(WriteSummaryFacts {
        confluence: Some(ConfluenceFacts {
            space_key: space
                .and_then(|s| text(s, "key"))
                .as_deref()
                .map(capped)
                .unwrap_or_default(),
            space_name: space.and_then(|s| text(s, "name")).as_deref().map(capped),
            page: Some(PageRef {
                id: content_id.to_owned(),
                title: title.as_deref().map(capped).unwrap_or_default(),
            }),
            container_type: Some(kind.to_owned()),
            ..ConfluenceFacts::default()
        }),
        ..WriteSummaryFacts::default()
    });
    verdict
}

/// `POST /rest/api/content` with the §7.4 payload: `{"type":"comment","container":{"id",
/// "type"},"ancestors":[{"id":<reply_to>}] (only with `reply_to`),"body":{"storage":…}}`. The body
/// checks answer first (the Task 9 rule: the validation dry call refuses a placeholder, a refused
/// storage or an empty comment before any enrichment GET). Then only a `Preview` verdict for these
/// params renders a request: the container type is the one enrichment read, and a `reply_to` is
/// sent only when enrichment resolved that very value (never unchecked, an approver edit included).
pub fn comment_add_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    resolve_url(ctx.base, ctx.spec.endpoint.path, ctx.params, &[])?;
    let storage = storage_text(ctx, EmptyBody::Refuse)?;
    let verdict = ctx
        .enrichment
        .filter(|v| v.hold == Hold::Preview)
        .ok_or(ExecError::EnrichmentRequired)?;
    let resolved = |name: &str| verdict.resolved.get(name).and_then(Value::as_str);
    let content_id = str_param(ctx.params, "content_id");
    let kind = resolved("container_type").filter(|k| matches!(*k, "page" | "blogpost"));
    let (Some(kind), true) = (kind, resolved("content_id") == Some(content_id)) else {
        return Err(ExecError::EnrichmentRequired);
    };
    let reply = reply_to(ctx.params);
    if resolved("reply_to") != reply {
        return Err(ExecError::EnrichmentRequired);
    }
    let mut body = json!({
        "type": "comment",
        "container": {"id": content_id, "type": kind},
        "body": {"storage": {"value": storage, "representation": "storage"}},
    });
    if let (Some(reply), Some(map)) = (reply, body.as_object_mut()) {
        map.insert("ancestors".to_owned(), json!([{ "id": reply }]));
    }
    json_request(ctx, &body)
}

// ---- confluence.label.add / confluence.label.remove --------------------------------------------

/// The content the labels go on or come off: one GET with its labels (`metadata.labels`).
const LABELS_PATH: &str = "/rest/api/content/{id}";

/// The embedded label list's page size when the answer names none (the server's default).
const LABELS_PAGE_CAP: u64 = 200;

/// PD-108: one enrichment GET (`enrich`) reads the content's title and its current labels, for the
/// card only (the "already present" / "not present" rows). Nothing sent depends on it, but a write
/// is rendered only after a usable answer for this very id. No stale rule (§5.4 step 5: additive
/// or idempotent writes); the only param an approver edit changes is `labels`, which the facts do
/// not depend on.
pub static LABELS_ENRICH: EnrichRule = EnrichRule {
    plan: labels_plan,
    judge: labels_judge,
};

fn labels_plan(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichStep {
    match answers {
        [] => fetch(
            EnrichPurpose::Enrich,
            get_call(LABELS_PATH, ctx.params, &[("expand", "metadata.labels")]),
        ),
        _ => EnrichStep::Judge,
    }
}

/// The names of the global labels the content has. Labels with another prefix (`my`, `team`) are
/// not what a `global` add or a remove by name touches.
fn global_labels(results: &[Value]) -> Vec<String> {
    results
        .iter()
        .filter(|l| {
            l.get("prefix")
                .and_then(Value::as_str)
                .is_none_or(|p| p == "global")
        })
        .filter_map(|l| l.get("name").and_then(Value::as_str))
        .map(capped)
        .collect()
}

fn labels_judge(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichVerdict {
    let Some(content) = answers.first() else {
        return EnrichVerdict::unusable();
    };
    // Fail closed on an answer without the label list (not a content answer).
    let Some(results) = content
        .pointer("/metadata/labels/results")
        .and_then(Value::as_array)
    else {
        return EnrichVerdict::unusable();
    };
    let id = str_param(ctx.params, "id");
    // The answer must be about this content, and the label list must be all of it: a full page
    // (the server's `limit`, 200 when it names none) or a further page means labels are unread,
    // so no "not present" can be claimed (T19 review M-5, M-7).
    let list = content.pointer("/metadata/labels");
    let count = |key: &str| {
        list.and_then(|l| l.get(key))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    let limit = list
        .and_then(|l| l.get("limit"))
        .and_then(Value::as_u64)
        .unwrap_or(LABELS_PAGE_CAP);
    let shown = u64::try_from(results.len()).unwrap_or(u64::MAX);
    let more = list.is_some_and(|l| l.pointer("/_links/next").is_some())
        || count("size") > shown
        || count("totalSize") > shown
        || shown >= limit;
    if content.get("id").and_then(Value::as_str) != Some(id) || more {
        return EnrichVerdict::unusable();
    }
    let title = content.get("title").and_then(Value::as_str).map(capped);
    let mut resolved = Map::new();
    resolved.insert("id".to_owned(), Value::from(id));
    let mut verdict = EnrichVerdict::preview(Value::Null, resolved);
    verdict.summary = Some(WriteSummaryFacts {
        confluence: Some(ConfluenceFacts {
            page: Some(PageRef {
                id: id.to_owned(),
                title: title.unwrap_or_default(),
            }),
            container_type: content
                .get("type")
                .and_then(Value::as_str)
                .map(str::to_owned),
            current_labels: global_labels(results),
            ..ConfluenceFacts::default()
        }),
        ..WriteSummaryFacts::default()
    });
    verdict
}

/// Only a `Preview` verdict for this content id renders a label request.
fn labels_verdict<'a>(ctx: &'a ExecCtx<'_>) -> Result<&'a EnrichVerdict, ExecError> {
    let id = str_param(ctx.params, "id");
    ctx.enrichment
        .filter(|v| {
            v.hold == Hold::Preview && v.resolved.get("id").and_then(Value::as_str) == Some(id)
        })
        .ok_or(ExecError::EnrichmentRequired)
}

/// `POST /rest/api/content/{id}/label` with `[{"prefix":"global","name":<label>}, …]` in the
/// params' order (§7.4, PD-108): one entry per label, exactly as the agent wrote it.
pub fn label_add_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    resolve_url(ctx.base, ctx.spec.endpoint.path, ctx.params, &[])?;
    let items = ctx
        .params
        .get("labels")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let labels: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
    if labels.is_empty() {
        return Err(ExecError::Invalid(invalid("labels", "required", None)));
    }
    // The body is the approver's contract: nothing is dropped from it (a non-string entry), and
    // one label is not sent twice under two cases. Validation checks both; this is the second line.
    if labels.len() != items.len() {
        return Err(ExecError::Invalid(invalid(
            "labels",
            "labels must be strings",
            None,
        )));
    }
    let mut seen = std::collections::HashSet::new();
    if !labels.iter().all(|l| seen.insert(l.to_ascii_lowercase())) {
        return Err(ExecError::Invalid(invalid(
            "labels",
            "labels must be distinct ignoring case",
            None,
        )));
    }
    labels_verdict(ctx)?;
    let body: Vec<Value> = labels
        .into_iter()
        .map(|name| json!({"prefix": "global", "name": name}))
        .collect();
    json_request(ctx, &Value::Array(body))
}

/// `DELETE /rest/api/content/{id}/label/{label}`, no body and no content type (§1.3: the only
/// DELETE). `resolve_url` refuses a `.`/`..` label (it would act as a dot segment and name another
/// resource) before anything is rendered.
pub fn label_remove_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    let resolved_url = resolve_url(ctx.base, ctx.spec.endpoint.path, ctx.params, &[])?;
    labels_verdict(ctx)?;
    Ok(ExecPlan::Write(vec![HttpRequestSpec {
        index: 0,
        method: method_name(ctx.spec.endpoint.method).to_owned(),
        resolved_url,
        content_type: None,
        body: Vec::new(),
    }]))
}

// ---- confluence.attachment.upload --------------------------------------------------------------

/// Stage 1 and the replace stale check: the content's attachments of one filename.
const ATTACHMENTS_PATH: &str = "/rest/api/content/{id}/child/attachment";

/// §7.4 / PD-109: `replace=true` posts the new bytes to the `/data` endpoint of the attachment.
const ATTACHMENT_DATA_PATH: &str = "/rest/api/content/{id}/child/attachment/{attachmentId}/data";

/// PD-109: one GET (`enrich`) lists the content's attachments of the filename with their
/// versions. Without `replace`, an attachment of that name (exactly, or differing only in case)
/// is the collision hold (`Hold::Collision`, Approve disabled, no deny detail applies, §7.4
/// "attachment already exists"); with `replace`, exactly one attachment of exactly that name is
/// the one replaced (its id and version are the stale baseline, `stale::ATTACHMENT_REPLACE`),
/// none is `UnresolvedName {filename, 0}`. `filename` and `replace` are the params an approver
/// edit re-enriches (`id` is the target param, read-only).
pub static ATTACHMENT_ENRICH: EnrichRule = EnrichRule {
    plan: attachment_plan,
    judge: attachment_judge,
};

/// The lookup of the content's attachments named like the `filename` param (a query value
/// encoded by `build_url`, never spliced into the path), with their versions.
pub(crate) fn attachment_call(params: &Value) -> GetCall {
    get_call(
        ATTACHMENTS_PATH,
        params,
        &[
            ("filename", str_param(params, "filename")),
            ("expand", "version"),
        ],
    )
}

/// The agent asked to replace the attachment of that name (`replace: true`; absent is `false`).
pub(crate) fn wants_replace(params: &Value) -> bool {
    params.get("replace") == Some(&Value::Bool(true))
}

/// An attachment of a lookup answer (raw server text).
pub(crate) struct Listed {
    pub id: String,
    pub title: String,
    pub version: u64,
    pub size: Option<u64>,
}

/// The attachments of a lookup answer; `None` (fail closed) when it is no list, an entry is not
/// a current attachment with an id, a title and a version, or a further page may hold more (a
/// collision could lie beyond it).
pub(crate) fn listed_attachments(answer: &Value) -> Option<Vec<Listed>> {
    if answer.pointer("/_links/next").is_some() {
        return None;
    }
    answer
        .get("results")?
        .as_array()?
        .iter()
        .map(|a| {
            let current =
                text_of(a, "type") == Some("attachment") && text_of(a, "status") == Some("current");
            current.then_some(())?;
            Some(Listed {
                id: id_text(a.get("id"))?,
                title: text_of(a, "title")?.to_owned(),
                version: content_version(a)?,
                size: a.pointer("/extensions/fileSize").and_then(Value::as_u64),
            })
        })
        .collect()
}

/// An attachment id fit for the `/data` path segment (`att3001`, or digits): anything else from
/// the server fails closed.
fn is_attachment_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Two names Confluence may take for one attachment: equal, or equal ignoring case.
fn same_name_any_case(a: &str, b: &str) -> bool {
    a == b || a.to_lowercase() == b.to_lowercase()
}

fn attachment_plan(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichStep {
    single_round(
        vec![(EnrichPurpose::Enrich, attachment_call(ctx.params))],
        answers,
    )
}

fn attachment_judge(ctx: &EnrichCtx<'_>, answers: &[Value]) -> EnrichVerdict {
    let params = ctx.params;
    let Some(listed) = answers.first().and_then(listed_attachments) else {
        return EnrichVerdict::unusable();
    };
    let filename = str_param(params, "filename");
    let replace = wants_replace(params);
    let exact: Vec<&Listed> = listed.iter().filter(|a| a.title == filename).collect();
    let variants: Vec<&Listed> = listed
        .iter()
        .filter(|a| a.title != filename && same_name_any_case(&a.title, filename))
        .collect();

    let mut resolved = Map::new();
    resolved.insert("id".to_owned(), Value::from(str_param(params, "id")));
    resolved.insert("filename".to_owned(), Value::from(filename));
    resolved.insert("replace".to_owned(), Value::Bool(replace));
    let facts = |a: Option<&Listed>| WriteSummaryFacts {
        confluence: Some(ConfluenceFacts {
            existing_attachment: a.map(|a| ExistingAttachment {
                id: a.id.clone(),
                version: a.version,
                size: a.size,
            }),
            ..ConfluenceFacts::default()
        }),
        ..WriteSummaryFacts::default()
    };

    if !replace {
        let existing = exact.first().or(variants.first()).copied();
        let mut verdict = EnrichVerdict::preview(Value::Null, resolved);
        if existing.is_some() {
            verdict.hold = Hold::Collision;
        }
        verdict.summary = Some(facts(existing));
        return verdict;
    }
    match exact.as_slice() {
        [] => unresolved(
            "filename",
            filename,
            0,
            variants
                .iter()
                .map(|a| capped(&a.title))
                .take(MAX_CANDIDATES)
                .collect(),
        ),
        [one] if is_attachment_id(&one.id) => {
            resolved.insert("attachment_id".to_owned(), Value::from(one.id.as_str()));
            let baseline = json!({"attachment_id": one.id, "version": one.version});
            let mut verdict = EnrichVerdict::preview(baseline, resolved);
            verdict.summary = Some(facts(Some(one)));
            verdict
        }
        // A server id unfit for the path, or two attachments of exactly that name (which one?):
        // fail closed.
        _ => EnrichVerdict::unusable(),
    }
}

/// The agent's content: standard base64, padding optional (the schema's pattern).
const CONTENT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// PD-109: the filename goes into the part header as sent (`filename="<name>"`, UTF-8), so a
/// double quote or a control character (CR, LF, tab, C0, DEL, C1) cannot be written there and is
/// refused; `..`, `/`-free names and any other character are ordinary (attachments are stored by
/// name, not by path; the schema refuses `/` and `\`). The message never echoes the name.
fn check_filename(filename: &str) -> Result<(), ExecError> {
    if filename.chars().any(|c| c == '"' || c.is_control()) {
        return Err(ExecError::Invalid(invalid(
            "filename",
            "must not contain a double quote or a control character",
            None,
        )));
    }
    Ok(())
}

/// PD-110 (the part's `Content-Type`): the type the file part is sent as, sniffed from its magic
/// bytes for `png`, `jpeg`, `gif`, `webp`, `pdf` and `zip`; anything else is
/// `application/octet-stream` (never a type the agent names, never `text/html` or SVG).
pub(crate) fn sniff_mime(content: &[u8]) -> &'static str {
    let at = |range: std::ops::Range<usize>, magic: &[u8]| content.get(range) == Some(magic);
    if content.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if content.starts_with(b"\xff\xd8\xff") {
        "image/jpeg"
    } else if content.starts_with(b"GIF87a") || content.starts_with(b"GIF89a") {
        "image/gif"
    } else if content.starts_with(b"RIFF") && at(8..12, b"WEBP") {
        "image/webp"
    } else if content.starts_with(b"%PDF-") {
        "application/pdf"
    } else if content.starts_with(b"PK\x03\x04") || content.starts_with(b"PK\x05\x06") {
        "application/zip"
    } else {
        "application/octet-stream"
    }
}

/// PD-109: `atlas-duck-` and the first 32 hex chars of SHA-256(file bytes); while that string
/// occurs in the file bytes, the filename or the comment, `-1`, `-2`, … is appended (the first
/// that occurs in none). A pure function of the params, so two renders give the same bytes.
fn multipart_boundary(content: &[u8], filename: &str, comment: Option<&str>) -> String {
    let digest = hex::encode(Sha256::digest(content));
    let base = format!("atlas-duck-{}", digest.get(..32).unwrap_or(&digest));
    let parts = [
        content,
        filename.as_bytes(),
        comment.unwrap_or("").as_bytes(),
    ];
    let free = |b: &String| {
        parts
            .iter()
            .all(|hay| find_bytes(hay, b.as_bytes()).is_none())
    };
    std::iter::once(base.clone())
        .chain((1u64..).map(|n| format!("{base}-{n}")))
        .find(free)
        .unwrap_or(base)
}

/// PD-109: the `multipart/form-data` body (RFC 7578): the `file` part (`Content-Disposition:
/// form-data; name="file"; filename="<filename>"`, `Content-Type` sniffed) and, when given, the
/// `comment` part (`text/plain; charset=utf-8`), CRLF line ends, closed by `--<b>--` CRLF; and
/// the request's content type with the boundary, so `request_set_hash` covers both.
pub(crate) fn multipart(
    filename: &str,
    content: &[u8],
    comment: Option<&str>,
) -> (String, Vec<u8>) {
    let b = multipart_boundary(content, filename, comment);
    let mut body = Vec::with_capacity(content.len().saturating_add(512));
    body.extend_from_slice(
        format!(
            "--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n\
             Content-Type: {}\r\n\r\n",
            sniff_mime(content)
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    if let Some(comment) = comment {
        body.extend_from_slice(
            format!(
                "\r\n--{b}\r\nContent-Disposition: form-data; name=\"comment\"\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\r\n{comment}"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("\r\n--{b}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={b}"), body)
}

/// The one multipart `POST` of PD-109: a new attachment to `…/child/attachment?allowDuplicated=
/// false`, a replace to `…/child/attachment/{attachmentId}/data`. The static checks answer first
/// (the validation dry call, no verdict yet): the filename rule and content that is no base64 are
/// `validation` (exit 2). Then only a verdict for these very params renders a request: a
/// `Preview` (a new attachment, or the replace of the one attachment enrichment found, its id
/// from that verdict), or the `Collision` hold's card, which shows the new-attachment request an
/// approval would have sent (Approve stays disabled, `engine::write::approvable`).
pub fn attachment_upload_executor(ctx: &ExecCtx<'_>) -> Result<ExecPlan, ExecError> {
    let params = ctx.params;
    resolve_url(ctx.base, ctx.spec.endpoint.path, params, &[])?;
    let filename = str_param(params, "filename");
    check_filename(filename)?;
    let content = CONTENT_BASE64
        .decode(str_param(params, "content_base64"))
        .map_err(|_| ExecError::Invalid(invalid("content_base64", "not valid base64", None)))?;
    let replace = wants_replace(params);
    let verdict = ctx
        .enrichment
        .filter(|v| v.hold == Hold::Preview || (v.hold == Hold::Collision && !replace))
        .ok_or(ExecError::EnrichmentRequired)?;
    let resolved = |name: &str| verdict.resolved.get(name);
    let id = str_param(params, "id");
    if resolved("id").and_then(Value::as_str) != Some(id)
        || resolved("filename").and_then(Value::as_str) != Some(filename)
        || resolved("replace") != Some(&Value::Bool(replace))
    {
        return Err(ExecError::EnrichmentRequired);
    }
    let resolved_url = if replace {
        let attachment = resolved("attachment_id")
            .and_then(Value::as_str)
            .filter(|a| is_attachment_id(a))
            .ok_or(ExecError::EnrichmentRequired)?;
        let at = json!({"id": id, "attachmentId": attachment});
        resolve_url(ctx.base, ATTACHMENT_DATA_PATH, &at, &[])?
    } else {
        let query = [("allowDuplicated".to_owned(), "false".to_owned())];
        resolve_url(ctx.base, ctx.spec.endpoint.path, params, &query)?
    };
    let comment = params.get("comment").and_then(Value::as_str);
    let (content_type, body) = multipart(filename, &content, comment);
    Ok(ExecPlan::Write(vec![HttpRequestSpec {
        index: 0,
        method: method_name(ctx.spec.endpoint.method).to_owned(),
        resolved_url,
        content_type: Some(content_type),
        body,
    }]))
}

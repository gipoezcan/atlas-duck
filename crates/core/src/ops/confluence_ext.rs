//! The Confluence writes M7 completes beyond `confluence.page.update`:
//! - `confluence.page.create` (Task 16, PD-105): the space resolved by its key, the parent page by
//!   id or by title within that space ([`resolve_parent`], shared with `page.move`), and the
//!   duplicate-title check, so a create is sent only into the space and under the page the
//!   approver saw;
//! - `confluence.comment.add` (Task 18, PD-107): the container type from the enrichment and the
//!   `reply_to` resolution (a comment on this very content), so a reply is never sent unchecked.

use atlas_duck_atlassian::GetCall;
use atlas_duck_preview::invisible::escape_for_display;
use atlas_duck_preview::warning::{self, Warning, WarningId};
use serde_json::{Map, Value, json};

use super::confluence_body::{EmptyBody, storage_text};
use super::jira::{MAX_CANDIDATES, capped, unresolved};
use super::{
    ConfluenceFacts, EnrichCtx, EnrichPurpose, EnrichRule, EnrichStep, EnrichVerdict, ExecCtx,
    ExecError, ExecPlan, PageRef, WriteSummaryFacts, get_call, json_request, resolve_url,
    str_param,
};
use crate::lifecycle::model::Hold;

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
/// key the space answer named): an all-digit value by id, any other by title (at most two
/// answers: one resolves, two are ambiguous). `None` without a `parent`.
pub(crate) fn parent_call(params: &Value, space_key: &str) -> Option<(EnrichPurpose, GetCall)> {
    let parent = parent_param(params)?;
    let call = if is_page_id(parent) {
        get_call(PARENT_PATH, params, &[("expand", PARENT_EXPAND)])
    } else {
        get_call(
            CONTENT_LOOKUP_PATH,
            params,
            &[
                ("spaceKey", space_key),
                ("title", parent),
                ("type", "page"),
                ("expand", PARENT_EXPAND),
                ("limit", "2"),
            ],
        )
    };
    Some((EnrichPurpose::Resolve, call))
}

/// PD-105 / I-35: the page the `parent` param names in the space `space_key`, from the answer to
/// [`parent_call`]; otherwise the verdict that holds the write. Never a guess:
/// - by id: the answer must be that id; a page that is not `current`, not a `page` or in another
///   space is no match ("no page '<v>' in space <KEY>");
/// - by title: only `current` pages of the answer count; none, or one whose title is not exactly
///   the value, is no match (its title the candidate); two or more are ambiguous (the candidates
///   are their titles); the one match must be in the space too.
///
/// An answer that lacks what the rule reads (the id, the space, the title, `results`) fails
/// closed (`unusable`, an "enrichment failed" hold). A JSON 404 never reaches here: the engine
/// holds a non-2xx enrichment answer before the judge.
pub(crate) fn resolve_parent(
    params: &Value,
    space_key: &str,
    answer: &Value,
) -> Result<Parent, Box<EnrichVerdict>> {
    let value = str_param(params, "parent");
    let no_match = |candidates: Vec<String>| Box::new(unresolved("parent", value, 0, candidates));
    let is_current_page = |p: &Value| {
        text_of(p, "type") == Some("page") && text_of(p, "status").is_none_or(|s| s == "current")
    };
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
    let ancestors = found
        .get("ancestors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|a| PageRef {
            id: id_text(a.get("id")).unwrap_or_default(),
            title: text_of(a, "title").map(capped).unwrap_or_default(),
        })
        .collect();
    Ok(Parent {
        id,
        title: title.to_owned(),
        ancestors,
    })
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

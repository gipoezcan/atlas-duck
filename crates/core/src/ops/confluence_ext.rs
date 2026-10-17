//! The Confluence writes M7 completes beyond `confluence.page.update`: `confluence.comment.add`
//! (Task 18, PD-107): the container type from the enrichment and the `reply_to` resolution (a
//! comment on this very content), so a reply is never sent unchecked.

use atlas_duck_atlassian::GetCall;
use serde_json::{Map, Value, json};

use super::confluence_body::{EmptyBody, storage_text};
use super::jira::{capped, unresolved};
use super::{
    ConfluenceFacts, EnrichCtx, EnrichPurpose, EnrichRule, EnrichStep, EnrichVerdict, ExecCtx,
    ExecError, ExecPlan, PageRef, WriteSummaryFacts, get_call, json_request, resolve_url,
    str_param,
};
use crate::lifecycle::model::Hold;

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

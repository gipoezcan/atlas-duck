//! §7.3 field rules: `fields`/`expand` lists, the `fields` and `expected` maps of the Jira writes.

use atlas_duck_registry::{FieldRules, OperationSpec};
use serde_json::Value;

use super::{ValidationError, echo, invalid};

/// §7.3 ("a fixed list"): the Jira DC 9.12 system field ids.
pub const JIRA_SYSTEM_FIELDS: &[&str] = &[
    "summary",
    "status",
    "issuetype",
    "priority",
    "assignee",
    "reporter",
    "creator",
    "created",
    "updated",
    "labels",
    "components",
    "fixVersions",
    "versions",
    "parent",
    "description",
    "issuelinks",
    "security",
    "resolution",
    "resolutiondate",
    "duedate",
    "environment",
    "timetracking",
    "timeoriginalestimate",
    "timeestimate",
    "timespent",
    "aggregatetimeoriginalestimate",
    "aggregatetimeestimate",
    "aggregatetimespent",
    "aggregateprogress",
    "progress",
    "workratio",
    "worklog",
    "comment",
    "attachment",
    "subtasks",
    "watches",
    "votes",
    "project",
    "lastViewed",
    "thumbnail",
];

/// Create parameters that `fields` must not repeat (§7.3).
const DEDICATED_CREATE_PARAMS: &[&str] = &["project", "issuetype", "summary", "description"];

/// `customfield_\d+` (ASCII digits only).
fn is_custom_field(id: &str) -> bool {
    id.strip_prefix("customfield_")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

fn is_field_id(id: &str) -> bool {
    JIRA_SYSTEM_FIELDS.contains(&id) || is_custom_field(id)
}

/// A `fields` list entry: a field id, `-<field id>`, `*all` or `*navigable`.
fn is_fields_entry(entry: &str) -> bool {
    matches!(entry, "*all" | "*navigable") || is_field_id(entry.strip_prefix('-').unwrap_or(entry))
}

pub(super) fn check(spec: &OperationSpec, params: &Value) -> Result<(), ValidationError> {
    if let Some(rules) = &spec.field_rules {
        check_rules(spec, rules, params)?;
    }
    if spec.conflict_baselines.contains(&"expected") {
        check_map_keys("fields", params, false)?;
        check_map_keys("expected", params, false)?;
    }
    Ok(())
}

fn check_rules(
    spec: &OperationSpec,
    rules: &FieldRules,
    params: &Value,
) -> Result<(), ValidationError> {
    if let Some(name) = rules.fields_param
        && let Some(list) = params.get(name).and_then(Value::as_array)
    {
        for entry in list {
            let text = entry.as_str().unwrap_or("");
            if !is_fields_entry(text) {
                return Err(invalid(name, "not a valid field id", Some(text)));
            }
        }
    }
    if let Some(name) = rules.expand_param
        && let Some(list) = params.get(name).and_then(Value::as_array)
    {
        for entry in list {
            let text = entry.as_str().unwrap_or("");
            if !rules.expand_allow.contains(&text) {
                return Err(invalid(name, "not an allowed expand value", Some(text)));
            }
        }
    }
    if let Some(name) = rules.fields_map_param {
        check_map_keys(name, params, spec.id == "jira.issue.create")?;
    }
    Ok(())
}

fn check_map_keys(name: &str, params: &Value, create: bool) -> Result<(), ValidationError> {
    let Some(map) = params.get(name).and_then(Value::as_object) else {
        return Ok(());
    };
    for key in map.keys() {
        if create && DEDICATED_CREATE_PARAMS.contains(&key.as_str()) {
            return Err(invalid(
                &format!("{name}.{key}"),
                "duplicates a dedicated parameter",
                None,
            ));
        }
        if !is_field_id(key) {
            return Err(invalid(
                &format!("{name}.{}", echo(key)),
                "not a valid field id",
                None,
            ));
        }
    }
    Ok(())
}

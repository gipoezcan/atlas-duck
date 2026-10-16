//! The Confluence previewers (§6.3): the search table (Task 12a). Every cell is display-escaped
//! text (the shared table cells of `jira_preview`); what a layout leaves out of the candidate is
//! counted in `hidden_in_preview_bytes`, and Raw has the exact bytes.

use atlas_duck_preview::PreviewBody;
use serde_json::{Map, Value};

use super::jira_preview::{
    TABLE_ROW_CAP, bytes_of, cell_of, omitted_row, pair_bytes, short_string, table_count,
};
use super::{PreviewCtx, PreviewInput, PreviewModel, generic};

/// §6.3 "Confluence search": the table's columns (plan text, Task 12a), in this order.
const SEARCH_COLUMNS: [&str; 4] = ["title", "space", "type", "last modified"];

/// The column added with `excerpt=indexed` (§6.3 "excerpt").
const EXCERPT_COLUMN: &str = "excerpt";

/// A root key of a search answer that is page mechanics (shown as the count), not content.
fn is_page_mechanic(key: &str, value: &Value) -> bool {
    matches!(key, "start" | "limit" | "size" | "totalSize") && value.is_number()
}

/// §6.3 "Confluence search": a row per released result with its `title`, its space
/// (`resultGlobalContainer.title`), `content.type`, `lastModified` and, only when the agent asked
/// for `excerpt=indexed`, its `excerpt`; the count "N of totalSize" (the read's paging facts).
/// `None` when the candidate holds no `results` list (an upstream-error card keeps the Fallback).
pub(crate) fn search_table(ctx: &PreviewCtx<'_>) -> Option<PreviewModel> {
    let PreviewInput::Read(view) = &ctx.input else {
        return None;
    };
    let root = view.candidate.as_object()?;
    let results = root.get("results")?.as_array()?;
    let excerpt = ctx.params.get("excerpt").and_then(Value::as_str) == Some("indexed");

    let mut hidden = root
        .iter()
        .filter(|(k, v)| k.as_str() != "results" && !is_page_mechanic(k, v))
        .fold(0u64, |sum, (k, v)| sum.saturating_add(pair_bytes(k, v)));
    let mut columns: Vec<String> = SEARCH_COLUMNS.iter().map(|c| (*c).to_owned()).collect();
    if excerpt {
        columns.push(EXCERPT_COLUMN.to_owned());
    }
    let mut rows: Vec<Vec<String>> = Vec::with_capacity(results.len().min(TABLE_ROW_CAP + 1));
    for (n, result) in results.iter().enumerate() {
        let (Some(map), true) = (result.as_object(), n < TABLE_ROW_CAP) else {
            hidden = hidden.saturating_add(bytes_of(result));
            continue;
        };
        let member = |object: &str, key: &str| {
            map.get(object)
                .and_then(Value::as_object)
                .and_then(|o| o.get(key))
        };
        let mut row = vec![
            cell_of(map.get("title"), &mut hidden),
            cell_of(member("resultGlobalContainer", "title"), &mut hidden),
            cell_of(member("content", "type"), &mut hidden),
            cell_of(map.get("lastModified"), &mut hidden),
        ];
        if excerpt {
            row.push(cell_of(map.get("excerpt"), &mut hidden));
        }
        rows.push(row);
        hidden = hidden.saturating_add(unshown_bytes(map, excerpt));
    }
    if results.len() > TABLE_ROW_CAP {
        rows.push(omitted_row(columns.len(), results.len() - TABLE_ROW_CAP));
    }

    let (mut header, warnings) = generic::read_parts(ctx, view, hidden);
    let count = table_count(&mut header, results.len());
    let query = header.query.clone();
    Some(PreviewModel {
        header,
        body: PreviewBody::Table {
            columns,
            rows,
            count,
        },
        warnings,
        query,
    })
}

/// The bytes of a result its row does not show: every key and nested key but the shown ones,
/// except a short `content.id` (the result's identifier, as a Jira issue's `id`).
fn unshown_bytes(map: &Map<String, Value>, excerpt: bool) -> u64 {
    let others = |object: &Map<String, Value>, shown: &dyn Fn(&str, &Value) -> bool| {
        object
            .iter()
            .filter(|(k, v)| !shown(k, v))
            .fold(0u64, |sum, (k, v)| sum.saturating_add(pair_bytes(k, v)))
    };
    map.iter().fold(0u64, |sum, (key, value)| {
        let unshown = match (key.as_str(), value) {
            ("title" | "lastModified", _) => 0,
            ("excerpt", _) if excerpt => 0,
            ("content", Value::Object(content)) => others(content, &|k, v| {
                k == "type" || (k == "id" && (short_string(v) || v.is_number()))
            }),
            ("resultGlobalContainer", Value::Object(space)) => others(space, &|k, _| k == "title"),
            _ => pair_bytes(key, value),
        };
        sum.saturating_add(unshown)
    })
}

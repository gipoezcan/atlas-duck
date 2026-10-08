//! I-01 response bodies for Jira 9.12 / 10.x and Confluence 8.5 / 9.x (§13).
//!
//! Only `serverInfo` (Jira) and the applinks manifest (Confluence) differ between the two versions
//! of a product for the fields M3 reads; the other bodies are shared by both versions. `core`'s
//! Task 18 test validates them against the registry result schemas.

/// The fixed `Date` used by `MockDc::with_date` tests (2026-10-07 10:00:00 UTC).
pub const FIXTURE_DATE: &str = "Wed, 07 Oct 2026 10:00:00 GMT";

pub const JIRA_9_12_VERSION: &str = "9.12.0";
pub const JIRA_10_VERSION: &str = "10.3.1";
pub const CONFLUENCE_8_5_VERSION: &str = "8.5.4";
pub const CONFLUENCE_9_VERSION: &str = "9.2.1";

/// `GET /rest/api/2/serverInfo` for a Jira version (`"9.12.0"`, `"10.3.1"`, ...).
pub fn jira_server_info(version: &str) -> String {
    let numbers: Vec<serde_json::Value> = version
        .split('.')
        .filter_map(|p| p.parse::<u64>().ok())
        .map(serde_json::Value::from)
        .collect();
    serde_json::json!({
        "baseUrl": "https://jira.corp.example",
        "version": version,
        "versionNumbers": numbers,
        "deploymentType": "Server",
        "buildNumber": 912000,
        "buildDate": "2023-11-28T00:00:00.000+0000",
        "serverTime": "2026-10-07T10:00:00.000+0000",
        "scmInfo": "0000000000000000000000000000000000000000",
        "serverTitle": "Jira"
    })
    .to_string()
}

/// `GET /rest/api/2/myself`.
pub fn jira_myself(name: &str, key: &str) -> String {
    serde_json::json!({
        "self": format!("https://jira.corp.example/rest/api/2/user?username={name}"),
        "key": key,
        "name": name,
        "emailAddress": format!("{name}@corp.example"),
        "displayName": "Jane Doe",
        "active": true,
        "deleted": false,
        "timeZone": "Europe/Berlin",
        "locale": "en_US",
        "groups": {"size": 1, "items": []},
        "applicationRoles": {"size": 1, "items": []},
        "expand": "groups,applicationRoles"
    })
    .to_string()
}

pub const JIRA_MYSELF: &str = r#"{"self":"https://jira.corp.example/rest/api/2/user?username=jdoe","key":"JIRAUSER1","name":"jdoe","emailAddress":"jdoe@corp.example","displayName":"Jane Doe","active":true,"deleted":false,"timeZone":"Europe/Berlin","locale":"en_US"}"#;

pub const JIRA_ISSUE: &str = r#"{"expand":"renderedFields,names,schema,operations,editmeta,changelog,versionedRepresentations","id":"10001","self":"https://jira.corp.example/rest/api/2/issue/10001","key":"ABC-1","fields":{"summary":"Login page times out","status":{"self":"https://jira.corp.example/rest/api/2/status/3","name":"In Progress","id":"3","statusCategory":{"id":4,"key":"indeterminate","name":"In Progress"}},"assignee":{"name":"jdoe","key":"JIRAUSER1","displayName":"Jane Doe"},"reporter":{"name":"bob","key":"JIRAUSER2","displayName":"Bob Builder"},"priority":{"name":"Major","id":"3"},"issuetype":{"id":"10002","name":"Bug","subtask":false},"project":{"id":"10000","key":"ABC","name":"Alpha Beta"},"labels":["web"],"created":"2026-10-01T09:00:00.000+0200","updated":"2026-10-06T16:30:00.000+0200","description":"Steps to reproduce: open the login page and wait."}}"#;

pub const JIRA_SEARCH_PAGE: &str = r#"{"expand":"schema,names","startAt":0,"maxResults":50,"total":2,"issues":[{"id":"10001","key":"ABC-1","self":"https://jira.corp.example/rest/api/2/issue/10001","fields":{"summary":"Login page times out","status":{"name":"In Progress","id":"3"},"assignee":{"name":"jdoe","key":"JIRAUSER1","displayName":"Jane Doe"},"priority":{"name":"Major","id":"3"},"issuetype":{"id":"10002","name":"Bug"},"updated":"2026-10-06T16:30:00.000+0200"}},{"id":"10002","key":"ABC-2","self":"https://jira.corp.example/rest/api/2/issue/10002","fields":{"summary":"Add dark mode","status":{"name":"Open","id":"1"},"assignee":null,"priority":{"name":"Minor","id":"4"},"issuetype":{"id":"10001","name":"Story"},"updated":"2026-10-05T11:00:00.000+0200"}}]}"#;

pub const JIRA_CREATEMETA_ISSUETYPES: &str = r#"{"maxResults":50,"startAt":0,"total":2,"isLast":true,"values":[{"self":"https://jira.corp.example/rest/api/2/issuetype/10001","id":"10001","description":"A user story.","name":"Story","subtask":false},{"self":"https://jira.corp.example/rest/api/2/issuetype/10002","id":"10002","description":"A problem.","name":"Bug","subtask":false}]}"#;

pub const JIRA_TRANSITIONS: &str = r#"{"expand":"transitions","transitions":[{"id":"21","name":"Start Progress","to":{"self":"https://jira.corp.example/rest/api/2/status/3","name":"In Progress","id":"3","statusCategory":{"id":4,"key":"indeterminate","name":"In Progress"}},"fields":{}},{"id":"31","name":"Done","to":{"self":"https://jira.corp.example/rest/api/2/status/10001","name":"Done","id":"10001","statusCategory":{"id":3,"key":"done","name":"Done"}},"fields":{"resolution":{"required":true,"name":"Resolution","allowedValues":[{"id":"1","name":"Fixed"}]}}}]}"#;

pub const JIRA_COMMENT: &str = r#"{"self":"https://jira.corp.example/rest/api/2/issue/10001/comment/20001","id":"20001","author":{"name":"jdoe","key":"JIRAUSER1","displayName":"Jane Doe"},"body":"Reproduced on staging.","updateAuthor":{"name":"jdoe","key":"JIRAUSER1","displayName":"Jane Doe"},"created":"2026-10-06T10:00:00.000+0200","updated":"2026-10-06T10:00:00.000+0200"}"#;

/// `GET /rest/api/user/current` for a known user.
pub fn confluence_user_current(username: &str, user_key: &str) -> String {
    serde_json::json!({
        "type": "known",
        "username": username,
        "userKey": user_key,
        "profilePicture": {"path": "/images/icons/profilepics/default.svg", "width": 48, "height": 48, "isDefault": true},
        "displayName": "Jane Doe",
        "_links": {"self": format!("https://wiki.corp.example/rest/api/user?key={user_key}")},
        "_expandable": {"status": ""}
    })
    .to_string()
}

/// `GET /rest/api/user/current` without (or with an invalid) token.
pub const CONFLUENCE_USER_ANONYMOUS: &str = r#"{"type":"anonymous","profilePicture":{"path":"/images/icons/profilepics/anonymous.svg","width":48,"height":48,"isDefault":true},"displayName":"Anonymous","_links":{"self":"https://wiki.corp.example/rest/api/user/anonymous"}}"#;

/// `GET /rest/applinks/1.0/manifest` (JSON when asked with `Accept: application/json`).
pub fn applinks_manifest(version: &str) -> String {
    serde_json::json!({
        "id": "8f2b8d0e-1c55-3a6c-9a3e-2a1f4c0f7a11",
        "name": "Confluence",
        "typeId": "confluence",
        "version": version,
        "buildNumber": 9012,
        "applinksVersion": "9.1.4",
        "inboundAuthenticationTypes": [],
        "outboundAuthenticationTypes": [],
        "publicSignup": false,
        "url": "https://wiki.corp.example",
        "iconUrl": "https://wiki.corp.example/images/logo/confluence-logo.png"
    })
    .to_string()
}

pub const CONFLUENCE_PAGE: &str = r#"{"id":"65537","type":"page","status":"current","title":"Release checklist","space":{"id":98305,"key":"DOC","name":"Documentation","type":"global"},"version":{"by":{"type":"known","username":"jdoe","userKey":"8a7f808a1","displayName":"Jane Doe"},"when":"2026-10-06T14:00:00.000+02:00","number":7,"minorEdit":false},"ancestors":[{"id":"65536","type":"page","status":"current","title":"Home"}],"body":{"storage":{"value":"<p>Check the build.</p>","representation":"storage"}},"_links":{"webui":"/display/DOC/Release+checklist","base":"https://wiki.corp.example","context":"","self":"https://wiki.corp.example/rest/api/content/65537"}}"#;

pub const CONFLUENCE_SEARCH_PAGE: &str = r#"{"results":[{"content":{"id":"65537","type":"page","status":"current","title":"Release checklist","_links":{"webui":"/display/DOC/Release+checklist","self":"https://wiki.corp.example/rest/api/content/65537"}},"title":"Release checklist","excerpt":"","url":"/display/DOC/Release+checklist","resultGlobalContainer":{"title":"Documentation","displayUrl":"/display/DOC"},"entityType":"content","lastModified":"2026-10-06T14:00:00.000+02:00"}],"start":0,"limit":25,"size":1,"totalSize":1,"cqlQuery":"type = page","searchDuration":12,"_links":{"base":"https://wiki.corp.example","context":""}}"#;

// Paged fixtures (Task 10). Item ids count from the page's offset, so a test can tell pages apart.

/// One `POST /rest/api/2/search` page: `count` issues from `start_at` (`ABC-<start_at + 1>`, ...).
pub fn jira_search_page(start_at: u64, max_results: u64, total: u64, count: u64) -> String {
    let issues: Vec<serde_json::Value> = (start_at..start_at + count)
        .map(|i| {
            serde_json::json!({
                "id": (10_001 + i).to_string(),
                "key": format!("ABC-{}", i + 1),
                "self": format!("https://jira.corp.example/rest/api/2/issue/{}", 10_001 + i),
                "fields": {"summary": format!("Issue {}", i + 1)}
            })
        })
        .collect();
    serde_json::json!({
        "expand": "schema,names",
        "startAt": start_at,
        "maxResults": max_results,
        "total": total,
        "issues": issues
    })
    .to_string()
}

/// One Jira Agile page (`/rest/agile/1.0/board`): `values` and `isLast`, no `total` when `None`.
pub fn jira_board_page(start_at: u64, max_results: u64, total: Option<u64>, count: u64) -> String {
    let values: Vec<serde_json::Value> = (start_at..start_at + count)
        .map(|i| serde_json::json!({"id": i + 1, "name": format!("Board {}", i + 1), "type": "scrum"}))
        .collect();
    let mut page = serde_json::json!({
        "maxResults": max_results,
        "startAt": start_at,
        "isLast": total.is_some_and(|t| start_at + count >= t),
        "values": values
    });
    if let (Some(t), Some(obj)) = (total, page.as_object_mut()) {
        obj.insert("total".to_owned(), t.into());
    }
    page.to_string()
}

/// One `GET /rest/api/space` page: `size` spaces from `start`; `next` is the origin-relative
/// `_links.next` Confluence DC sends (without the context path), absent on the last page.
pub fn confluence_space_page(start: u64, limit: u64, size: u64, next: Option<&str>) -> String {
    confluence_space_page_padded(start, limit, size, next, 0)
}

/// `confluence_space_page` with a `padding` string of `pad` bytes (cap tests).
pub fn confluence_space_page_padded(
    start: u64,
    limit: u64,
    size: u64,
    next: Option<&str>,
    pad: usize,
) -> String {
    let results: Vec<serde_json::Value> = (start..start + size)
        .map(|i| {
            serde_json::json!({
                "id": 98_305 + i,
                "key": format!("S{}", i + 1),
                "name": format!("Space {}", i + 1),
                "type": "global"
            })
        })
        .collect();
    let mut links = serde_json::json!({
        "base": "https://wiki.corp.example",
        "context": "",
        "self": "https://wiki.corp.example/rest/api/space"
    });
    if let (Some(n), Some(obj)) = (next, links.as_object_mut()) {
        obj.insert("next".to_owned(), n.into());
    }
    serde_json::json!({
        "results": results,
        "start": start,
        "limit": limit,
        "size": size,
        "padding": " ".repeat(pad),
        "_links": links
    })
    .to_string()
}

// Write responses (Task 10, I-25).

/// `POST /rest/api/2/issue` → 201.
pub const JIRA_ISSUE_CREATED: &str =
    r#"{"id":"10003","key":"ABC-3","self":"https://jira.corp.example/rest/api/2/issue/10003"}"#;

/// A Jira 400 validation error.
pub const JIRA_ERROR_400: &str =
    r#"{"errorMessages":[],"errors":{"summary":"You must specify a summary of the issue."}}"#;

/// `PUT /rest/api/content/{id}` → 200 (the updated page, version 8).
pub const CONFLUENCE_PAGE_UPDATED: &str = r#"{"id":"65537","type":"page","status":"current","title":"Release checklist","version":{"by":{"type":"known","username":"jdoe","userKey":"8a7f808a1","displayName":"Jane Doe"},"when":"2026-10-07T10:00:00.000+02:00","number":8,"minorEdit":false},"_links":{"webui":"/display/DOC/Release+checklist","base":"https://wiki.corp.example","context":"","self":"https://wiki.corp.example/rest/api/content/65537"}}"#;

/// Confluence DC's answer to a stale `version.number` (409).
pub const CONFLUENCE_VERSION_CONFLICT_409: &str = r#"{"statusCode":409,"data":{"authorized":false,"valid":true,"errors":[],"successful":false},"message":"Version must be incremented on update. Current version is: 8"}"#;

/// The 400 form of a version conflict (V04/V06 confirm the exact text in M7).
pub const CONFLUENCE_VERSION_CONFLICT_400: &str = r#"{"statusCode":400,"data":{"authorized":false,"valid":true,"errors":[],"successful":false},"message":"Version must be incremented on update. Current version is: 8"}"#;

/// A Confluence 400 that is not about versions.
pub const CONFLUENCE_ERROR_400: &str = r#"{"statusCode":400,"data":{"authorized":false,"valid":true,"errors":[],"successful":false},"message":"A page with this title already exists in this space"}"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fixture_is_json() {
        let owned = [
            jira_server_info(JIRA_9_12_VERSION),
            jira_server_info(JIRA_10_VERSION),
            jira_myself("jdoe", "JIRAUSER1"),
            confluence_user_current("jdoe", "8a7f808a1"),
            applinks_manifest(CONFLUENCE_8_5_VERSION),
            applinks_manifest(CONFLUENCE_9_VERSION),
            jira_search_page(50, 50, 120, 50),
            jira_board_page(0, 50, Some(3), 3),
            jira_board_page(0, 50, None, 3),
            confluence_space_page(0, 25, 25, Some("/rest/api/space?limit=25&start=25")),
            confluence_space_page_padded(25, 25, 10, None, 16),
        ];
        let fixed = [
            JIRA_MYSELF,
            JIRA_ISSUE,
            JIRA_SEARCH_PAGE,
            JIRA_CREATEMETA_ISSUETYPES,
            JIRA_TRANSITIONS,
            JIRA_COMMENT,
            CONFLUENCE_USER_ANONYMOUS,
            CONFLUENCE_PAGE,
            CONFLUENCE_SEARCH_PAGE,
            JIRA_ISSUE_CREATED,
            JIRA_ERROR_400,
            CONFLUENCE_PAGE_UPDATED,
            CONFLUENCE_VERSION_CONFLICT_409,
            CONFLUENCE_VERSION_CONFLICT_400,
            CONFLUENCE_ERROR_400,
        ];
        for body in owned.iter().map(String::as_str).chain(fixed) {
            assert!(
                serde_json::from_str::<serde_json::Value>(body).is_ok(),
                "{body}"
            );
        }
        let info: serde_json::Value =
            serde_json::from_str(&jira_server_info("9.12.0")).unwrap_or(serde_json::Value::Null);
        assert_eq!(info["version"], "9.12.0");
        assert_eq!(info["versionNumbers"], serde_json::json!([9, 12, 0]));
    }
}

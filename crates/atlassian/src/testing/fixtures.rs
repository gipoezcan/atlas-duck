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

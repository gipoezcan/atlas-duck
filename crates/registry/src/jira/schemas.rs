//! JSON text for the Jira catalog: params schemas (draft 2020-12, `additionalProperties: false`,
//! one `examples[0]` each), realistic anonymized DC examples (`example.invalid` hosts), sparse
//! examples (same shape, nullables `null`, item arrays `[]`) and result/receipt schemas.

// ---- shared params ---------------------------------------------------------------------------

pub(crate) const EMPTY_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"properties":{},"examples":[{}]}"#;

pub(crate) const KEY_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["key"],"properties":{"key":{"type":"string","pattern":"^[A-Z][A-Z0-9_]*-[0-9]+$"}},"examples":[{"key":"ABC-123"}]}"#;

/// `jira.sprint.issues` and `jira.backlog.issues`.
pub(crate) const AGILE_ISSUES_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["id"],
 "properties":{
  "id":{"type":"integer","minimum":1},
  "jql":{"type":"string","minLength":1,"maxLength":20000},
  "fields":{"type":"array","items":{"type":"string"},"maxItems":200},
  "start":{"type":"integer","minimum":0,"default":0},
  "max":{"type":"integer","minimum":1,"default":50}},
 "examples":[{"id":42}]}"#;

// ---- jira.myself / project.* -----------------------------------------------------------------

pub(crate) const MYSELF_EXAMPLE: &str = r#"{"self":"https://jira.example.invalid/rest/api/2/user?username=jdoe","key":"JIRAUSER10100","name":"jdoe","emailAddress":"jane.doe@example.invalid","displayName":"Jane Doe","active":true,"timeZone":"Europe/Berlin","locale":"en_US"}"#;
pub(crate) const MYSELF_EXAMPLE_SPARSE: &str = r#"{"self":"https://jira.example.invalid/rest/api/2/user?username=jdoe","key":"JIRAUSER10100","name":"jdoe","emailAddress":null,"displayName":"Jane Doe","active":true,"timeZone":null,"locale":null}"#;
pub(crate) const MYSELF_RESULT: &str = r#"{"type":"object","required":["name","key","displayName","active"],"properties":{"self":{"type":"string"},"key":{"type":"string"},"name":{"type":"string"},"emailAddress":{"type":["string","null"]},"displayName":{"type":"string"},"active":{"type":"boolean"},"timeZone":{"type":["string","null"]},"locale":{"type":["string","null"]}}}"#;

pub(crate) const PROJECT_LIST_EXAMPLE: &str = r#"[{"self":"https://jira.example.invalid/rest/api/2/project/10000","id":"10000","key":"ABC","name":"Alpha Beta Cooperation","projectTypeKey":"software"}]"#;
pub(crate) const PROJECT_LIST_EXAMPLE_SPARSE: &str = r#"[]"#;
pub(crate) const PROJECT_LIST_RESULT: &str = r#"{"type":"array","items":{"type":"object","required":["id","key","name"],"properties":{"self":{"type":"string"},"id":{"type":"string"},"key":{"type":"string"},"name":{"type":"string"},"projectTypeKey":{"type":["string","null"]}}}}"#;

pub(crate) const PROJECT_GET_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["key"],"properties":{"key":{"type":"string","pattern":"^[A-Za-z0-9_-]+$"}},"examples":[{"key":"ABC"}]}"#;
pub(crate) const PROJECT_GET_EXAMPLE: &str = r#"{"self":"https://jira.example.invalid/rest/api/2/project/10000","id":"10000","key":"ABC","name":"Alpha Beta Cooperation","description":"Internal tooling.","lead":{"name":"jdoe","key":"JIRAUSER10100","displayName":"Jane Doe","active":true},"components":[{"id":"10200","name":"Auth"}],"issueTypes":[{"id":"10004","name":"Bug","subtask":false}],"projectTypeKey":"software"}"#;
pub(crate) const PROJECT_GET_EXAMPLE_SPARSE: &str = r#"{"self":"https://jira.example.invalid/rest/api/2/project/10000","id":"10000","key":"ABC","name":"Alpha Beta Cooperation","description":null,"lead":null,"components":[],"issueTypes":[],"projectTypeKey":null}"#;
pub(crate) const PROJECT_GET_RESULT: &str = r#"{"type":"object","required":["id","key","name"],"properties":{"self":{"type":"string"},"id":{"type":"string"},"key":{"type":"string"},"name":{"type":"string"},"description":{"type":["string","null"]},"lead":{"type":["object","null"]},"components":{"type":"array","items":{"type":"object"}},"issueTypes":{"type":"array","items":{"type":"object"}},"projectTypeKey":{"type":["string","null"]}}}"#;

// ---- jira.issue.get --------------------------------------------------------------------------

pub(crate) const ISSUE_GET_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["key"],
 "properties":{
  "key":{"type":"string","pattern":"^[A-Z][A-Z0-9_]*-[0-9]+$"},
  "fields":{"type":"array","items":{"type":"string"},"maxItems":200},
  "expand":{"type":"array","items":{"type":"string"},"maxItems":8},
  "comments":{"type":"boolean","default":false},
  "changelog":{"type":"boolean","default":false},
  "rendered":{"type":"boolean","default":false}},
 "examples":[{"key":"ABC-123"}]}"#;
pub(crate) const ISSUE_GET_EXAMPLE: &str = r#"{"expand":"","id":"10001","self":"https://jira.example.invalid/rest/api/2/issue/10001","key":"ABC-123","fields":{"summary":"Login fails after password reset","status":{"id":"1","name":"Open"},"issuetype":{"id":"10004","name":"Bug"},"priority":{"id":"3","name":"Major"},"assignee":{"name":"jdoe","key":"JIRAUSER10100","displayName":"Jane Doe","active":true},"reporter":{"name":"asmith","key":"JIRAUSER10101","displayName":"Alex Smith","active":true},"created":"2026-09-01T09:12:44.000+0200","updated":"2026-09-03T14:02:10.000+0200","labels":["backend"],"components":[{"id":"10200","name":"Auth"}],"fixVersions":[{"id":"10300","name":"1.4"}],"parent":{"id":"10000","key":"ABC-100","fields":{"summary":"Auth rework"}},"description":"Users cannot log in after resetting the password.","issuelinks":[{"id":"10500","type":{"id":"10000","name":"Blocks"},"outwardIssue":{"id":"10002","key":"ABC-124"}}],"security":null}}"#;
pub(crate) const ISSUE_GET_EXAMPLE_SPARSE: &str = r#"{"expand":"","id":"10001","self":"https://jira.example.invalid/rest/api/2/issue/10001","key":"ABC-123","fields":{"summary":"Login fails after password reset","status":{"id":"1","name":"Open"},"issuetype":{"id":"10004","name":"Bug"},"priority":null,"assignee":null,"reporter":null,"created":"2026-09-01T09:12:44.000+0200","updated":"2026-09-03T14:02:10.000+0200","labels":[],"components":[],"fixVersions":[],"parent":null,"description":null,"issuelinks":[],"security":null}}"#;
pub(crate) const ISSUE_GET_RESULT: &str = r#"{"type":"object","required":["key","fields"],"properties":{"expand":{"type":"string"},"id":{"type":"string"},"self":{"type":"string"},"key":{"type":"string"},"fields":{"type":"object","properties":{"summary":{"type":"string"},"status":{"type":"object"},"issuetype":{"type":"object"},"priority":{"type":["object","null"]},"assignee":{"type":["object","null"]},"reporter":{"type":["object","null"]},"created":{"type":"string"},"updated":{"type":"string"},"labels":{"type":"array","items":{"type":"string"}},"components":{"type":"array","items":{"type":"object"}},"fixVersions":{"type":"array","items":{"type":"object"}},"parent":{"type":["object","null"]},"description":{"type":["string","null"]},"issuelinks":{"type":"array","items":{"type":"object"}},"security":{"type":["object","null"]}}},"renderedFields":{"type":"object"},"names":{"type":"object"},"schema":{"type":"object"},"editmeta":{"type":"object"},"changelog":{"type":"object"}}}"#;

// ---- jira.search -----------------------------------------------------------------------------

pub(crate) const SEARCH_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["jql"],
 "properties":{
  "jql":{"type":"string","minLength":1,"maxLength":20000},
  "fields":{"type":"array","items":{"type":"string"},"maxItems":200},
  "expand":{"type":"array","items":{"type":"string"},"maxItems":8},
  "start":{"type":"integer","minimum":0,"default":0},
  "max":{"type":"integer","minimum":1,"default":50}},
 "examples":[{"jql":"project = ABC AND status = Open ORDER BY updated DESC"}]}"#;
pub(crate) const SEARCH_EXAMPLE: &str = r#"{"expand":"schema,names","startAt":0,"maxResults":50,"total":1,"issues":[{"id":"10001","self":"https://jira.example.invalid/rest/api/2/issue/10001","key":"ABC-123","fields":{"summary":"Login fails after password reset","status":{"id":"1","name":"Open"},"assignee":{"name":"jdoe","key":"JIRAUSER10100","displayName":"Jane Doe","active":true},"priority":{"id":"3","name":"Major"},"issuetype":{"id":"10004","name":"Bug"},"updated":"2026-09-03T14:02:10.000+0200"}}],"names":{"summary":"Summary","status":"Status"},"schema":{"summary":{"type":"string","system":"summary"}}}"#;
pub(crate) const SEARCH_EXAMPLE_SPARSE: &str = r#"{"expand":"schema,names","startAt":0,"maxResults":50,"total":0,"issues":[],"names":{},"schema":{}}"#;
pub(crate) const SEARCH_RESULT: &str = r#"{"type":"object","required":["startAt","maxResults","total","issues"],"properties":{"expand":{"type":"string"},"startAt":{"type":"integer"},"maxResults":{"type":"integer"},"total":{"type":"integer"},"issues":{"type":"array","items":{"type":"object","required":["key"],"properties":{"id":{"type":"string"},"self":{"type":"string"},"key":{"type":"string"},"fields":{"type":"object"},"renderedFields":{"type":"object"},"changelog":{"type":"object"}}}},"names":{"type":"object"},"schema":{"type":"object"}}}"#;

// ---- jira.comment.list / worklog.list --------------------------------------------------------

pub(crate) const COMMENT_LIST_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["key"],
 "properties":{
  "key":{"type":"string","pattern":"^[A-Z][A-Z0-9_]*-[0-9]+$"},
  "start":{"type":"integer","minimum":0,"default":0},
  "max":{"type":"integer","minimum":1,"default":50}},
 "examples":[{"key":"ABC-123"}]}"#;
pub(crate) const COMMENT_LIST_EXAMPLE: &str = r#"{"startAt":0,"maxResults":50,"total":1,"comments":[{"self":"https://jira.example.invalid/rest/api/2/issue/10001/comment/10900","id":"10900","author":{"name":"asmith","key":"JIRAUSER10101","displayName":"Alex Smith","active":true},"body":"Reproduced on 9.12.","updateAuthor":{"name":"asmith","key":"JIRAUSER10101","displayName":"Alex Smith","active":true},"created":"2026-09-02T10:00:00.000+0200","updated":"2026-09-02T10:00:00.000+0200"}]}"#;
pub(crate) const COMMENT_LIST_EXAMPLE_SPARSE: &str =
    r#"{"startAt":0,"maxResults":50,"total":0,"comments":[]}"#;
pub(crate) const COMMENT_LIST_RESULT: &str = r#"{"type":"object","required":["startAt","maxResults","total","comments"],"properties":{"startAt":{"type":"integer"},"maxResults":{"type":"integer"},"total":{"type":"integer"},"comments":{"type":"array","items":{"type":"object","required":["id"],"properties":{"self":{"type":"string"},"id":{"type":"string"},"author":{"type":["object","null"]},"body":{"type":["string","null"]},"updateAuthor":{"type":["object","null"]},"created":{"type":"string"},"updated":{"type":"string"},"visibility":{"type":["object","null"]}}}}}}"#;

pub(crate) const WORKLOG_LIST_EXAMPLE: &str = r#"{"startAt":0,"maxResults":1048576,"total":1,"worklogs":[{"self":"https://jira.example.invalid/rest/api/2/issue/10001/worklog/11000","id":"11000","issueId":"10001","author":{"name":"jdoe","key":"JIRAUSER10100","displayName":"Jane Doe","active":true},"comment":"Investigation","created":"2026-09-02T11:00:00.000+0200","updated":"2026-09-02T11:00:00.000+0200","started":"2026-09-02T09:00:00.000+0200","timeSpent":"2h","timeSpentSeconds":7200}]}"#;
pub(crate) const WORKLOG_LIST_EXAMPLE_SPARSE: &str =
    r#"{"startAt":0,"maxResults":1048576,"total":0,"worklogs":[]}"#;
pub(crate) const WORKLOG_LIST_RESULT: &str = r#"{"type":"object","required":["total","worklogs"],"properties":{"startAt":{"type":"integer"},"maxResults":{"type":"integer"},"total":{"type":"integer"},"worklogs":{"type":"array","items":{"type":"object","required":["id"],"properties":{"self":{"type":"string"},"id":{"type":"string"},"issueId":{"type":"string"},"author":{"type":["object","null"]},"comment":{"type":["string","null"]},"created":{"type":"string"},"updated":{"type":"string"},"started":{"type":"string"},"timeSpent":{"type":"string"},"timeSpentSeconds":{"type":"integer"}}}}}}"#;

// ---- jira.transition.list / issue.editmeta ---------------------------------------------------

pub(crate) const TRANSITION_LIST_EXAMPLE: &str = r#"{"expand":"transitions","transitions":[{"id":"21","name":"In Progress","to":{"id":"3","name":"In Progress","statusCategory":{"key":"indeterminate"}},"hasScreen":false,"fields":{}}]}"#;
pub(crate) const TRANSITION_LIST_EXAMPLE_SPARSE: &str =
    r#"{"expand":"transitions","transitions":[]}"#;
pub(crate) const TRANSITION_LIST_RESULT: &str = r#"{"type":"object","required":["transitions"],"properties":{"expand":{"type":"string"},"transitions":{"type":"array","items":{"type":"object","required":["id","name"],"properties":{"id":{"type":"string"},"name":{"type":"string"},"to":{"type":"object"},"hasScreen":{"type":"boolean"},"fields":{"type":"object"}}}}}}"#;

pub(crate) const EDITMETA_EXAMPLE: &str = r#"{"fields":{"summary":{"required":true,"name":"Summary","key":"summary","operations":["set"],"schema":{"type":"string","system":"summary"}},"labels":{"required":false,"name":"Labels","key":"labels","operations":["add","set","remove"],"schema":{"type":"array","items":"string","system":"labels"}}}}"#;
pub(crate) const EDITMETA_EXAMPLE_SPARSE: &str = r#"{"fields":{}}"#;
pub(crate) const EDITMETA_RESULT: &str =
    r#"{"type":"object","required":["fields"],"properties":{"fields":{"type":"object"}}}"#;

// ---- jira.createmeta.* -----------------------------------------------------------------------

pub(crate) const CREATEMETA_ISSUETYPES_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["project"],"properties":{"project":{"type":"string","pattern":"^[A-Za-z0-9_-]+$"}},"examples":[{"project":"ABC"}]}"#;
pub(crate) const CREATEMETA_ISSUETYPES_EXAMPLE: &str = r#"{"maxResults":50,"startAt":0,"total":2,"isLast":true,"values":[{"self":"https://jira.example.invalid/rest/api/2/issuetype/10004","id":"10004","name":"Bug","description":"A problem.","iconUrl":"https://jira.example.invalid/images/icons/bug.png","subtask":false},{"self":"https://jira.example.invalid/rest/api/2/issuetype/10005","id":"10005","name":"Task","description":null,"iconUrl":"https://jira.example.invalid/images/icons/task.png","subtask":false}]}"#;
pub(crate) const CREATEMETA_ISSUETYPES_EXAMPLE_SPARSE: &str =
    r#"{"maxResults":50,"startAt":0,"total":0,"isLast":true,"values":[]}"#;
pub(crate) const CREATEMETA_ISSUETYPES_RESULT: &str = r#"{"type":"object","required":["values"],"properties":{"maxResults":{"type":"integer"},"startAt":{"type":"integer"},"total":{"type":"integer"},"isLast":{"type":"boolean"},"values":{"type":"array","items":{"type":"object","required":["id","name"],"properties":{"self":{"type":"string"},"id":{"type":"string"},"name":{"type":"string"},"description":{"type":["string","null"]},"iconUrl":{"type":["string","null"]},"subtask":{"type":"boolean"}}}}}}"#;

pub(crate) const CREATEMETA_FIELDS_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["project","typeId"],"properties":{"project":{"type":"string","pattern":"^[A-Za-z0-9_-]+$"},"typeId":{"type":"string","pattern":"^[0-9]+$"}},"examples":[{"project":"ABC","typeId":"10004"}]}"#;
pub(crate) const CREATEMETA_FIELDS_EXAMPLE: &str = r#"{"maxResults":50,"startAt":0,"total":2,"isLast":true,"values":[{"required":true,"schema":{"type":"string","system":"summary"},"name":"Summary","fieldId":"summary","hasDefaultValue":false,"operations":["set"]},{"required":true,"schema":{"type":"option","custom":"com.atlassian.jira.plugin.system.customfieldtypes:select","customId":10200},"name":"Team","fieldId":"customfield_10200","hasDefaultValue":false,"operations":["set"],"allowedValues":[{"id":"10400","value":"Platform"}]}]}"#;
pub(crate) const CREATEMETA_FIELDS_EXAMPLE_SPARSE: &str =
    r#"{"maxResults":50,"startAt":0,"total":0,"isLast":true,"values":[]}"#;
pub(crate) const CREATEMETA_FIELDS_RESULT: &str = r#"{"type":"object","required":["values"],"properties":{"maxResults":{"type":"integer"},"startAt":{"type":"integer"},"total":{"type":"integer"},"isLast":{"type":"boolean"},"values":{"type":"array","items":{"type":"object","required":["fieldId","required"],"properties":{"required":{"type":"boolean"},"schema":{"type":["object","null"]},"name":{"type":"string"},"fieldId":{"type":"string"},"hasDefaultValue":{"type":"boolean"},"operations":{"type":"array","items":{"type":"string"}},"allowedValues":{"type":"array","items":{"type":"object"}}}}}}}"#;

// ---- jira.field.list / issuelinktype.list ----------------------------------------------------

pub(crate) const FIELD_LIST_EXAMPLE: &str = r#"[{"id":"summary","name":"Summary","custom":false,"orderable":true,"navigable":true,"searchable":true,"clauseNames":["summary"],"schema":{"type":"string","system":"summary"}},{"id":"customfield_10200","name":"Team","custom":true,"orderable":true,"navigable":true,"searchable":true,"clauseNames":["cf[10200]","Team"],"schema":{"type":"option","custom":"com.atlassian.jira.plugin.system.customfieldtypes:select","customId":10200}}]"#;
pub(crate) const FIELD_LIST_EXAMPLE_SPARSE: &str = r#"[]"#;
pub(crate) const FIELD_LIST_RESULT: &str = r#"{"type":"array","items":{"type":"object","required":["id","name"],"properties":{"id":{"type":"string"},"name":{"type":"string"},"custom":{"type":"boolean"},"orderable":{"type":"boolean"},"navigable":{"type":"boolean"},"searchable":{"type":"boolean"},"clauseNames":{"type":"array","items":{"type":"string"}},"schema":{"type":["object","null"]}}}}"#;

pub(crate) const ISSUELINKTYPE_LIST_EXAMPLE: &str = r#"{"issueLinkTypes":[{"id":"10000","name":"Blocks","inward":"is blocked by","outward":"blocks","self":"https://jira.example.invalid/rest/api/2/issueLinkType/10000"}]}"#;
pub(crate) const ISSUELINKTYPE_LIST_EXAMPLE_SPARSE: &str = r#"{"issueLinkTypes":[]}"#;
pub(crate) const ISSUELINKTYPE_LIST_RESULT: &str = r#"{"type":"object","required":["issueLinkTypes"],"properties":{"issueLinkTypes":{"type":"array","items":{"type":"object","required":["id","name","inward","outward"],"properties":{"id":{"type":"string"},"name":{"type":"string"},"inward":{"type":"string"},"outward":{"type":"string"},"self":{"type":"string"}}}}}}"#;

// ---- jira.attachment.meta --------------------------------------------------------------------

pub(crate) const ATTACHMENT_META_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["id"],"properties":{"id":{"type":"string","pattern":"^[0-9]+$"}},"examples":[{"id":"12000"}]}"#;
pub(crate) const ATTACHMENT_META_EXAMPLE: &str = r#"{"self":"https://jira.example.invalid/rest/api/2/attachment/12000","id":"12000","filename":"screenshot.png","author":{"name":"asmith","key":"JIRAUSER10101","displayName":"Alex Smith","active":true},"created":"2026-09-02T10:05:00.000+0200","size":48213,"mimeType":"image/png","content":"https://jira.example.invalid/secure/attachment/12000/screenshot.png","thumbnail":"https://jira.example.invalid/secure/thumbnail/12000/screenshot.png"}"#;
pub(crate) const ATTACHMENT_META_EXAMPLE_SPARSE: &str = r#"{"self":"https://jira.example.invalid/rest/api/2/attachment/12000","id":"12000","filename":"notes.txt","author":null,"created":"2026-09-02T10:05:00.000+0200","size":12,"mimeType":null,"content":"https://jira.example.invalid/secure/attachment/12000/notes.txt","thumbnail":null}"#;
pub(crate) const ATTACHMENT_META_RESULT: &str = r#"{"type":"object","required":["id","filename"],"properties":{"self":{"type":"string"},"id":{"type":"string"},"filename":{"type":"string"},"author":{"type":["object","null"]},"created":{"type":"string"},"size":{"type":"integer"},"mimeType":{"type":["string","null"]},"content":{"type":["string","null"]},"thumbnail":{"type":["string","null"]}}}"#;

// ---- jira.user.assignable --------------------------------------------------------------------

pub(crate) const USER_ASSIGNABLE_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["username"],
 "properties":{
  "username":{"type":"string","minLength":1,"maxLength":255},
  "project":{"type":"string","pattern":"^[A-Za-z0-9_-]+$"},
  "issueKey":{"type":"string","pattern":"^[A-Z][A-Z0-9_]*-[0-9]+$"},
  "max":{"type":"integer","minimum":1,"default":50}},
 "examples":[{"username":"jdoe","project":"ABC"}]}"#;
pub(crate) const USER_ASSIGNABLE_EXAMPLE: &str = r#"[{"self":"https://jira.example.invalid/rest/api/2/user?username=jdoe","key":"JIRAUSER10100","name":"jdoe","emailAddress":"jane.doe@example.invalid","displayName":"Jane Doe","active":true}]"#;
pub(crate) const USER_ASSIGNABLE_EXAMPLE_SPARSE: &str = r#"[]"#;
pub(crate) const USER_ASSIGNABLE_RESULT: &str = r#"{"type":"array","items":{"type":"object","required":["name","key"],"properties":{"self":{"type":"string"},"key":{"type":"string"},"name":{"type":"string"},"emailAddress":{"type":["string","null"]},"displayName":{"type":"string"},"active":{"type":"boolean"}}}}"#;

// ---- jira.board.list / sprint.list / sprint.issues / backlog.issues --------------------------

pub(crate) const BOARD_LIST_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "properties":{
  "name":{"type":"string","minLength":1,"maxLength":255},
  "start":{"type":"integer","minimum":0,"default":0},
  "max":{"type":"integer","minimum":1,"default":50}},
 "examples":[{"name":"ABC board"}]}"#;
pub(crate) const BOARD_LIST_EXAMPLE: &str = r#"{"maxResults":50,"startAt":0,"total":1,"isLast":true,"values":[{"id":42,"self":"https://jira.example.invalid/rest/agile/1.0/board/42","name":"ABC board","type":"scrum"}]}"#;
pub(crate) const BOARD_LIST_EXAMPLE_SPARSE: &str =
    r#"{"maxResults":50,"startAt":0,"total":0,"isLast":true,"values":[]}"#;
pub(crate) const BOARD_LIST_RESULT: &str = r#"{"type":"object","required":["values"],"properties":{"maxResults":{"type":"integer"},"startAt":{"type":"integer"},"total":{"type":"integer"},"isLast":{"type":"boolean"},"values":{"type":"array","items":{"type":"object","required":["id","name"],"properties":{"id":{"type":"integer"},"self":{"type":"string"},"name":{"type":"string"},"type":{"type":"string"}}}}}}"#;

pub(crate) const SPRINT_LIST_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["id"],
 "properties":{
  "id":{"type":"integer","minimum":1},
  "state":{"type":"string","enum":["future","active","closed"]},
  "start":{"type":"integer","minimum":0,"default":0},
  "max":{"type":"integer","minimum":1,"default":50}},
 "examples":[{"id":42,"state":"active"}]}"#;
pub(crate) const SPRINT_LIST_EXAMPLE: &str = r#"{"maxResults":50,"startAt":0,"total":1,"isLast":true,"values":[{"id":7,"self":"https://jira.example.invalid/rest/agile/1.0/sprint/7","state":"active","name":"Sprint 7","startDate":"2026-09-28T08:00:00.000Z","endDate":"2026-10-12T16:00:00.000Z","originBoardId":42,"goal":"Ship login fixes"}]}"#;
pub(crate) const SPRINT_LIST_EXAMPLE_SPARSE: &str =
    r#"{"maxResults":50,"startAt":0,"total":0,"isLast":true,"values":[]}"#;
pub(crate) const SPRINT_LIST_RESULT: &str = r#"{"type":"object","required":["values"],"properties":{"maxResults":{"type":"integer"},"startAt":{"type":"integer"},"total":{"type":"integer"},"isLast":{"type":"boolean"},"values":{"type":"array","items":{"type":"object","required":["id","state","name"],"properties":{"id":{"type":"integer"},"self":{"type":"string"},"state":{"type":"string"},"name":{"type":"string"},"startDate":{"type":["string","null"]},"endDate":{"type":["string","null"]},"originBoardId":{"type":"integer"},"goal":{"type":["string","null"]}}}}}}"#;

pub(crate) const AGILE_ISSUES_EXAMPLE: &str = r#"{"expand":"schema,names","startAt":0,"maxResults":50,"total":1,"issues":[{"id":"10001","self":"https://jira.example.invalid/rest/agile/1.0/issue/10001","key":"ABC-123","fields":{"summary":"Login fails after password reset","status":{"id":"1","name":"Open"},"assignee":{"name":"jdoe","key":"JIRAUSER10100","displayName":"Jane Doe","active":true}}}]}"#;
pub(crate) const AGILE_ISSUES_EXAMPLE_SPARSE: &str =
    r#"{"expand":"schema,names","startAt":0,"maxResults":50,"total":0,"issues":[]}"#;
pub(crate) const AGILE_ISSUES_RESULT: &str = r#"{"type":"object","required":["issues"],"properties":{"expand":{"type":"string"},"startAt":{"type":"integer"},"maxResults":{"type":"integer"},"total":{"type":"integer"},"issues":{"type":"array","items":{"type":"object","required":["key"],"properties":{"id":{"type":"string"},"self":{"type":"string"},"key":{"type":"string"},"fields":{"type":"object"}}}}}}"#;

// ---- writes ----------------------------------------------------------------------------------

pub(crate) const ISSUE_CREATE_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["project","issuetype","summary"],
 "properties":{
  "project":{"type":"string","minLength":1,"maxLength":255},
  "issuetype":{"type":"string","minLength":1,"maxLength":255},
  "summary":{"type":"string","minLength":1,"maxLength":255},
  "description":{"type":"string","maxLength":32768},
  "body_format":{"type":"string","enum":["markdown","wiki"],"default":"markdown"},
  "fields":{"type":"object","propertyNames":{"pattern":"^([a-z][A-Za-z0-9_]*|customfield_[0-9]+)$"},"description":"Extra Jira fields in REST shape, keyed by system field id or customfield_N; a key that duplicates a dedicated param is rejected."}},
 "examples":[{"project":"ABC","issuetype":"Bug","summary":"Login fails after password reset","description":"Steps to reproduce: ...","fields":{"customfield_10200":{"value":"Platform"}}}]}"#;
pub(crate) const ISSUE_CREATE_EXAMPLE: &str = r#"{"id":"10002","key":"ABC-124"}"#;
pub(crate) const ISSUE_CREATE_EXAMPLE_SPARSE: &str = r#"{"id":"10002","key":"ABC-124"}"#;
pub(crate) const ISSUE_CREATE_RESULT: &str = r#"{"type":"object","additionalProperties":false,"required":["id","key"],"properties":{"id":{"type":"string"},"key":{"type":"string"}}}"#;

pub(crate) const ISSUE_EDIT_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["key"],
 "properties":{
  "key":{"type":"string","pattern":"^[A-Z][A-Z0-9_]*-[0-9]+$"},
  "fields":{"type":"object","propertyNames":{"pattern":"^([a-z][A-Za-z0-9_]*|customfield_[0-9]+)$"}},
  "update":{"type":"object","description":"Jira update operations, e.g. {\"labels\":[{\"add\":\"x\"}]}."},
  "expected":{"type":"object","description":"{field id: value as read}; a mismatch at enrichment puts the request in the conflict state. Recommended for every edited field, especially description."}},
 "examples":[{"key":"ABC-123","fields":{"summary":"Login fails after reset"},"expected":{"summary":"Login fails after password reset"}}]}"#;

pub(crate) const COMMENT_ADD_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["key","body"],
 "properties":{
  "key":{"type":"string","pattern":"^[A-Z][A-Z0-9_]*-[0-9]+$"},
  "body":{"type":"string","minLength":1,"maxLength":32768},
  "body_format":{"type":"string","enum":["markdown","wiki"],"default":"markdown"},
  "visibility":{"type":"object","additionalProperties":false,"required":["type","value"],"properties":{"type":{"type":"string","enum":["group","role"]},"value":{"type":"string","minLength":1}}}},
 "examples":[{"key":"ABC-123","body":"Fixed in 1.4."}]}"#;
pub(crate) const COMMENT_ADD_EXAMPLE: &str = r#"{"id":"10901"}"#;
pub(crate) const COMMENT_ADD_EXAMPLE_SPARSE: &str = r#"{"id":"10901"}"#;
pub(crate) const COMMENT_ADD_RESULT: &str = r#"{"type":"object","additionalProperties":false,"required":["id"],"properties":{"id":{"type":"string"}}}"#;

pub(crate) const ISSUE_TRANSITION_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["key","transition"],
 "properties":{
  "key":{"type":"string","pattern":"^[A-Z][A-Z0-9_]*-[0-9]+$"},
  "transition":{"type":"string","minLength":1,"description":"Transition name or id; the app resolves it."},
  "fields":{"type":"object","propertyNames":{"pattern":"^([a-z][A-Za-z0-9_]*|customfield_[0-9]+)$"}},
  "comment":{"type":"string","minLength":1,"maxLength":32768}},
 "examples":[{"key":"ABC-123","transition":"In Progress"}]}"#;

pub(crate) const ISSUE_ASSIGN_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["key","assignee"],
 "properties":{
  "key":{"type":"string","pattern":"^[A-Z][A-Z0-9_]*-[0-9]+$"},
  "assignee":{"type":["string","null"],"description":"Username, or null to unassign."}},
 "examples":[{"key":"ABC-123","assignee":"jdoe"}]}"#;

pub(crate) const WORKLOG_ADD_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["key","time_spent"],
 "properties":{
  "key":{"type":"string","pattern":"^[A-Z][A-Z0-9_]*-[0-9]+$"},
  "time_spent":{"type":"string","pattern":"^[0-9]+[wdhm]( [0-9]+[wdhm])*$"},
  "comment":{"type":"string","maxLength":32768},
  "started":{"type":"string","description":"Jira timestamp, e.g. 2026-09-02T09:00:00.000+0200."}},
 "examples":[{"key":"ABC-123","time_spent":"2h","comment":"Investigation"}]}"#;
pub(crate) const WORKLOG_ADD_EXAMPLE: &str = r#"{"id":"11001"}"#;
pub(crate) const WORKLOG_ADD_EXAMPLE_SPARSE: &str = r#"{"id":"11001"}"#;
pub(crate) const WORKLOG_ADD_RESULT: &str = r#"{"type":"object","additionalProperties":false,"required":["id"],"properties":{"id":{"type":"string"}}}"#;

pub(crate) const ISSUELINK_CREATE_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["type","inward","outward"],
 "properties":{
  "type":{"type":"string","minLength":1,"description":"Link type name; the app resolves it."},
  "inward":{"type":"string","pattern":"^[A-Z][A-Z0-9_]*-[0-9]+$"},
  "outward":{"type":"string","pattern":"^[A-Z][A-Z0-9_]*-[0-9]+$"},
  "comment":{"type":"string","minLength":1,"maxLength":32768}},
 "examples":[{"type":"Blocks","inward":"ABC-124","outward":"ABC-123"}]}"#;

pub(crate) const SPRINT_MOVE_ISSUES_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["id","issues"],
 "properties":{
  "id":{"type":"integer","minimum":1},
  "issues":{"type":"array","items":{"type":"string","pattern":"^[A-Z][A-Z0-9_]*-[0-9]+$"},"minItems":1,"maxItems":50}},
 "examples":[{"id":7,"issues":["ABC-123","ABC-124"]}]}"#;

pub(crate) const BACKLOG_MOVE_ISSUES_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["issues"],
 "properties":{
  "issues":{"type":"array","items":{"type":"string","pattern":"^[A-Z][A-Z0-9_]*-[0-9]+$"},"minItems":1,"maxItems":50}},
 "examples":[{"issues":["ABC-123"]}]}"#;

/// Receipt of every write whose declared success is an empty body (`204`/`201`): `{}`.
pub(crate) const EMPTY_RECEIPT_EXAMPLE: &str = r#"{}"#;
pub(crate) const EMPTY_RECEIPT_RESULT: &str =
    r#"{"type":"object","additionalProperties":false,"maxProperties":0}"#;

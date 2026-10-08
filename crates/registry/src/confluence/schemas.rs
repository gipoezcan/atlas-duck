//! JSON text for the Confluence catalog: params schemas (draft 2020-12, `additionalProperties:
//! false`, one `examples[0]` each), realistic anonymized DC examples (`example.invalid` hosts),
//! sparse examples (same shape, nullables `null`, item arrays `[]`) and result/receipt schemas.
//!
//! Ids are numeric strings (content ids), space keys and labels are path-safe so a placeholder
//! can never smuggle a `/`, `?` or `#` into the URL.

// ---- shared params ---------------------------------------------------------------------------

pub(crate) const EMPTY_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"properties":{},"examples":[{}]}"#;

/// `confluence.page.get`-style single content id; also `label.list` and `attachment.list`.
pub(crate) const ID_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["id"],"properties":{"id":{"type":"string","pattern":"^[0-9]+$"}},"examples":[{"id":"123456"}]}"#;

/// `confluence.page.children` and `confluence.comment.list`.
pub(crate) const ID_PAGED_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["id"],
 "properties":{
  "id":{"type":"string","pattern":"^[0-9]+$"},
  "start":{"type":"integer","minimum":0,"default":0},
  "max":{"type":"integer","minimum":1,"default":25}},
 "examples":[{"id":"123456"}]}"#;

/// Result of every op whose result is a Confluence paged list of content stubs.
pub(crate) const STUB_LIST_EXAMPLE: &str = r#"{"results":[{"id":"123457","type":"page","status":"current","title":"Release notes","_links":{"webui":"/display/ABC/Release+notes"}}],"start":0,"limit":25,"size":1}"#;
pub(crate) const STUB_LIST_EXAMPLE_SPARSE: &str = r#"{"results":[],"start":0,"limit":25,"size":0}"#;
pub(crate) const STUB_LIST_RESULT: &str = r#"{"type":"object","required":["results"],"properties":{"results":{"type":"array","items":{"type":"object","required":["id"],"properties":{"id":{"type":"string"},"type":{"type":"string"},"status":{"type":"string"},"title":{"type":"string"},"_links":{"type":"object"}}}},"start":{"type":"integer"},"limit":{"type":"integer"},"size":{"type":"integer"}}}"#;

// ---- confluence.user.current / space.* --------------------------------------------------------

pub(crate) const USER_CURRENT_EXAMPLE: &str =
    r#"{"type":"known","username":"jdoe","userKey":"8a7f0c2e5d3b4a1f","displayName":"Jane Doe"}"#;
pub(crate) const USER_CURRENT_EXAMPLE_SPARSE: &str =
    r#"{"type":"known","username":"jdoe","userKey":"8a7f0c2e5d3b4a1f","displayName":"Jane Doe"}"#;
pub(crate) const USER_CURRENT_RESULT: &str = r#"{"type":"object","required":["username","displayName"],"properties":{"type":{"type":"string"},"username":{"type":"string"},"userKey":{"type":"string"},"displayName":{"type":"string"}}}"#;

pub(crate) const SPACE_LIST_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "properties":{
  "start":{"type":"integer","minimum":0,"default":0},
  "max":{"type":"integer","minimum":1,"default":25},
  "type":{"type":"string","enum":["global","personal"]}},
 "examples":[{"type":"global"}]}"#;
pub(crate) const SPACE_LIST_EXAMPLE: &str = r#"{"results":[{"id":1,"key":"ABC","name":"Alpha Beta Cooperation","type":"global","_links":{"webui":"/display/ABC"}}],"start":0,"limit":25,"size":1}"#;
pub(crate) const SPACE_LIST_EXAMPLE_SPARSE: &str =
    r#"{"results":[],"start":0,"limit":25,"size":0}"#;
pub(crate) const SPACE_LIST_RESULT: &str = r#"{"type":"object","required":["results"],"properties":{"results":{"type":"array","items":{"type":"object","required":["key","name"],"properties":{"id":{"type":"integer"},"key":{"type":"string"},"name":{"type":"string"},"type":{"type":"string"},"_links":{"type":"object"}}}},"start":{"type":"integer"},"limit":{"type":"integer"},"size":{"type":"integer"}}}"#;

pub(crate) const SPACE_GET_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["key"],"properties":{"key":{"type":"string","pattern":"^[A-Za-z0-9_~-]+$","maxLength":255}},"examples":[{"key":"ABC"}]}"#;
pub(crate) const SPACE_GET_EXAMPLE: &str = r#"{"id":1,"key":"ABC","name":"Alpha Beta Cooperation","type":"global","description":{"plain":{"value":"Team space.","representation":"plain"}},"_links":{"webui":"/display/ABC","self":"https://confluence.example.invalid/rest/api/space/ABC"}}"#;
pub(crate) const SPACE_GET_EXAMPLE_SPARSE: &str = r#"{"id":1,"key":"ABC","name":"Alpha Beta Cooperation","type":"global","description":null,"_links":{"webui":"/display/ABC","self":"https://confluence.example.invalid/rest/api/space/ABC"}}"#;
pub(crate) const SPACE_GET_RESULT: &str = r#"{"type":"object","required":["key","name"],"properties":{"id":{"type":"integer"},"key":{"type":"string"},"name":{"type":"string"},"type":{"type":"string"},"description":{"type":["object","null"]},"_links":{"type":"object"}}}"#;

// ---- confluence.page.get ----------------------------------------------------------------------

pub(crate) const PAGE_GET_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["id"],
 "properties":{
  "id":{"type":"string","pattern":"^[0-9]+$"},
  "format":{"type":"string","enum":["markdown","storage","view"],"default":"markdown"}},
 "examples":[{"id":"123456"}]}"#;
pub(crate) const PAGE_GET_EXAMPLE: &str = r#"{"id":"123456","type":"page","status":"current","title":"Release notes","space":{"id":1,"key":"ABC","name":"Alpha Beta Cooperation","_links":{"webui":"/display/ABC"}},"version":{"number":3,"when":"2026-09-03T14:02:10.000+0200","by":{"username":"jdoe","displayName":"Jane Doe"}},"ancestors":[{"id":"123400","type":"page","title":"Home","_links":{"webui":"/display/ABC/Home"}}],"body":{"storage":{"value":"<p>Version 1.4 fixes the login.</p>","representation":"storage"}},"_links":{"self":"https://confluence.example.invalid/rest/api/content/123456","webui":"/display/ABC/Release+notes"}}"#;
pub(crate) const PAGE_GET_EXAMPLE_SPARSE: &str = r#"{"id":"123456","type":"page","status":"current","title":"Release notes","space":{"id":1,"key":"ABC","name":"Alpha Beta Cooperation","_links":{"webui":"/display/ABC"}},"version":{"number":1,"when":"2026-09-03T14:02:10.000+0200","by":null},"ancestors":[],"body":{"storage":{"value":"","representation":"storage"}},"_links":{"self":"https://confluence.example.invalid/rest/api/content/123456","webui":"/display/ABC/Release+notes"}}"#;
pub(crate) const PAGE_GET_RESULT: &str = r#"{"type":"object","required":["id","type","title"],"properties":{"id":{"type":"string"},"type":{"type":"string"},"status":{"type":"string"},"title":{"type":"string"},"space":{"type":"object"},"version":{"type":"object","properties":{"number":{"type":"integer"},"when":{"type":"string"},"by":{"type":["object","null"]}}},"ancestors":{"type":"array","items":{"type":"object"}},"body":{"type":"object"},"_links":{"type":"object"}}}"#;

// ---- confluence.page.find ---------------------------------------------------------------------

pub(crate) const PAGE_FIND_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["space","title"],
 "properties":{
  "space":{"type":"string","pattern":"^[A-Za-z0-9_~-]+$","maxLength":255},
  "title":{"type":"string","minLength":1,"maxLength":255}},
 "examples":[{"space":"ABC","title":"Release notes"}]}"#;

// ---- confluence.search ------------------------------------------------------------------------

pub(crate) const SEARCH_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["cql"],
 "properties":{
  "cql":{"type":"string","minLength":1,"maxLength":20000},
  "start":{"type":"integer","minimum":0,"default":0},
  "max":{"type":"integer","minimum":1,"default":25},
  "excerpt":{"type":"string","enum":["none","indexed"],"default":"none"}},
 "examples":[{"cql":"space = ABC AND type = page AND title ~ \"Release\""}]}"#;
pub(crate) const SEARCH_EXAMPLE: &str = r#"{"results":[{"content":{"id":"123456","type":"page","status":"current","_links":{"webui":"/display/ABC/Release+notes"}},"title":"Release notes","excerpt":"","url":"/display/ABC/Release+notes","resultGlobalContainer":{"title":"Alpha Beta Cooperation","displayUrl":"/display/ABC"},"lastModified":"2026-09-03T14:02:10.000+0200"}],"start":0,"limit":25,"size":1,"totalSize":1}"#;
pub(crate) const SEARCH_EXAMPLE_SPARSE: &str =
    r#"{"results":[],"start":0,"limit":25,"size":0,"totalSize":0}"#;
pub(crate) const SEARCH_RESULT: &str = r#"{"type":"object","required":["results"],"properties":{"results":{"type":"array","items":{"type":"object","properties":{"content":{"type":"object"},"title":{"type":"string"},"excerpt":{"type":"string"},"url":{"type":"string"},"resultGlobalContainer":{"type":"object"},"lastModified":{"type":"string"}}}},"start":{"type":"integer"},"limit":{"type":"integer"},"size":{"type":"integer"},"totalSize":{"type":"integer"}}}"#;

// ---- confluence.comment.list ------------------------------------------------------------------

pub(crate) const COMMENT_LIST_EXAMPLE: &str = r#"{"results":[{"id":"789","type":"comment","status":"current","title":"Re: Release notes","body":{"storage":{"value":"<p>Looks good.</p>","representation":"storage"}},"history":{"createdBy":{"username":"asmith","displayName":"Alex Smith"},"createdDate":"2026-09-04T08:30:00.000+0200"},"ancestors":[],"version":{"number":1},"_links":{"webui":"/display/ABC/Release+notes?focusedCommentId=789"}}],"start":0,"limit":25,"size":1}"#;
pub(crate) const COMMENT_LIST_EXAMPLE_SPARSE: &str =
    r#"{"results":[],"start":0,"limit":25,"size":0}"#;
pub(crate) const COMMENT_LIST_RESULT: &str = r#"{"type":"object","required":["results"],"properties":{"results":{"type":"array","items":{"type":"object","required":["id"],"properties":{"id":{"type":"string"},"type":{"type":"string"},"status":{"type":"string"},"title":{"type":"string"},"body":{"type":"object"},"history":{"type":"object"},"ancestors":{"type":"array","items":{"type":"object"}},"version":{"type":"object"},"_links":{"type":"object"}}}},"start":{"type":"integer"},"limit":{"type":"integer"},"size":{"type":"integer"}}}"#;

// ---- confluence.label.list / attachment.list --------------------------------------------------

pub(crate) const LABEL_LIST_EXAMPLE: &str = r#"{"results":[{"prefix":"global","name":"release","id":"2001"}],"start":0,"limit":200,"size":1}"#;
pub(crate) const LABEL_LIST_EXAMPLE_SPARSE: &str =
    r#"{"results":[],"start":0,"limit":200,"size":0}"#;
pub(crate) const LABEL_LIST_RESULT: &str = r#"{"type":"object","required":["results"],"properties":{"results":{"type":"array","items":{"type":"object","required":["name"],"properties":{"prefix":{"type":"string"},"name":{"type":"string"},"id":{"type":"string"}}}},"start":{"type":"integer"},"limit":{"type":"integer"},"size":{"type":"integer"}}}"#;

pub(crate) const ATTACHMENT_LIST_EXAMPLE: &str = r#"{"results":[{"id":"att3001","type":"attachment","status":"current","title":"diagram.png","metadata":{"mediaType":"image/png","comment":null},"extensions":{"mediaType":"image/png","fileSize":48213},"_links":{"download":"/download/attachments/123456/diagram.png","webui":"/display/ABC/Release+notes?preview=/123456/3001/diagram.png"}}],"start":0,"limit":25,"size":1}"#;
pub(crate) const ATTACHMENT_LIST_EXAMPLE_SPARSE: &str =
    r#"{"results":[],"start":0,"limit":25,"size":0}"#;
pub(crate) const ATTACHMENT_LIST_RESULT: &str = r#"{"type":"object","required":["results"],"properties":{"results":{"type":"array","items":{"type":"object","required":["id","title"],"properties":{"id":{"type":"string"},"type":{"type":"string"},"status":{"type":"string"},"title":{"type":"string"},"metadata":{"type":"object"},"extensions":{"type":"object"},"_links":{"type":"object"}}}},"start":{"type":"integer"},"limit":{"type":"integer"},"size":{"type":"integer"}}}"#;

// ---- confluence.page.history ------------------------------------------------------------------

pub(crate) const PAGE_HISTORY_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["id"],
 "properties":{
  "id":{"type":"string","pattern":"^[0-9]+$"},
  "version":{"type":"integer","minimum":1,"description":"Fetch this historical version (body included) instead of the history summary."},
  "format":{"type":"string","enum":["markdown","storage","view"],"default":"markdown"}},
 "examples":[{"id":"123456"}]}"#;
pub(crate) const PAGE_HISTORY_EXAMPLE: &str = r#"{"latest":true,"createdBy":{"username":"jdoe","displayName":"Jane Doe"},"createdDate":"2026-08-20T10:00:00.000+0200","lastUpdated":{"by":{"username":"jdoe","displayName":"Jane Doe"},"when":"2026-09-03T14:02:10.000+0200","number":3},"previousVersion":{"number":2,"when":"2026-09-01T09:00:00.000+0200"},"contributors":{"publishers":{"users":[{"username":"jdoe","displayName":"Jane Doe"}]}},"_links":{"self":"https://confluence.example.invalid/rest/api/content/123456/history"}}"#;
pub(crate) const PAGE_HISTORY_EXAMPLE_SPARSE: &str = r#"{"latest":true,"createdBy":{"username":"jdoe","displayName":"Jane Doe"},"createdDate":"2026-08-20T10:00:00.000+0200","lastUpdated":{"by":{"username":"jdoe","displayName":"Jane Doe"},"when":"2026-08-20T10:00:00.000+0200","number":1},"previousVersion":null,"contributors":{"publishers":{"users":[]}},"_links":{"self":"https://confluence.example.invalid/rest/api/content/123456/history"}}"#;
/// The summary or, with `version`, a content object: only what both share is required.
pub(crate) const PAGE_HISTORY_RESULT: &str = r#"{"type":"object","properties":{"latest":{"type":"boolean"},"createdBy":{"type":["object","null"]},"createdDate":{"type":"string"},"lastUpdated":{"type":"object"},"previousVersion":{"type":["object","null"]},"contributors":{"type":"object"},"id":{"type":"string"},"type":{"type":"string"},"status":{"type":"string"},"title":{"type":"string"},"version":{"type":"object"},"body":{"type":"object"},"_links":{"type":"object"}}}"#;

// ---- writes -----------------------------------------------------------------------------------

pub(crate) const PAGE_CREATE_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["space","title","body"],
 "properties":{
  "space":{"type":"string","pattern":"^[A-Za-z0-9_~-]+$","maxLength":255},
  "title":{"type":"string","minLength":1,"maxLength":255},
  "body":{"type":"string","maxLength":1048576},
  "body_format":{"type":"string","enum":["markdown","storage"],"default":"markdown"},
  "parent":{"type":"string","pattern":"^[0-9]+$","description":"Parent page id."}},
 "examples":[{"space":"ABC","title":"Release notes 1.5","body":"Release 1.5 fixes the login.","parent":"123400"}]}"#;

pub(crate) const PAGE_UPDATE_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["id","base_version","body"],
 "properties":{
  "id":{"type":"string","pattern":"^[0-9]+$"},
  "base_version":{"type":"integer","minimum":1,"description":"The version number you read; the app sends base_version + 1 and flags a newer server version as a conflict."},
  "body":{"type":"string","maxLength":1048576},
  "body_format":{"type":"string","enum":["markdown","storage"],"default":"markdown"},
  "title":{"type":"string","minLength":1,"maxLength":255}},
 "examples":[{"id":"123456","base_version":3,"body":"Release 1.4 fixes the login and the reset flow."}]}"#;

pub(crate) const PAGE_MOVE_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["id","parent"],
 "properties":{
  "id":{"type":"string","pattern":"^[0-9]+$"},
  "parent":{"type":"string","pattern":"^[0-9]+$","description":"New parent page id (same space)."}},
 "examples":[{"id":"123456","parent":"123400"}]}"#;

pub(crate) const COMMENT_ADD_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["content_id","body"],
 "properties":{
  "content_id":{"type":"string","pattern":"^[0-9]+$"},
  "body":{"type":"string","minLength":1,"maxLength":32768},
  "body_format":{"type":"string","enum":["markdown","storage"],"default":"markdown"},
  "reply_to":{"type":"string","pattern":"^[0-9]+$","description":"Comment id to reply to."}},
 "examples":[{"content_id":"123456","body":"Looks good."}]}"#;

pub(crate) const LABEL_ADD_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["id","labels"],
 "properties":{
  "id":{"type":"string","pattern":"^[0-9]+$"},
  "labels":{"type":"array","items":{"type":"string","pattern":"^[A-Za-z0-9_.:-]+$","maxLength":255},"minItems":1,"maxItems":20,"uniqueItems":true}},
 "examples":[{"id":"123456","labels":["release","docs"]}]}"#;
/// §4.2: labels only the agent supplied, not the server's full label list.
pub(crate) const LABEL_ADD_EXAMPLE: &str = r#"{"labels":["release","docs"]}"#;
pub(crate) const LABEL_ADD_EXAMPLE_SPARSE: &str = r#"{"labels":[]}"#;
pub(crate) const LABEL_ADD_RESULT: &str = r#"{"type":"object","additionalProperties":false,"required":["labels"],"properties":{"labels":{"type":"array","items":{"type":"string"}}}}"#;

pub(crate) const LABEL_REMOVE_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["id","label"],
 "properties":{
  "id":{"type":"string","pattern":"^[0-9]+$"},
  "label":{"type":"string","pattern":"^[A-Za-z0-9_.:-]+$","maxLength":255}},
 "examples":[{"id":"123456","label":"release"}]}"#;
/// Declared empty success (204): the receipt is `{}`.
pub(crate) const EMPTY_RECEIPT_EXAMPLE: &str = r#"{}"#;
pub(crate) const EMPTY_RECEIPT_RESULT: &str = r#"{"type":"object","maxProperties":0}"#;

/// 10 MiB of bytes is 13 981 016 base64 characters.
pub(crate) const ATTACHMENT_UPLOAD_PARAMS: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["id","filename","content_base64"],
 "properties":{
  "id":{"type":"string","pattern":"^[0-9]+$"},
  "filename":{"type":"string","pattern":"^[^/\\\\]+$","minLength":1,"maxLength":255},
  "content_base64":{"type":"string","pattern":"^[A-Za-z0-9+/]*={0,2}$","maxLength":13981016},
  "replace":{"type":"boolean","default":false},
  "comment":{"type":"string","maxLength":1000}},
 "examples":[{"id":"123456","filename":"notes.txt","content_base64":"aGVsbG8gd29ybGQ=","comment":"Meeting notes"}]}"#;

// ---- receipts (§4.2: id, type, status, version.number, _links.webui) --------------------------

pub(crate) const PAGE_RECEIPT_EXAMPLE: &str = r#"{"id":"123457","type":"page","status":"current","version":{"number":1},"_links":{"webui":"/display/ABC/Release+notes+1.5"}}"#;
pub(crate) const PAGE_UPDATE_RECEIPT_EXAMPLE: &str = r#"{"id":"123456","type":"page","status":"current","version":{"number":4},"_links":{"webui":"/display/ABC/Release+notes"}}"#;
pub(crate) const COMMENT_RECEIPT_EXAMPLE: &str = r#"{"id":"790","type":"comment","status":"current","version":{"number":1},"_links":{"webui":"/display/ABC/Release+notes?focusedCommentId=790"}}"#;
pub(crate) const ATTACHMENT_RECEIPT_EXAMPLE: &str = r#"{"id":"att3002","type":"attachment","status":"current","version":{"number":1},"_links":{"webui":"/display/ABC/Release+notes?preview=/123456/3002/notes.txt"}}"#;
pub(crate) const CONTENT_RECEIPT_RESULT: &str = r#"{"type":"object","additionalProperties":false,"required":["id","type","status"],"properties":{"id":{"type":"string"},"type":{"type":"string"},"status":{"type":"string"},"version":{"type":"object","additionalProperties":false,"properties":{"number":{"type":"integer"}}},"_links":{"type":"object","additionalProperties":false,"properties":{"webui":{"type":"string"}}}}}"#;

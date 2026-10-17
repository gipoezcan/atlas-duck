#![cfg(feature = "testing")]
//! `confluence.attachment.upload` (M7 Task 20a, PD-109; §5.4 steps 2, 4 and 5, §7.4, §13 I-06):
//! the filename lookup (`?filename=<f>&expand=version`), the collision hold without `replace`
//! (`Hold::Collision`, Approve disabled, a batch with it rejected whole, a plain deny only), the
//! replace of the one attachment of that name through its `/data` endpoint with the
//! attachment-version stale rule, the deterministic multipart body (boundary from the file's
//! SHA-256, never inside any part), the filename rules, the receipt from `results[0]`
//! (`Projection::FirstResultFields`) and the request view that never carries the file bytes
//! (Δ2, plan review I-4), while `WRITE_APPROVED` stores and hashes the exact wire bytes.
//! Task 20b (PD-110): the `AttachmentUpload` card over the request sent (sniffed type, SHA-256,
//! the thumbnail capped at 2 MiB, the extension fact row, the collision and replace lines), the
//! edit form that never inlines `content_base64` (a `null` edit of it is "unchanged") and the
//! bounded preview of a 10 MiB upload.
//!
//! Checked twice: as pure functions of the op table (plan, judge, executor, stale rule, previewer
//! as the engine calls them) and end to end through the harness.

mod common;

use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, UserKind};
use atlas_duck_atlassian::{GetCall, HttpRequestSpec};
use atlas_duck_audit::{EventType, RequestRecord, request_set_hash};
use atlas_duck_core::lifecycle::model::Hold;
use atlas_duck_core::ops::{
    EnrichCtx, EnrichPurpose, EnrichStep, EnrichVerdict, ExecCtx, ExecError, ExecPlan, PreviewCtx,
    PreviewInput, PreviewModel, StaleCtx, StaleVerdict, WriteView, generic, op_table,
};
use std::time::Instant;

use atlas_duck_core::payloads::InvalidReason;
use atlas_duck_core::testing::Harness;
use atlas_duck_core::{
    BatchFailure, BatchItem, DecisionError, DecisionOutcome, DenyDetails, Edits,
};
use atlas_duck_ipc::envelope::{ErrorCode, Status};
use atlas_duck_preview::render::DOC_MAX_BYTES;
use atlas_duck_preview::{
    BodyView, Platform, PreviewBody, RequestView, WarningId, body_digest_line, render,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::confluence::content_path;
use common::{TestError, TestResult, code, de, detail, exit, request_id};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

const UPLOAD: &str = "confluence.attachment.upload";
const PAGE_ID: &str = "65537";
const FILENAME: &str = "notes.txt";
const ATT_ID: &str = "att3001";
/// A small UTF-8 file: the case a "show UTF-8 parts up to 4 KiB" rule would leak.
const TEXT: &[u8] = b"hello world, these are the meeting notes";
const COMMENT: &str = "Meeting notes";
/// PD-109: the new-attachment endpoint, and the `/data` endpoint of an existing one.
const ATTACH_PATH: &str = "/rest/api/content/65537/child/attachment";
const DATA_PATH: &str = "/rest/api/content/65537/child/attachment/att3001/data";

// ---- pure helpers: the op table as the engine calls it ---------------------------------------

fn spec() -> Result<&'static atlas_duck_registry::OperationSpec, TestError> {
    atlas_duck_registry::get(UPLOAD).ok_or_else(|| "no confluence.attachment.upload".into())
}

fn params(filename: &str, content: &[u8], replace: bool, comment: Option<&str>) -> Value {
    let mut p = json!({
        "id": PAGE_ID,
        "filename": filename,
        "content_base64": STANDARD.encode(content),
    });
    if replace {
        p["replace"] = json!(true);
    }
    if let Some(c) = comment {
        p["comment"] = json!(c);
    }
    p
}

/// An attachment as `GET …/child/attachment?filename=…&expand=version` lists it.
fn attachment(id: &str, title: &str, version: u64) -> Value {
    json!({
        "id": id,
        "type": "attachment",
        "status": "current",
        "title": title,
        "version": {"number": version, "when": "2026-10-06T14:00:00.000+02:00"},
        "metadata": {"mediaType": "text/plain", "comment": null},
        "extensions": {"mediaType": "text/plain", "fileSize": 11},
        "_links": {"download": format!("/download/attachments/{PAGE_ID}/{title}")},
    })
}

/// The lookup's answer: `{results, start, limit, size}`.
fn lookup(results: &[Value]) -> Value {
    json!({"results": results, "start": 0, "limit": 50, "size": results.len(), "_links": {}})
}

type Rounds = Vec<Vec<(EnrichPurpose, GetCall)>>;

/// The rule's rounds over `answers` the way the engine's staged driver feeds them, then the judge.
fn staged(params: &Value, answers: &[Value]) -> Result<(Rounds, EnrichVerdict), TestError> {
    let rule = op_table()
        .get(UPLOAD)
        .and_then(|i| i.enrich)
        .ok_or("no enrich rule")?;
    let ctx = EnrichCtx {
        spec: spec()?,
        params,
    };
    let mut given: Vec<Value> = Vec::new();
    let mut rounds = Vec::new();
    loop {
        match (rule.plan)(&ctx, &given) {
            EnrichStep::Judge => break,
            EnrichStep::Fetch(calls) => {
                for _ in &calls {
                    let next = answers
                        .get(given.len())
                        .ok_or("the plan asked for more answers than the test gives")?;
                    given.push(next.clone());
                }
                rounds.push(calls);
            }
        }
        if rounds.len() > 4 {
            return Err("more than four rounds".into());
        }
    }
    Ok((rounds, (rule.judge)(&ctx, &given)))
}

fn verdict(params: &Value, found: &[Value]) -> Result<EnrichVerdict, TestError> {
    Ok(staged(params, &[lookup(found)])?.1)
}

fn exec(params: &Value, v: Option<&EnrichVerdict>) -> Result<ExecPlan, ExecError> {
    let base = atlas_duck_atlassian::normalize_base_url("https://wiki.example.invalid/wiki")
        .map_err(|_| ExecError::NotInThisBuild)?;
    let imp = op_table().get(UPLOAD).ok_or(ExecError::NotInThisBuild)?;
    let spec = spec().map_err(|_| ExecError::NotInThisBuild)?;
    let ctx = ExecCtx {
        spec,
        params,
        base: &base,
        enrichment: v,
        effective_max: None,
        comments_cap: None,
        test_fault: None,
    };
    (imp.executor)(&ctx)
}

fn one_request(params: &Value, v: &EnrichVerdict) -> Result<HttpRequestSpec, TestError> {
    match exec(params, Some(v)) {
        Ok(ExecPlan::Write(r)) => match <[HttpRequestSpec; 1]>::try_from(r) {
            Ok([one]) => Ok(one),
            Err(r) => Err(format!("{} requests", r.len()).into()),
        },
        other => Err(format!("not a write: {other:?}").into()),
    }
}

fn preview_of(
    params: &Value,
    v: &EnrichVerdict,
    reqs: &[HttpRequestSpec],
) -> Result<PreviewModel, TestError> {
    let imp = op_table().get(UPLOAD).ok_or("no OpImpl")?;
    let ctx = PreviewCtx {
        spec: spec()?,
        instance_alias: "wiki",
        params,
        input: PreviewInput::Write(WriteView {
            requests: reqs,
            hold: v.hold,
            enrichment: Some(v),
            failure: None,
        }),
        field_names: None,
    };
    Ok((imp.previewer)(&ctx))
}

fn stale(
    params: &Value,
    baseline: &Value,
    responses: &[Value],
) -> Result<(Vec<GetCall>, StaleVerdict), TestError> {
    let rule = op_table()
        .get(UPLOAD)
        .and_then(|i| i.stale_check)
        .ok_or("no stale rule")?;
    let ctx = StaleCtx {
        spec: spec()?,
        params,
        baseline,
    };
    Ok(((rule.plan)(&ctx), (rule.judge)(&ctx, responses)))
}

fn query(call: &GetCall) -> Vec<(&str, &str)> {
    call.query
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// PD-109: `atlas-duck-` and the first 32 hex chars of the file's SHA-256.
fn first_boundary(content: &[u8]) -> String {
    format!("atlas-duck-{}", &sha256_hex(content)[..32])
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn boundary_of(r: &HttpRequestSpec) -> Result<String, TestError> {
    r.content_type
        .as_deref()
        .and_then(|ct| ct.strip_prefix("multipart/form-data; boundary="))
        .map(str::to_owned)
        .ok_or_else(|| format!("not multipart: {:?}", r.content_type).into())
}

/// The parts of a `multipart/form-data` body as RFC 2046 lays it out (`--b CRLF headers CRLF
/// CRLF body` per part, each followed by `CRLF --b`, the last by `--` and CRLF): `(headers,
/// body)`. Written independently of the executor.
fn parts(body: &[u8], boundary: &str) -> Result<Vec<(String, Vec<u8>)>, TestError> {
    let open = format!("--{boundary}\r\n");
    let next = format!("\r\n--{boundary}");
    let mut rest = body
        .strip_prefix(open.as_bytes())
        .ok_or("no opening boundary")?;
    let mut out = Vec::new();
    loop {
        let head_end = find(rest, b"\r\n\r\n").ok_or("no header end")?;
        let headers = String::from_utf8(rest[..head_end].to_vec())?;
        let after = &rest[head_end + 4..];
        let end = find(after, next.as_bytes()).ok_or("no closing boundary")?;
        out.push((headers, after[..end].to_vec()));
        let tail = &after[end + next.len()..];
        if tail == b"--\r\n" {
            return Ok(out);
        }
        rest = tail
            .strip_prefix(b"\r\n")
            .ok_or("no CRLF after a boundary")?;
    }
}

fn file_headers(filename: &str, mime: &str) -> String {
    format!(
        "Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: {mime}"
    )
}

const COMMENT_HEADERS: &str =
    "Content-Disposition: form-data; name=\"comment\"\r\nContent-Type: text/plain; charset=utf-8";

fn unresolved_of(v: &EnrichVerdict) -> Option<(&str, &str, u64, Vec<&str>)> {
    v.unresolved.as_ref().map(|(p, val, n, c)| {
        (
            p.as_str(),
            val.as_str(),
            *n,
            c.iter().map(String::as_str).collect(),
        )
    })
}

fn invalid_param(r: Result<ExecPlan, ExecError>) -> Result<String, TestError> {
    match r {
        Err(ExecError::Invalid(e)) => {
            assert_eq!(e.code, ErrorCode::Validation, "{e:?}");
            Ok(e.details
                .get("param")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned())
        }
        other => Err(format!("not refused: {other:?}").into()),
    }
}

// ---- the lookup and its judge ----------------------------------------------------------------

/// PD-109 stage 1: one GET of the content's attachments by that filename, with their versions.
#[test]
fn upload_lookup_plan_is_one_filename_get() -> TestResult {
    let p = params("Bericht ü&x.pdf", TEXT, false, None);
    let (rounds, v) = staged(&p, &[lookup(&[])])?;
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    let [round] = rounds.as_slice() else {
        return Err(format!("{} rounds", rounds.len()).into());
    };
    let [(purpose, call)] = round.as_slice() else {
        return Err("not one GET".into());
    };
    assert_eq!(*purpose, EnrichPurpose::Enrich);
    assert_eq!(
        call.endpoint_template,
        "/rest/api/content/{id}/child/attachment"
    );
    assert_eq!(call.params, json!({"id": PAGE_ID}));
    // The filename is a query value (encoded by `build_url`), never spliced into the path.
    // An explicit page size (T20a review I-3): a full page fails closed below.
    assert_eq!(
        query(call),
        [
            ("filename", "Bericht ü&x.pdf"),
            ("expand", "version"),
            ("limit", "50")
        ]
    );
    // The edits that re-run it: the filename and `replace` (PD-109); `id` is the target.
    let imp = op_table().get(UPLOAD).ok_or("no OpImpl")?;
    assert_eq!(imp.enrich_keys, ["filename", "replace"]);
    Ok(())
}

/// Without `replace`, an attachment of the same name (exactly, or differing only in case) is
/// the collision hold; the facts name it for the card (Task 20b); anything else is no collision.
#[test]
fn upload_collision_judge() -> TestResult {
    let p = params(FILENAME, TEXT, false, Some(COMMENT));
    let v = verdict(&p, &[attachment(ATT_ID, FILENAME, 2)])?;
    assert_eq!(v.hold, Hold::Collision, "{v:?}");
    let existing = v
        .summary
        .as_ref()
        .and_then(|s| s.confluence.as_ref())
        .and_then(|c| c.existing_attachment.as_ref())
        .ok_or("no existing attachment")?;
    assert_eq!(
        (existing.id.as_str(), existing.version, existing.size),
        (ATT_ID, 2, Some(11))
    );
    let v = verdict(&p, &[attachment(ATT_ID, "Notes.TXT", 2)])?;
    assert_eq!(v.hold, Hold::Collision, "a case variant collides too");
    // An attachment of another name (a server that ignored the filter) is no collision.
    let v = verdict(&p, &[attachment("att9", "other.txt", 1)])?;
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    let v = verdict(&p, &[])?;
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    // An answer the judge cannot use fails closed.
    let mut historical = attachment(ATT_ID, FILENAME, 2);
    historical["status"] = json!("historical");
    let mut not_attachment = attachment(ATT_ID, FILENAME, 2);
    not_attachment["type"] = json!("page");
    let full_page: Vec<Value> = (0..50)
        .map(|n| attachment(&format!("att{n}"), &format!("other{n}.txt"), 1))
        .collect();
    for bad in [
        json!({"size": 0}),
        json!({"results": "x"}),
        json!({"results": [{"title": FILENAME}]}),
        json!({"results": [{"id": ATT_ID, "type": "attachment", "status": "current",
                            "title": FILENAME}]}),
        // Complete entries that are no current attachment (T20a review m-2).
        lookup(&[historical]),
        lookup(&[not_attachment]),
        // A further page that may hold the collision.
        json!({"results": [], "_links": {"next": "/rest/api/content/65537/child/attachment?start=50"}}),
        // A full page (the `limit` sent, or the server's own), or a count beyond what is listed
        // (T20a review I-3, the T19 M-5 rule).
        lookup(&full_page),
        json!({"results": full_page, "start": 0, "limit": 200, "size": 50}),
        json!({"results": [attachment("att9", "other.txt", 1)], "start": 0, "limit": 1, "size": 1}),
        json!({"results": [], "start": 0, "limit": 50, "size": 1}),
        json!({"results": [], "start": 0, "limit": 50, "size": 0, "totalSize": 3}),
    ] {
        let v = staged(&p, std::slice::from_ref(&bad))?.1;
        assert_eq!(v.hold, Hold::EnrichmentError, "{bad}");
    }
    Ok(())
}

// ---- the multipart body ----------------------------------------------------------------------

/// PD-109 / §5.4 step 4: the body is a pure function of the params (two renders are byte-equal),
/// the boundary is `atlas-duck-<32 hex of SHA-256(file)>`, the `file` part holds exactly the
/// decoded bytes, the URL carries `allowDuplicated=false`; end to end `WRITE_APPROVED` stores
/// that very body as base64 and its `request_set_hash` is the hash of the bytes on the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_new_multipart_body_deterministic() -> TestResult {
    let p = params(FILENAME, TEXT, false, Some(COMMENT));
    let v = verdict(&p, &[])?;
    let a = one_request(&p, &v)?;
    let b = one_request(&p, &v)?;
    assert_eq!(a, b, "two renders, the same bytes");
    assert_eq!(a.method, "POST");
    assert_eq!(
        a.resolved_url,
        "https://wiki.example.invalid/wiki/rest/api/content/65537/child/attachment?allowDuplicated=false"
    );
    let boundary = boundary_of(&a)?;
    assert_eq!(boundary, first_boundary(TEXT));
    assert_eq!(
        a.content_type.as_deref(),
        Some(format!("multipart/form-data; boundary={}", first_boundary(TEXT)).as_str())
    );
    let got = parts(&a.body, &boundary)?;
    assert_eq!(
        got,
        [
            (
                file_headers(FILENAME, "application/octet-stream"),
                TEXT.to_vec()
            ),
            (COMMENT_HEADERS.to_owned(), COMMENT.as_bytes().to_vec()),
        ]
    );
    // Without a comment there is one part.
    let bare = params(FILENAME, TEXT, false, None);
    let r = one_request(&bare, &verdict(&bare, &[])?)?;
    assert_eq!(parts(&r.body, &boundary_of(&r)?)?.len(), 1);
    // An empty file is a file.
    let empty = params(FILENAME, b"", false, None);
    let r = one_request(&empty, &verdict(&empty, &[])?)?;
    assert_eq!(parts(&r.body, &boundary_of(&r)?)?[0].1, b"");

    // End to end.
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    upload_server(mock, &[]).await;
    let id = queued(&h, p.clone()).await?;
    assert!(h.approver().open(&id).map_err(de)?.preview.approvable);
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let posts = requests_with(mock, "POST").await;
    let [sent] = posts.as_slice() else {
        return Err(format!("{} POSTs", posts.len()).into());
    };
    assert_eq!(sent.url.path(), mock.path(ATTACH_PATH));
    assert_eq!(sent.url.query(), Some("allowDuplicated=false"));
    assert_eq!(sent.body, a.body, "the wire bytes are the rendered body");
    let sent_ct = sent
        .headers
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    assert_eq!(sent_ct, a.content_type);
    let approved = records_of(&h, &id, EventType::WRITE_APPROVED).await?;
    let [approved] = approved.as_slice() else {
        return Err("not one WRITE_APPROVED".into());
    };
    let stored = &approved["requests"][0];
    let b64 = stored["body_b64"].as_str().ok_or("no body_b64")?;
    assert_eq!(
        STANDARD.decode(b64)?,
        sent.body,
        "stored as base64, exactly"
    );
    // wiremock rebuilds the URL from the Host header; the method guard compares it byte for byte
    // with the approved one, so the path and query suffice here.
    let url = stored["url"].as_str().ok_or("no url")?;
    let wire_suffix = format!("{}?allowDuplicated=false", sent.url.path());
    assert!(url.ends_with(&wire_suffix), "{url}");
    assert_eq!(stored["content_type"].as_str(), sent_ct.as_deref());
    let wire = RequestRecord {
        index: 0,
        method: "POST".to_owned(),
        resolved_url: url.to_owned(),
        content_type: sent_ct,
        body_bytes: sent.body.clone(),
    };
    assert_eq!(
        approved["request_set_hash"],
        json!(hex::encode(request_set_hash(&[wire])))
    );
    // The receipt is the projection of `results[0]` of the answer.
    assert_eq!(
        env.data,
        Some(json!({"receipt": {
            "id": "att3002", "type": "attachment", "status": "current",
            "version": {"number": 1},
            "_links": {"webui": "/display/DOC/Release+checklist?preview=/65537/3002/notes.txt"},
        }}))
    );
    // The lookup (`enrich`); after the approval the identity call alone (`stale_check`): a new
    // attachment has no stale rule.
    assert_eq!(
        purposes(&h, &id).await?,
        [json!("enrich"), json!("stale_check")]
    );
    Ok(())
}

/// PD-110 (Task 20a part): the `file` part's `Content-Type` is sniffed from the magic bytes.
#[test]
fn upload_part_content_type_is_sniffed() -> TestResult {
    let cases: [(&[u8], &str); 8] = [
        (b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR", "image/png"),
        (b"\xff\xd8\xff\xe0\0\x10JFIF", "image/jpeg"),
        (b"GIF89a\x01\0\x01\0", "image/gif"),
        (b"RIFF\x24\0\0\0WEBPVP8 ", "image/webp"),
        (b"%PDF-1.7\n", "application/pdf"),
        (b"PK\x03\x04\x14\0", "application/zip"),
        (
            b"<svg xmlns='http://www.w3.org/2000/svg'/>",
            "application/octet-stream",
        ),
        (b"RIFF\x24\0\0\0WAVEfmt ", "application/octet-stream"),
    ];
    for (bytes, mime) in cases {
        let p = params("f.bin", bytes, false, None);
        let r = one_request(&p, &verdict(&p, &[])?)?;
        let got = parts(&r.body, &boundary_of(&r)?)?;
        assert_eq!(got[0].0, file_headers("f.bin", mime), "{mime}");
        assert_eq!(got[0].1, bytes);
    }
    Ok(())
}

/// PD-109: a boundary that occurs in a part (the comment or the filename the agent wrote) gets
/// `-1`, `-2`, … until it occurs nowhere; the body still splits into exactly its parts.
#[test]
fn upload_boundary_not_in_content() -> TestResult {
    let b0 = first_boundary(TEXT);
    let cases = [
        (
            FILENAME.to_owned(),
            format!("see --{b0} here"),
            format!("{b0}-1"),
        ),
        (
            FILENAME.to_owned(),
            format!("{b0} and {b0}-1"),
            format!("{b0}-2"),
        ),
        (format!("{b0}.txt"), COMMENT.to_owned(), format!("{b0}-1")),
    ];
    for (filename, comment, want) in cases {
        let p = params(&filename, TEXT, false, Some(&comment));
        let r = one_request(&p, &verdict(&p, &[])?)?;
        let boundary = boundary_of(&r)?;
        assert_eq!(boundary, want);
        for hay in [TEXT, filename.as_bytes(), comment.as_bytes()] {
            assert!(find(hay, boundary.as_bytes()).is_none());
        }
        let got = parts(&r.body, &boundary)?;
        assert_eq!(
            got,
            [
                (
                    file_headers(&filename, "application/octet-stream"),
                    TEXT.to_vec()
                ),
                (COMMENT_HEADERS.to_owned(), comment.as_bytes().to_vec()),
            ]
        );
    }
    Ok(())
}

/// PD-109: a filename with `"`, CR, LF or another control character cannot be written into the
/// part header as sent: refused at validation (exit 2), the message never echoing the name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_filename_with_quote_rejected_exit2() -> TestResult {
    for name in [
        "a\"b.txt",
        "a\rb.txt",
        "a\nb.txt",
        "a\tb.txt",
        "a\u{7}b.txt",
        "a\u{7f}b.txt",
        "a\u{85}b.txt",
    ] {
        let p = params(name, TEXT, false, None);
        assert_eq!(invalid_param(exec(&p, None))?, "filename", "{name:?}");
    }
    // Content that is no base64 is refused before anything else too.
    let mut p = params(FILENAME, TEXT, false, None);
    p["content_base64"] = json!("abcde");
    assert_eq!(invalid_param(exec(&p, None))?, "content_base64");

    let h = Harness::confluence().await?;
    let env = h
        .submit(
            UPLOAD,
            params("secret\"name.txt", TEXT, false, Some(COMMENT)),
        )
        .await;
    assert_eq!(code(&env), "validation", "{}", env.to_json_line());
    assert_eq!(exit(&env), 2);
    assert_eq!(detail(&env, "param"), json!("filename"));
    assert!(
        !env.to_json_line().contains("secret"),
        "the name is not echoed"
    );
    let id = request_id(&env)?;
    assert_eq!(
        h.event_types(&id).await?,
        [EventType::REQUEST_RECEIVED, EventType::REQUEST_REJECTED]
    );
    Ok(())
}

/// Plan review m-9: a non-ASCII filename is sent as UTF-8 in the `filename` parameter, and `..`
/// is an ordinary filename character (attachments are stored by name, not by path).
#[test]
fn upload_non_ascii_and_dotdot_filenames_sent_as_given() -> TestResult {
    for name in ["Bericht-ü.pdf", "..notes.txt", "..", "名前 (1).txt"] {
        let p = params(name, TEXT, false, None);
        // The validation dry call passes it (only the verdict is missing).
        assert_eq!(exec(&p, None), Err(ExecError::EnrichmentRequired), "{name}");
        let r = one_request(&p, &verdict(&p, &[])?)?;
        let got = parts(&r.body, &boundary_of(&r)?)?;
        assert_eq!(
            got[0].0,
            file_headers(name, "application/octet-stream"),
            "{name}"
        );
        let header = format!("filename=\"{name}\"");
        assert!(find(&r.body, header.as_bytes()).is_some(), "UTF-8 as given");
        assert_eq!(
            r.resolved_url,
            "https://wiki.example.invalid/wiki/rest/api/content/65537/child/attachment?allowDuplicated=false",
            "the name is never in the URL"
        );
    }
    Ok(())
}

// ---- the request view ------------------------------------------------------------------------

/// Δ2 / plan review I-4: the preview's request body is the text envelope (boundary lines, part
/// headers and the comment as sent), the file part replaced by its one size and SHA-256 line,
/// whatever its size or encoding; neither the model, its serialization nor the rendered
/// document carries the bytes (the card's raster thumbnail aside, PD-110), and the replaced bytes
/// count as hidden. `WRITE_APPROVED` and the Raw pages keep the real bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_view_never_carries_file_bytes() -> TestResult {
    let mut binary = b"\x89PNG\r\n\x1a\n".to_vec();
    binary.extend((0..5000u32).map(|i| (i % 251) as u8));
    let big: Vec<u8> = b"Lorem ipsum dolor sit amet. ".repeat(80_000);
    for content in [TEXT.to_vec(), binary, big] {
        let p = params(FILENAME, &content, false, Some(COMMENT));
        let v = verdict(&p, &[])?;
        let r = one_request(&p, &v)?;
        let m = preview_of(&p, &v, std::slice::from_ref(&r))?;
        let requests = card_requests(&m.body)?;
        let [view] = requests else {
            return Err("not one request".into());
        };
        let boundary = boundary_of(&r)?;
        let line = body_digest_line(content.len() as u64, &sha256_hex(&content));
        let envelope = format!(
            "--{boundary}\r\n{}\r\n\r\n{line}\r\n--{boundary}\r\n{COMMENT_HEADERS}\r\n\r\n{COMMENT}\r\n--{boundary}--\r\n",
            file_headers(FILENAME, sniffed(&content))
        );
        assert_eq!(view.body, BodyView::Text(envelope));
        assert_eq!(view.content_type, r.content_type);
        assert_eq!(m.header.hidden_in_preview_bytes, content.len() as u64);
        assert_eq!(m.header.byte_size, r.body.len() as u64, "the real size");
        no_file_bytes(&serde_json::to_string(requests)?, &content)?;
        // Task 20b: the card's only copy of the bytes is a raster thumbnail (PD-110).
        no_file_bytes(
            &serde_json::to_string(&without_thumbnail(&m.body))?,
            &content,
        )?;
    }

    // A collision card shows the request an approval would have sent, under the same rule.
    let p = params(FILENAME, TEXT, false, Some(COMMENT));
    let v = verdict(&p, &[attachment(ATT_ID, FILENAME, 2)])?;
    assert_eq!(v.hold, Hold::Collision);
    let r = one_request(&p, &v)?;
    assert_eq!(
        r.resolved_url,
        "https://wiki.example.invalid/wiki/rest/api/content/65537/child/attachment?allowDuplicated=false"
    );
    let m = preview_of(&p, &v, std::slice::from_ref(&r))?;
    no_file_bytes(&serde_json::to_string(&m.body)?, TEXT)?;

    // End to end: the opened preview's body and the rendered document.
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    upload_server(mock, &[]).await;
    let id = queued(&h, p).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    let doc = render::document(&preview, Platform::current());
    no_file_bytes(&doc, TEXT)?;
    no_file_bytes(&serde_json::to_string(&preview.body)?, TEXT)?;
    no_file_bytes(&serde_json::to_string(&preview.header)?, TEXT)?;
    assert!(doc.contains(&body_digest_line(TEXT.len() as u64, &sha256_hex(TEXT))));
    assert!(doc.contains(COMMENT), "the comment part is shown as sent");
    Ok(())
}

/// The sniffed type a part is sent as (PD-110).
fn sniffed(content: &[u8]) -> &'static str {
    if content.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else {
        "application/octet-stream"
    }
}

/// Neither the raw text, nor a slice of it, nor its base64 is in `s`.
fn no_file_bytes(s: &str, content: &[u8]) -> TestResult {
    let b64 = STANDARD.encode(content);
    assert!(!s.contains(&b64), "the base64 of the file");
    let slice = &content[..content.len().min(24)];
    if let Ok(text) = std::str::from_utf8(slice) {
        assert!(!s.contains(text), "a raw slice of the file: {text}");
    }
    assert!(!s.contains(&b64[..b64.len().min(24)]), "a base64 slice");
    Ok(())
}

/// Δ2 backstop (lead ruling on T20a review I-1): a body that is no UTF-8 and above 1 MiB is shown
/// as its size and digest only, a smaller one as base64; a UTF-8 body is text at any size (the
/// renderer caps it and counts the cut); a malformed multipart body is a digest (fail closed:
/// never shown as text, never as base64).
#[test]
fn request_view_digest_backstop() -> TestResult {
    let p = params(FILENAME, TEXT, false, None);
    let v = verdict(&p, &[])?;
    let request = |content_type: &str, body: Vec<u8>| HttpRequestSpec {
        index: 0,
        method: "POST".to_owned(),
        resolved_url: "https://wiki.example.invalid/wiki/rest/api/content".to_owned(),
        content_type: Some(content_type.to_owned()),
        body,
    };
    let mib = 1024 * 1024;
    let over = format!("\"{}\"", "a".repeat(mib)).into_bytes();
    let binary_at_cap = vec![0xff_u8; mib];
    let binary_over = vec![0xff_u8; mib + 1];
    let malformed = b"--atlas-duck-x\r\nno header end".to_vec();
    let cases = [
        (request("application/json", over.clone()), None, 0),
        (
            request("application/octet-stream", binary_at_cap.clone()),
            None,
            0,
        ),
        (
            request("application/octet-stream", binary_over.clone()),
            Some((binary_over.len() as u64, sha256_hex(&binary_over))),
            binary_over.len() as u64,
        ),
        (
            request(
                "multipart/form-data; boundary=atlas-duck-x",
                malformed.clone(),
            ),
            Some((malformed.len() as u64, sha256_hex(&malformed))),
            malformed.len() as u64,
        ),
        (
            request("multipart/form-data", TEXT.to_vec()),
            Some((TEXT.len() as u64, sha256_hex(TEXT))),
            TEXT.len() as u64,
        ),
    ];
    for (r, digest, hidden) in cases {
        let m = preview_of(&p, &v, std::slice::from_ref(&r))?;
        let PreviewBody::WriteRequests { requests } = &m.body else {
            return Err("not the request list".into());
        };
        match (&requests[0].body, digest) {
            (BodyView::Digest { bytes, sha256 }, Some((b, h))) => {
                assert_eq!((*bytes, sha256.as_str()), (b, h.as_str()));
            }
            (BodyView::Text(t), None) => assert_eq!(t.as_bytes(), over.as_slice()),
            (BodyView::Base64(b), None) => assert_eq!(STANDARD.decode(b)?, binary_at_cap),
            (other, want) => return Err(format!("{other:?} for {want:?}").into()),
        }
        assert_eq!(m.header.hidden_in_preview_bytes, hidden);
    }
    Ok(())
}

/// Design choice 4 (T20a review m-2): the §6.4 counts run over each multipart part, so a bidi
/// control in the filename or the comment is counted beside a binary file (the whole body is no
/// UTF-8 and would count nothing).
#[test]
fn bidi_in_multipart_parts_is_counted_beside_a_binary_file() -> TestResult {
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend([0xff, 0xfe, 0x00, 0x01]);
    for (filename, comment) in [
        ("a\u{202E}b.png", None),
        ("plain.png", Some("see \u{202E}here")),
    ] {
        let p = params(filename, &png, false, comment);
        let v = verdict(&p, &[])?;
        let r = one_request(&p, &v)?;
        assert!(std::str::from_utf8(&r.body).is_err(), "a binary body");
        let m = preview_of(&p, &v, std::slice::from_ref(&r))?;
        assert_eq!(m.header.bidi_controls, 1, "{filename:?} {comment:?}");
        assert!(
            m.warnings.iter().any(|w| w.id == WarningId::BidiControls),
            "{:?}",
            m.warnings
        );
    }
    Ok(())
}

// ---- the collision hold ----------------------------------------------------------------------

/// I-06 (attachment collision): an existing `notes.txt` without `replace` is the collision hold:
/// Approve disabled (opened or not), no deny detail applies, a batch with a clean label add is
/// rejected whole, and the plain deny is `denied` (exit 3) without the existing attachment's facts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i06_attachment_collision_not_approvable_individual_and_batch() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    upload_server(mock, &[attachment(ATT_ID, FILENAME, 2)]).await;
    // A clean label add on another page.
    mount_any_get(
        mock,
        &content_path("65538"),
        &json!({"id": "65538", "type": "page", "status": "current", "title": "Other",
                "metadata": {"labels": {"results": [], "start": 0, "limit": 200, "size": 0}}}),
    )
    .await;
    let collision = queued(&h, params(FILENAME, TEXT, false, Some(COMMENT))).await?;
    let clean = queued_op(
        &h,
        "confluence.label.add",
        json!({"id": "65538", "labels": ["release"]}),
    )
    .await?;
    let p = h.approver().open(&collision).map_err(de)?.preview;
    assert!(!p.approvable);
    assert!(p.deny_offers.is_empty(), "{:?}", p.deny_offers);
    let requests = card_requests(&p.body)?;
    assert_eq!(
        requests.len(),
        1,
        "the card shows what an approval would send"
    );
    not_approvable(h.approver().approve(&collision))?;
    not_approvable(h.approver().approve_unopened(&collision))?;

    h.approver().open(&clean).map_err(de)?;
    assert!(h.approver().item(&clean).ok_or("gone")?.approvable);
    let batch = [&clean, &collision]
        .iter()
        .map(|r| {
            Ok(BatchItem {
                request_id: (*r).clone(),
                candidate_rev: h.approver().rev(r).map_err(de)?,
            })
        })
        .collect::<Result<Vec<_>, TestError>>()?;
    match h.decisions().decide_batch(batch) {
        Err(DecisionError::BatchRejected { failed }) => assert_eq!(
            failed,
            [(
                collision.clone(),
                BatchFailure::Invalid(InvalidReason::NotApprovable)
            )]
        ),
        other => return Err(format!("expected BatchRejected, got {other:?}").into()),
    }
    for r in [&clean, &collision] {
        assert!(
            records_of(&h, r, EventType::WRITE_APPROVED)
                .await?
                .is_empty()
        );
    }

    // Every deny detail is refused; the plain deny ends the request.
    for details in [
        DenyDetails::ResolutionFailed {
            include_candidates: true,
        },
        DenyDetails::UpstreamHttp {
            include_messages: true,
        },
        DenyDetails::OutcomeHint,
        DenyDetails::MissingFields {
            include_allowed_values: true,
        },
    ] {
        assert!(
            h.approver()
                .deny_with(&collision, "exists", details)
                .is_err(),
            "{details:?}"
        );
    }
    h.approver().deny(&collision, "exists").map_err(de)?;
    let env = h.await_(&collision, 5000).await;
    assert_eq!(env.status, Status::Denied, "{}", env.to_json_line());
    assert_eq!(code(&env), "denied");
    assert_eq!(exit(&env), 3);
    let line = env.to_json_line();
    assert!(!line.contains(ATT_ID), "{line}");
    assert!(
        requests_with(mock, "POST").await.is_empty(),
        "nothing was sent"
    );
    Ok(())
}

// ---- replace ---------------------------------------------------------------------------------

/// PD-109: with `replace`, the one attachment of that name is replaced through its own `/data`
/// endpoint (a `POST`, spec §7.4), the baseline is its id and version, and the stale check re-reads
/// the same lookup before the send.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_replace_uses_attachment_id_data_endpoint() -> TestResult {
    let p = params(FILENAME, TEXT, true, Some(COMMENT));
    let v = verdict(&p, &[attachment(ATT_ID, FILENAME, 2)])?;
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    assert_eq!(v.baseline, json!({"attachment_id": ATT_ID, "version": 2}));
    let existing = v
        .summary
        .as_ref()
        .and_then(|s| s.confluence.as_ref())
        .and_then(|c| c.existing_attachment.as_ref())
        .ok_or("no existing attachment")?;
    assert_eq!((existing.id.as_str(), existing.version), (ATT_ID, 2));
    let r = one_request(&p, &v)?;
    assert_eq!(r.method, "POST");
    assert_eq!(
        r.resolved_url,
        "https://wiki.example.invalid/wiki/rest/api/content/65537/child/attachment/att3001/data"
    );
    let got = parts(&r.body, &boundary_of(&r)?)?;
    assert_eq!(
        got[0],
        (
            file_headers(FILENAME, "application/octet-stream"),
            TEXT.to_vec()
        )
    );
    // The verdict of another `replace` value, filename or page renders nothing.
    for other in [
        params(FILENAME, TEXT, false, Some(COMMENT)),
        params("other.txt", TEXT, true, Some(COMMENT)),
    ] {
        assert_eq!(exec(&other, Some(&v)), Err(ExecError::EnrichmentRequired));
    }
    let mut elsewhere = p.clone();
    elsewhere["id"] = json!("65538");
    assert_eq!(
        exec(&elsewhere, Some(&v)),
        Err(ExecError::EnrichmentRequired)
    );
    // An attachment id that cannot be a path segment fails closed in the judge.
    let v = verdict(&p, &[attachment("att/../1", FILENAME, 2)])?;
    assert_eq!(v.hold, Hold::EnrichmentError);
    // Two current attachments of exactly that name: which one is unclear, fail closed.
    let v = verdict(
        &p,
        &[
            attachment(ATT_ID, FILENAME, 2),
            attachment("att3009", FILENAME, 1),
        ],
    )?;
    assert_eq!(v.hold, Hold::EnrichmentError);

    // End to end.
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    upload_server(mock, &[attachment(ATT_ID, FILENAME, 2)]).await;
    let id = queued(&h, p).await?;
    assert!(h.approver().open(&id).map_err(de)?.preview.approvable);
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let posts = requests_with(mock, "POST").await;
    let [sent] = posts.as_slice() else {
        return Err(format!("{} POSTs", posts.len()).into());
    };
    assert_eq!(sent.url.path(), mock.path(DATA_PATH));
    assert_eq!(sent.url.query(), None);
    assert_eq!(sent.body, r.body);
    // The data endpoint answers the attachment itself: the receipt is its projection.
    assert_eq!(
        env.data,
        Some(json!({"receipt": {
            "id": ATT_ID, "type": "attachment", "status": "current",
            "version": {"number": 3},
            "_links": {"webui": "/display/DOC/Release+checklist?preview=/65537/3001/notes.txt"},
        }}))
    );
    // The lookup (`enrich`), the identity call and the re-read lookup (`stale_check`).
    assert_eq!(
        purposes(&h, &id).await?,
        [json!("enrich"), json!("stale_check"), json!("stale_check")]
    );
    let lookups: Vec<Option<String>> = mock
        .received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == "GET" && r.url.path() == mock.path(ATTACH_PATH))
        .map(|r| r.url.query().map(str::to_owned))
        .collect();
    assert_eq!(
        lookups,
        [
            Some("filename=notes.txt&expand=version&limit=50".to_owned()),
            Some("filename=notes.txt&expand=version&limit=50".to_owned())
        ]
    );
    Ok(())
}

/// T20a review m-1 (lead ruling): with `replace`, no attachment of exactly that name but exactly
/// one that differs only in case is the one replaced (an approver can pick `replace` on a
/// case-variant collision); two such fail closed; an exact match wins over a case variant.
#[test]
fn upload_replace_resolves_one_case_variant() -> TestResult {
    let p = params(FILENAME, TEXT, true, None);
    let v = verdict(&p, &[attachment(ATT_ID, "Notes.TXT", 2)])?;
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    assert_eq!(v.baseline, json!({"attachment_id": ATT_ID, "version": 2}));
    let r = one_request(&p, &v)?;
    assert_eq!(
        r.resolved_url,
        "https://wiki.example.invalid/wiki/rest/api/content/65537/child/attachment/att3001/data"
    );
    let v = verdict(
        &p,
        &[
            attachment(ATT_ID, "Notes.TXT", 2),
            attachment("att3009", "NOTES.txt", 1),
        ],
    )?;
    assert_eq!(v.hold, Hold::EnrichmentError, "two case variants");
    let v = verdict(
        &p,
        &[
            attachment("att3009", "Notes.TXT", 1),
            attachment(ATT_ID, FILENAME, 2),
        ],
    )?;
    assert_eq!(v.hold, Hold::Preview, "{v:?}");
    assert_eq!(v.baseline, json!({"attachment_id": ATT_ID, "version": 2}));
    Ok(())
}

/// Report choice 15 / T20a review m-1: the approver's way out of a collision is to edit
/// `replace: true`. The edit re-runs the lookup, the existing attachment (here one that differs
/// only in case) becomes the one replaced, and the request is approvable after it is opened; the
/// stale check finds the same attachment and the bytes go to its `/data` endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn collision_way_out_is_an_edit_to_replace() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    upload_server(mock, &[attachment(ATT_ID, "Notes.TXT", 2)]).await;
    let id = queued(&h, params(FILENAME, TEXT, false, Some(COMMENT))).await?;
    assert!(!h.approver().open(&id).map_err(de)?.preview.approvable);
    let rev = h.approver().rev(&id).map_err(de)?.counter;
    let mut set = serde_json::Map::new();
    set.insert("replace".into(), json!(true));
    h.approver()
        .edit(
            &id,
            Edits {
                set,
                remove: Vec::new(),
            },
        )
        .map_err(de)?;
    assert!(item_after(&h, &id, rev).await?.approvable);
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert!(preview.approvable);
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let posts = requests_with(mock, "POST").await;
    let [sent] = posts.as_slice() else {
        return Err(format!("{} POSTs", posts.len()).into());
    };
    assert_eq!(sent.url.path(), mock.path(DATA_PATH));
    assert_eq!(
        purposes(&h, &id).await?,
        [
            json!("enrich"),
            json!("enrich"),
            json!("stale_check"),
            json!("stale_check")
        ]
    );
    Ok(())
}

/// PD-109: `replace` without an attachment of that name (exactly or in another case, see
/// `upload_replace_resolves_one_case_variant`) is `UnresolvedName {filename, 0}`; the deny hint
/// says "no attachment '<v>' on content <id>".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_replace_without_existing_is_unresolved() -> TestResult {
    let p = params(FILENAME, TEXT, true, None);
    let v = verdict(&p, &[])?;
    assert_eq!(v.hold, Hold::UnresolvedName);
    assert_eq!(unresolved_of(&v), Some(("filename", FILENAME, 0, vec![])));
    let v = verdict(&p, &[attachment(ATT_ID, "other.txt", 2)])?;
    assert_eq!(unresolved_of(&v), Some(("filename", FILENAME, 0, vec![])));
    assert_eq!(exec(&p, Some(&v)), Err(ExecError::EnrichmentRequired));

    for ticked in [false, true] {
        let h = Harness::confluence().await?;
        let mock = wiki(&h)?;
        upload_server(mock, &[attachment(ATT_ID, "other.txt", 2)]).await;
        let id = queued(&h, p.clone()).await?;
        let preview = h.approver().open(&id).map_err(de)?.preview;
        assert!(!preview.approvable);
        not_approvable(h.approver().approve(&id))?;
        h.approver()
            .deny_with(
                &id,
                "no such file",
                DenyDetails::ResolutionFailed {
                    include_candidates: ticked,
                },
            )
            .map_err(de)?;
        let env = h.await_(&id, 5000).await;
        assert_eq!(code(&env), "resolution_failed", "{}", env.to_json_line());
        assert_eq!(exit(&env), 3);
        assert_eq!(detail(&env, "param"), json!("filename"));
        assert_eq!(detail(&env, "value"), json!(FILENAME));
        assert_eq!(
            detail(&env, "message"),
            json!("no attachment 'notes.txt' on content 65537")
        );
        if ticked {
            assert_eq!(detail(&env, "candidates"), json!([]));
        } else {
            assert_eq!(detail(&env, "candidates"), Value::Null);
        }
        assert!(
            requests_with(mock, "POST").await.is_empty(),
            "nothing was sent"
        );
    }
    Ok(())
}

/// The stale rule (`stale::ATTACHMENT_REPLACE`, replace only): the same attachment id still has
/// that name and its `version.number` is unchanged; anything else is a change (fail closed).
#[test]
fn upload_replace_stale_rule() -> TestResult {
    let p = params(FILENAME, TEXT, true, None);
    let base = json!({"attachment_id": ATT_ID, "version": 2});
    let (calls, verdict) = stale(&p, &base, &[lookup(&[attachment(ATT_ID, FILENAME, 2)])])?;
    assert_eq!(verdict, StaleVerdict::Unchanged);
    let [call] = calls.as_slice() else {
        return Err("not one GET".into());
    };
    assert_eq!(
        call.endpoint_template,
        "/rest/api/content/{id}/child/attachment"
    );
    assert_eq!(call.params, json!({"id": PAGE_ID}));
    assert_eq!(
        query(call),
        [
            ("filename", FILENAME),
            ("expand", "version"),
            ("limit", "50")
        ]
    );
    let changed = |answer: Value| -> Result<String, TestError> {
        match stale(&p, &base, &[answer])?.1 {
            StaleVerdict::Changed { delta } => Ok(delta),
            StaleVerdict::Unchanged => Err("unchanged".into()),
        }
    };
    assert_eq!(
        changed(lookup(&[attachment(ATT_ID, FILENAME, 3)]))?,
        "attachment version changed since review (v2 → v3)"
    );
    assert_eq!(
        changed(lookup(&[attachment("att3009", FILENAME, 2)]))?,
        "attachment replaced by another since review"
    );
    assert_eq!(changed(lookup(&[]))?, "attachment no longer present");
    assert_eq!(
        changed(json!({"size": 1}))?,
        "the target could not be re-read"
    );
    // T20a review m-2: two attachments of that name now (which one would the bytes replace?).
    assert_eq!(
        changed(lookup(&[
            attachment(ATT_ID, FILENAME, 2),
            attachment("att3009", FILENAME, 2)
        ]))?,
        "more than one attachment of this name since review"
    );
    // T20a review I-3: a full page may hide a second one: unreadable.
    let full_page: Vec<Value> = std::iter::once(attachment(ATT_ID, FILENAME, 2))
        .chain((1..50).map(|n| attachment(&format!("att{n}"), &format!("other{n}.txt"), 1)))
        .collect();
    assert_eq!(
        changed(lookup(&full_page))?,
        "the target could not be re-read"
    );
    // T20a review m-1: the replace of the one case variant re-reads it under the same rule.
    let (_, verdict) = stale(&p, &base, &[lookup(&[attachment(ATT_ID, "Notes.TXT", 2)])])?;
    assert_eq!(verdict, StaleVerdict::Unchanged);
    assert_eq!(
        changed(lookup(&[attachment(ATT_ID, "Notes.TXT", 3)]))?,
        "attachment version changed since review (v2 → v3)"
    );
    // A baseline without the attachment fails closed.
    match stale(
        &p,
        &json!(null),
        &[lookup(&[attachment(ATT_ID, FILENAME, 2)])],
    )?
    .1
    {
        StaleVerdict::Changed { .. } => {}
        StaleVerdict::Unchanged => return Err("an unreadable baseline passed".into()),
    }
    // A new attachment has no stale rule: no GET, unchanged.
    let new = params(FILENAME, TEXT, false, None);
    let (calls, verdict) = stale(&new, &Value::Null, &[])?;
    assert!(calls.is_empty());
    assert_eq!(verdict, StaleVerdict::Unchanged);
    Ok(())
}

/// §5.4 step 5: the attachment's version moved after the review: `WRITE_STALE {changed}`, the
/// delta leads the re-review, and nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_replace_stale_when_attachment_version_changed() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    upload_server(mock, &[attachment(ATT_ID, FILENAME, 3)]).await;
    // Enrichment reads v2; the stale check (and every read after) v3.
    mount_lookup_once(mock, &[attachment(ATT_ID, FILENAME, 2)]).await;
    let id = queued(&h, params(FILENAME, TEXT, true, None)).await?;
    h.approver().open(&id).map_err(de)?;
    let rev = h.approver().rev(&id).map_err(de)?.counter;
    h.approver().approve(&id).map_err(de)?;
    let item = item_after(&h, &id, rev).await?;
    assert!(item.stale, "{item:?}");
    let stale: Vec<Value> = records_of(&h, &id, EventType::WRITE_STALE)
        .await?
        .into_iter()
        .map(|p| p["reason"].clone())
        .collect();
    assert_eq!(stale, [json!("changed")]);
    assert!(
        requests_with(mock, "POST").await.is_empty(),
        "nothing was sent"
    );
    let p = h.approver().open(&id).map_err(de)?.preview;
    let changed = p
        .warnings
        .iter()
        .find(|w| w.id == WarningId::ChangedSinceReview)
        .ok_or("no changed-since-review warning")?;
    assert!(
        changed
            .text
            .contains("attachment version changed since review (v2 → v3)"),
        "{}",
        changed.text
    );
    Ok(())
}

/// T16 hand-off (PD-111, V06): Confluence's optimistic-lock reading is `PUT`-only, so a 409 on the
/// replace `POST` is a refused write (`WRITE_FAILED`, `upstream_http`), never a version conflict;
/// the stale rule ran before the send.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_replace_409_is_write_failed() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    upload_server_with(mock, &[attachment(ATT_ID, FILENAME, 2)], 409).await;
    let id = queued(&h, params(FILENAME, TEXT, true, None)).await?;
    h.approver().open(&id).map_err(de)?;
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Failed, "{}", env.to_json_line());
    assert_eq!(code(&env), "upstream_http");
    assert_eq!(detail(&env, "status"), json!(409));
    assert!(
        records_of(&h, &id, EventType::WRITE_STALE)
            .await?
            .is_empty()
    );
    assert_eq!(records_of(&h, &id, EventType::WRITE_FAILED).await?.len(), 1);
    assert_eq!(requests_with(mock, "POST").await.len(), 1);
    Ok(())
}

// ---- receipt and caps ------------------------------------------------------------------------

/// Δ4 b: the receipt is the projection of `results[0]` when the answer is `{"results":[…]}`
/// (the new-attachment answer, V06 confirms), else of the object itself (the `/data` answer).
#[test]
fn upload_receipt_projects_first_result() -> TestResult {
    let spec = spec()?;
    let first = json!({"id": "att3002", "type": "attachment", "status": "current",
                       "title": FILENAME, "version": {"number": 1, "when": "x"},
                       "_links": {"webui": "/w", "download": "/d"}});
    let want = json!({"id": "att3002", "type": "attachment", "status": "current",
                      "version": {"number": 1}, "_links": {"webui": "/w"}});
    let answer = json!({"results": [first.clone(), {"id": "att3003"}], "size": 2});
    assert_eq!(generic::project_receipt(spec, &answer, &json!({})), want);
    assert_eq!(generic::project_receipt(spec, &first, &json!({})), want);
    assert_eq!(
        generic::project_receipt(spec, &json!({"results": [], "size": 0}), &json!({})),
        json!({})
    );
    assert_eq!(
        generic::receipt_fields(spec),
        ["id", "type", "status", "version.number", "_links.webui"]
    );
    Ok(())
}

/// §7.4: at most 10 MiB (the validate test `upload_size_limit` pins the cap itself); end to end
/// the agent gets `validation`, exit 2, nothing queued and no content echoed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_over_10mib_rejected_exit2() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    let over = vec![b'A'; 10 * 1024 * 1024 + 1];
    let env = h.submit(UPLOAD, params(FILENAME, &over, false, None)).await;
    assert_eq!(code(&env), "validation", "{}", env.to_json_line());
    assert_eq!(exit(&env), 2);
    assert_eq!(detail(&env, "param"), json!("content_base64"));
    assert!(env.to_json_line().len() < 1024, "no content echoed");
    let id = request_id(&env)?;
    assert_eq!(
        h.event_types(&id).await?,
        [EventType::REQUEST_RECEIVED, EventType::REQUEST_REJECTED]
    );
    assert!(mock.received().await.is_empty(), "nothing fetched or sent");
    // Exactly 10 MiB is accepted (queued).
    upload_server(mock, &[]).await;
    let at_cap = vec![b'A'; 10 * 1024 * 1024];
    queued(&h, params(FILENAME, &at_cap, false, None)).await?;
    Ok(())
}

/// Plan review I-4 / T20a review I-2 (lead rulings): a 10 MiB upload never puts the file into
/// the Request tab's params (`content_base64` is its size and SHA-256, the content `null`); Raw
/// stays the exact request list `WRITE_APPROVED` stores (option B), fetched on demand in pages
/// of at most `page_bytes` (256 KiB) per `raw_page` call, never as one DTO; the executor still
/// sends the real bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_tab_digests_the_file_and_raw_stays_paged_10mib() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    upload_server(mock, &[]).await;
    let content: Vec<u8> = (0..10 * 1024 * 1024u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let id = queued(&h, params(FILENAME, &content, false, Some(COMMENT))).await?;

    let detail = h
        .decisions()
        .request_detail(&id)
        .ok_or("no request detail")?;
    let serialized = serde_json::to_string(&detail)?;
    assert!(serialized.len() < 4096, "{} bytes", serialized.len());
    no_file_bytes(&serialized, &content)?;
    assert_eq!(
        detail.params["content_base64"],
        json!({"content": null, "bytes": content.len(), "sha256": sha256_hex(&content)})
    );
    assert_eq!(detail.params["filename"], json!(FILENAME));
    assert_eq!(detail.params["comment"], json!(COMMENT));

    // Raw: only the pager metadata is in the preview; each page is one bounded call.
    let preview = h.approver().open(&id).map_err(de)?.preview;
    let pager = preview.raw;
    assert_eq!(pager.page_bytes, 256 * 1024);
    assert!(
        pager.total_bytes > 10 * 1024 * 1024,
        "the whole stored list"
    );
    assert_eq!(
        pager.page_count,
        pager.total_bytes.div_ceil(pager.page_bytes)
    );
    let rev = h.approver().rev(&id).map_err(de)?;
    let mut raw = Vec::new();
    for page in 0..pager.page_count {
        let p = h.decisions().raw_page(&id, rev, page).map_err(de)?;
        assert!(p.bytes.len() as u64 <= pager.page_bytes, "page {page}");
        raw.extend(p.bytes);
    }
    assert_eq!(raw.len() as u64, pager.total_bytes);

    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 20_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let posts = requests_with(mock, "POST").await;
    let [sent] = posts.as_slice() else {
        return Err(format!("{} POSTs", posts.len()).into());
    };
    let boundary = sent
        .headers
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .and_then(|ct| ct.strip_prefix("multipart/form-data; boundary="))
        .ok_or("no multipart content type")?;
    assert_eq!(parts(&sent.body, boundary)?[0].1, content, "the real bytes");
    // Raw is exactly the list `WRITE_APPROVED` stores (the stored array, `body_b64` the wire
    // bytes).
    let approved = records_of(&h, &id, EventType::WRITE_APPROVED).await?;
    let [approved] = approved.as_slice() else {
        return Err("not one WRITE_APPROVED".into());
    };
    assert_eq!(raw, serde_json::to_vec(&approved["requests"])?);
    let raw: Value = serde_json::from_slice(&raw)?;
    assert_eq!(
        STANDARD.decode(raw[0]["body_b64"].as_str().ok_or("no body_b64")?)?,
        sent.body
    );
    Ok(())
}

// ---- the attachment card (Task 20b, PD-110) --------------------------------------------------

/// A 1×1 PNG.
const PIXEL_PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
const MIB: usize = 1024 * 1024;
/// plan text (PD-110): the card without a thumbnail.
const NO_THUMBNAIL: &str = "no thumbnail (not an image, or larger than 2 MiB)";
/// plan text (PD-110): the fact row of an active or mismatched extension.
const MISMATCH: &str = "extension and content type differ";

/// The fields of the `AttachmentUpload` card.
struct Card<'a> {
    filename: &'a str,
    size: u64,
    mime: &'a str,
    sha256: &'a str,
    thumbnail: Option<&'a str>,
    replaces: Option<u64>,
    existing: Option<&'a str>,
    comment: Option<&'a str>,
    notes: &'a [String],
    requests: &'a [RequestView],
}

fn card(body: &PreviewBody) -> Result<Card<'_>, TestError> {
    match body {
        PreviewBody::AttachmentUpload {
            filename,
            size,
            mime,
            sha256,
            thumbnail_data_uri,
            replaces_version,
            existing,
            comment,
            notes,
            requests,
        } => Ok(Card {
            filename,
            size: *size,
            mime,
            sha256,
            thumbnail: thumbnail_data_uri.as_deref(),
            replaces: *replaces_version,
            existing: existing.as_deref(),
            comment: comment.as_deref(),
            notes,
            requests,
        }),
        other => Err(format!("not the attachment card: {other:?}").into()),
    }
}

/// The requests the attachment card shows.
fn card_requests(body: &PreviewBody) -> Result<&[RequestView], TestError> {
    Ok(card(body)?.requests)
}

/// `body` without its thumbnail.
fn without_thumbnail(body: &PreviewBody) -> PreviewBody {
    let mut body = body.clone();
    if let PreviewBody::AttachmentUpload {
        thumbnail_data_uri, ..
    } = &mut body
    {
        *thumbnail_data_uri = None;
    }
    body
}

/// The preview of the upload `p` after a lookup that found `found`.
fn card_model(p: &Value, found: &[Value]) -> Result<PreviewModel, TestError> {
    let v = verdict(p, found)?;
    let r = one_request(p, &v)?;
    preview_of(p, &v, std::slice::from_ref(&r))
}

/// `len` bytes that start with `magic`.
fn headed(magic: &[u8], len: usize) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.extend((0..len.saturating_sub(magic.len())).map(|i| (i % 251) as u8));
    out
}

fn is_generic(m: &PreviewModel) -> bool {
    matches!(m.body, PreviewBody::WriteRequests { .. })
}

async fn opened_doc(
    h: &Harness,
    id: &str,
) -> Result<(atlas_duck_preview::Preview, String), TestError> {
    let preview = h.approver().open(id).map_err(de)?.preview;
    let doc = render::document(&preview, Platform::current());
    Ok((preview, doc))
}

/// §6.3 Attachment upload / PD-110: the card shows the file name, the size, the sniffed MIME type,
/// the SHA-256 and, for a raster image (png, jpeg, gif, webp) of at most 2 MiB, a `data:`
/// thumbnail in standard base64, unwrapped (T8 review m-7), that renders as an `<img>`; any other
/// type, and a larger image, shows the PD-110 text. The file part's bytes count as hidden once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_card_size_mime_sha256_thumbnail() -> TestResult {
    let png = STANDARD.decode(PIXEL_PNG)?;
    let p = params("pixel.png", &png, false, Some(COMMENT));
    let m = card_model(&p, &[])?;
    let c = card(&m.body)?;
    assert_eq!(c.filename, "pixel.png");
    assert_eq!(c.size, png.len() as u64);
    assert_eq!(c.mime, "image/png");
    assert_eq!(c.sha256, sha256_hex(&png));
    let uri = format!("data:image/png;base64,{}", STANDARD.encode(&png));
    assert_eq!(c.thumbnail, Some(uri.as_str()));
    assert_eq!(c.comment, Some(COMMENT));
    assert_eq!((c.replaces, c.existing), (None, None));
    assert!(c.notes.is_empty(), "{:?}", c.notes);
    assert_eq!(c.requests.len(), 1, "the request list stays on the card");
    assert_eq!(
        m.header.hidden_in_preview_bytes,
        png.len() as u64,
        "the file part's bytes, counted once"
    );

    // Each raster type is its own `data:` type; other types and other content get no thumbnail.
    let webp = [b"RIFF\x24\x00\x00\x00WEBPVP8 ".as_slice(), &[0u8; 24]].concat();
    let cases: [(&str, Vec<u8>, &str, Option<&str>); 7] = [
        (
            "a.jpg",
            headed(b"\xff\xd8\xff\xe0", 64),
            "image/jpeg",
            Some("image/jpeg"),
        ),
        (
            "a.gif",
            headed(b"GIF89a", 64),
            "image/gif",
            Some("image/gif"),
        ),
        ("a.webp", webp, "image/webp", Some("image/webp")),
        ("a.pdf", headed(b"%PDF-1.7\n", 64), "application/pdf", None),
        ("a.zip", headed(b"PK\x03\x04", 64), "application/zip", None),
        (FILENAME, TEXT.to_vec(), "application/octet-stream", None),
        (
            "a.svg",
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>".to_vec(),
            "application/octet-stream",
            None,
        ),
    ];
    for (name, content, mime, raster) in cases {
        let m = card_model(&params(name, &content, false, None), &[])?;
        let c = card(&m.body)?;
        assert_eq!((c.filename, c.mime), (name, mime));
        assert_eq!(c.sha256, sha256_hex(&content), "{name}");
        let want = raster.map(|t| format!("data:{t};base64,{}", STANDARD.encode(&content)));
        assert_eq!(c.thumbnail, want.as_deref(), "{name}");
        assert_eq!(c.comment, None);
    }
    // The cap: an image of exactly 2 MiB has a thumbnail, one byte more has none.
    for (len, thumbnail) in [(2 * MIB, true), (2 * MIB + 1, false), (3 * MIB, false)] {
        let content = headed(PNG_MAGIC, len);
        let m = card_model(&params("big.png", &content, false, None), &[])?;
        let c = card(&m.body)?;
        assert_eq!((c.mime, c.size), ("image/png", len as u64));
        assert_eq!(c.thumbnail.is_some(), thumbnail, "{len}");
    }

    // End to end: the rendered card.
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    upload_server(mock, &[]).await;
    let id = queued(&h, params("pixel.png", &png, false, Some(COMMENT))).await?;
    let (_, doc) = opened_doc(&h, &id).await?;
    assert!(
        doc.contains(&format!("<img src=\"{uri}\"")),
        "the thumbnail renders as an image"
    );
    let size = format!("{} bytes", png.len());
    for text in ["pixel.png", "image/png", &sha256_hex(&png), &size, COMMENT] {
        assert!(doc.contains(text), "{text}");
    }
    assert!(!doc.contains(NO_THUMBNAIL));
    let big = headed(PNG_MAGIC, 3 * MIB);
    let id = queued(&h, params("big.png", &big, false, None)).await?;
    let (_, doc) = opened_doc(&h, &id).await?;
    assert!(doc.contains(NO_THUMBNAIL), "a 3 MiB PNG");
    assert!(!doc.contains("<img"), "no image for a 3 MiB PNG");
    let id = queued(&h, params(FILENAME, TEXT, false, None)).await?;
    let (_, doc) = opened_doc(&h, &id).await?;
    assert!(doc.contains(NO_THUMBNAIL), "a text file");
    assert!(doc.contains("application/octet-stream"));
    Ok(())
}

/// PD-109 / §7.4: the collision hold's card says "attachment already exists" with the facts of
/// the attachment the lookup found (its id, version and size), and still shows the request an
/// approval would have sent; Approve stays disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn collision_card_line() -> TestResult {
    let p = params(FILENAME, TEXT, false, Some(COMMENT));
    let m = card_model(&p, &[attachment(ATT_ID, FILENAME, 2)])?;
    let c = card(&m.body)?;
    assert_eq!(c.existing, Some("attachment att3001, version 2, 11 bytes"));
    assert_eq!(c.replaces, None);
    assert_eq!(c.requests.len(), 1);
    assert_eq!(c.sha256, sha256_hex(TEXT));
    // A case variant without a reported size.
    let mut variant = attachment(ATT_ID, "Notes.TXT", 4);
    variant["extensions"] = json!({});
    let m = card_model(&p, &[variant])?;
    assert_eq!(
        card(&m.body)?.existing,
        Some("attachment att3001, version 4, size not reported")
    );

    // End to end.
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    upload_server(mock, &[attachment(ATT_ID, FILENAME, 2)]).await;
    let id = queued(&h, p).await?;
    let (preview, doc) = opened_doc(&h, &id).await?;
    assert!(!preview.approvable);
    let c = card(&preview.body)?;
    assert_eq!(c.existing, Some("attachment att3001, version 2, 11 bytes"));
    assert!(doc.contains("attachment already exists"), "{doc}");
    assert!(doc.contains("attachment att3001, version 2, 11 bytes"));
    not_approvable(h.approver().approve(&id))?;
    Ok(())
}

/// §6.3 "replaces existing attachment vN" when `replace`: N is the version of the one attachment
/// of that name, and the card's request is that attachment's `/data` endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replace_card_line() -> TestResult {
    let p = params(FILENAME, TEXT, true, None);
    let m = card_model(&p, &[attachment(ATT_ID, FILENAME, 3)])?;
    let c = card(&m.body)?;
    assert_eq!((c.replaces, c.existing), (Some(3), None));
    assert!(c.requests[0].resolved_url.ends_with(DATA_PATH));
    // A new attachment replaces nothing.
    let new = params(FILENAME, TEXT, false, None);
    assert_eq!(card(&card_model(&new, &[])?.body)?.replaces, None);
    // A request to another attachment's endpoint, or a new-attachment request under the replace
    // verdict, keeps the generic list (§5.1 inv. 4: the card states what is sent).
    let v = verdict(&p, &[attachment(ATT_ID, FILENAME, 3)])?;
    let mut other = one_request(&p, &v)?;
    other.resolved_url = other.resolved_url.replace(ATT_ID, "att3009");
    assert!(is_generic(&preview_of(&p, &v, &[other])?));
    let as_new = one_request(&new, &verdict(&new, &[])?)?;
    assert!(is_generic(&preview_of(&p, &v, &[as_new])?));

    // End to end.
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    upload_server(mock, &[attachment(ATT_ID, FILENAME, 3)]).await;
    let id = queued(&h, p).await?;
    let (preview, doc) = opened_doc(&h, &id).await?;
    assert!(preview.approvable);
    assert_eq!(card(&preview.body)?.replaces, Some(3));
    assert!(doc.contains("replaces existing attachment v3"), "{doc}");
    Ok(())
}

/// §5.1 inv. 4: the card states the facts of the request that is sent (file name, bytes, comment
/// and the type the part is sent as); a request list that is not exactly one multipart upload in
/// the executor's layout keeps the generic request list.
#[test]
fn card_is_built_over_the_request_sent() -> TestResult {
    let p = params(FILENAME, TEXT, false, Some(COMMENT));
    let v = verdict(&p, &[])?;
    let other = params("other.txt", b"other bytes", false, Some("another comment"));
    let sent = one_request(&other, &verdict(&other, &[])?)?;
    let m = preview_of(&p, &v, std::slice::from_ref(&sent))?;
    let c = card(&m.body)?;
    assert_eq!(
        (c.filename, c.size, c.sha256, c.comment),
        (
            "other.txt",
            11,
            sha256_hex(b"other bytes").as_str(),
            Some("another comment")
        )
    );

    let r = one_request(&p, &v)?;
    let boundary = boundary_of(&r)?;
    let swap = |from: &str, to: &str| {
        let mut x = r.clone();
        let body = String::from_utf8_lossy(&x.body).replace(from, to);
        x.body = body.into_bytes();
        x
    };
    let mut no_type = r.clone();
    no_type.content_type = None;
    let mut extra = r.clone();
    extra.body.extend_from_slice(b"trailing");
    let cases = [
        vec![r.clone(), r.clone()],
        vec![],
        vec![no_type],
        vec![extra],
        // The part is not sent as the sniffed type.
        vec![swap("application/octet-stream", "text/html")],
        // Another part name, another boundary in the body.
        vec![swap("name=\"file\"", "name=\"data\"")],
        vec![swap(&format!("--{boundary}--"), "--x--")],
    ];
    for reqs in cases {
        let m = preview_of(&p, &v, &reqs)?;
        assert!(is_generic(&m), "{:?}", m.body);
    }
    Ok(())
}

/// PD-110 (plan review m-9): a fact row "extension and content type differ" when the file name's
/// extension names an active type, or disagrees with the sniffed type; none when they agree.
#[test]
fn active_extension_fact_row() -> TestResult {
    let png = STANDARD.decode(PIXEL_PNG)?;
    let zip = headed(b"PK\x03\x04", 64);
    let jpeg = headed(b"\xff\xd8\xff\xe0", 64);
    let cases: [(&str, &[u8], bool); 16] = [
        ("x.svg", &png, true),
        ("x.html", b"<p>hi</p>", true),
        ("x.HTM", TEXT, true),
        ("x.js", TEXT, true),
        ("x.xhtml", TEXT, true),
        // Windows drops a trailing dot or space when the file is saved.
        ("x.html.", TEXT, true),
        // An image named as text, and a name of a sniffed type over other bytes.
        ("x.txt", &png, true),
        ("x.pdf", TEXT, true),
        ("x.jpg", &png, true),
        ("x.png", &png, false),
        ("X.PNG", &png, false),
        ("photo.jpeg", &jpeg, false),
        ("report.docx", &zip, false),
        ("archive.zip", &zip, false),
        (FILENAME, TEXT, false),
        ("README", TEXT, false),
    ];
    for (name, content, row) in cases {
        let m = card_model(&params(name, content, false, None), &[])?;
        let c = card(&m.body)?;
        assert_eq!(
            c.notes.iter().any(|n| n.starts_with(MISMATCH)),
            row,
            "{name}: {:?}",
            c.notes
        );
        if !row {
            assert!(c.notes.is_empty(), "{name}: {:?}", c.notes);
        }
        // A row, no warning of its own (the §6.4 counts of the part bodies stay as they are).
        assert!(
            m.warnings
                .iter()
                .all(|w| matches!(w.id, WarningId::OtherInvisible | WarningId::BidiControls)),
            "{name}: {:?}",
            m.warnings
        );
    }
    Ok(())
}

/// PD-110: the edit form shows `content_base64` read-only with the value `null` and the plan-text
/// label naming the size and the first 8 hex of the SHA-256; the other inputs keep their values,
/// and the serialized preview holds no base64 of the content.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edit_form_content_not_inlined() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    upload_server(mock, &[]).await;
    let id = queued(&h, params(FILENAME, TEXT, false, Some(COMMENT))).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    let form = preview.edit_form.as_ref().ok_or("no edit form")?;
    let input = |name: &str| {
        form.inputs
            .iter()
            .find(|i| i.path == name)
            .ok_or_else(|| TestError::from(format!("no {name} input")))
    };
    let content = input("content_base64")?;
    assert!(content.read_only);
    assert_eq!(content.value, Value::Null);
    assert_eq!(
        content.label,
        format!(
            "file content ({} bytes, SHA-256 {}…): not editable here; deny and resubmit to change it",
            TEXT.len(),
            &sha256_hex(TEXT)[..8]
        )
    );
    assert_eq!(input("filename")?.value, json!(FILENAME));
    assert!(!input("filename")?.read_only);
    assert_eq!(input("comment")?.value, json!(COMMENT));
    assert!(input("id")?.read_only);
    no_file_bytes(&serde_json::to_string(&preview)?, TEXT)?;
    Ok(())
}

/// PD-110 (plan review m-17): the raw-JSON editor is seeded from the form, so a save sends
/// `content_base64: null`: that is "unchanged" (the stored content stays, its SHA-256 too), while
/// the rest of the edit applies; any other value is validated as usual.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn content_base64_null_edit_is_unchanged() -> TestResult {
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    upload_server(mock, &[]).await;
    let id = queued(&h, params(FILENAME, TEXT, false, Some(COMMENT))).await?;
    h.approver().open(&id).map_err(de)?;
    let edit = |pairs: &[(&str, Value)]| Edits {
        set: pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect::<Map<String, Value>>(),
        remove: Vec::new(),
    };

    // Not base64: refused, nothing changes.
    let res = h.approver().edit(
        &id,
        edit(&[
            ("content_base64", json!("not base64!")),
            ("comment", json!("x")),
        ]),
    );
    assert!(
        matches!(res, Err(DecisionError::EditRejected(_))),
        "{res:?}"
    );

    let rev = h.approver().rev(&id).map_err(de)?.counter;
    h.approver()
        .edit(
            &id,
            edit(&[
                ("content_base64", Value::Null),
                ("comment", json!("Revised notes")),
            ]),
        )
        .map_err(de)?;
    item_after(&h, &id, rev).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    let c = card(&preview.body)?;
    assert_eq!(c.comment, Some("Revised notes"));
    assert_eq!(
        (c.size, c.sha256),
        (TEXT.len() as u64, sha256_hex(TEXT).as_str())
    );
    h.approver().approve(&id).map_err(de)?;
    let env = h.await_(&id, 10_000).await;
    assert_eq!(env.status, Status::Succeeded, "{}", env.to_json_line());
    let posts = requests_with(mock, "POST").await;
    let [sent] = posts.as_slice() else {
        return Err(format!("{} POSTs", posts.len()).into());
    };
    let got = parts(&sent.body, &first_boundary(TEXT))?;
    assert_eq!(got[0].1, TEXT, "the file bytes stayed");
    assert_eq!(got[1].1, b"Revised notes");

    // Another value is an edit of the content like any other.
    let id = queued(&h, params(FILENAME, TEXT, false, None)).await?;
    h.approver().open(&id).map_err(de)?;
    let rev = h.approver().rev(&id).map_err(de)?.counter;
    let new = b"new bytes".as_slice();
    h.approver()
        .edit(
            &id,
            edit(&[("content_base64", json!(STANDARD.encode(new)))]),
        )
        .map_err(de)?;
    item_after(&h, &id, rev).await?;
    let preview = h.approver().open(&id).map_err(de)?.preview;
    assert_eq!(card(&preview.body)?.sha256, sha256_hex(new));
    Ok(())
}

/// Plan review I-4 (T8 review m-2): a 10 MiB upload (a PNG, so only the 2 MiB cap keeps the
/// thumbnail out) opens with a serialized preview DTO below 64 KiB (body, header and edit form),
/// a document of at most `DOC_MAX_BYTES` + 4 KiB that names the SHA-256, the file's bytes counted
/// as hidden, and no slice or base64 of the file anywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_10mib_preview_is_bounded() -> TestResult {
    let content = headed(PNG_MAGIC, 10 * MIB);
    let sha = sha256_hex(&content);
    let h = Harness::confluence().await?;
    let mock = wiki(&h)?;
    upload_server(mock, &[]).await;
    let id = queued(&h, params("big.png", &content, false, Some(COMMENT))).await?;
    h.approver().open(&id).map_err(de)?;
    let t = Instant::now();
    let preview = h.decisions().preview_fetch(&id, None).map_err(de)?.preview;
    let build = t.elapsed();
    let t = Instant::now();
    let doc = render::document(&preview, Platform::current());
    let render_took = t.elapsed();
    println!(
        "P01-style upload_10mib preview {:.1} ms (build), render::document {:.1} ms",
        build.as_secs_f64() * 1000.0,
        render_took.as_secs_f64() * 1000.0
    );
    let dto = serde_json::to_string(&preview)?;
    assert!(dto.len() < 64 * 1024, "preview DTO {} bytes", dto.len());
    assert!(
        doc.len() <= DOC_MAX_BYTES + 4 * 1024,
        "document {} bytes",
        doc.len()
    );
    assert!(doc.contains(&sha), "the SHA-256 line");
    assert!(doc.contains(&body_digest_line(content.len() as u64, &sha)));
    let c = card(&preview.body)?;
    assert_eq!(
        (c.size, c.mime, c.thumbnail),
        (content.len() as u64, "image/png", None)
    );
    assert!(doc.contains(NO_THUMBNAIL));
    assert_eq!(
        preview.header.hidden_in_preview_bytes,
        content.len() as u64,
        "the file's bytes are hidden, once"
    );
    no_file_bytes(&dto, &content)?;
    no_file_bytes(&doc, &content)?;
    Ok(())
}

// ---- end to end helpers ----------------------------------------------------------------------

fn wiki(h: &Harness) -> Result<&MockDc, TestError> {
    h.mock("wiki").ok_or_else(|| "no wiki mock".into())
}

fn json_answer(mock: &MockDc, status: u16, body: &Value) -> ResponseTemplate {
    mock.response(status)
        .set_body_raw(body.to_string(), "application/json")
}

async fn mount_any_get(mock: &MockDc, p: &str, body: &Value) {
    Mock::given(method("GET"))
        .and(path(mock.path(p)))
        .respond_with(json_answer(mock, 200, body))
        .mount(mock.server())
        .await;
}

/// The lookup answers `found` (any query), behind a [`mount_lookup_once`].
async fn mount_lookup(mock: &MockDc, found: &[Value]) {
    Mock::given(method("GET"))
        .and(path(mock.path(ATTACH_PATH)))
        .respond_with(json_answer(mock, 200, &lookup(found)))
        .with_priority(2)
        .mount(mock.server())
        .await;
}

/// The first lookup answers `found`.
async fn mount_lookup_once(mock: &MockDc, found: &[Value]) {
    Mock::given(method("GET"))
        .and(path(mock.path(ATTACH_PATH)))
        .respond_with(json_answer(mock, 200, &lookup(found)))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(mock.server())
        .await;
}

/// The server side of an upload to page 65537: the identity call, the lookup answering `found`,
/// the new-attachment `POST` (answering `{"results":[…]}`) and the `/data` `POST` (answering the
/// attachment).
async fn upload_server(mock: &MockDc, found: &[Value]) {
    upload_server_with(mock, found, 200).await;
}

async fn upload_server_with(mock: &MockDc, found: &[Value], status: u16) {
    mock.confluence_user_current(UserKind::Known, TEST_USER, TEST_USER_KEY)
        .await;
    mount_lookup(mock, found).await;
    let created = json!({"results": [{
        "id": "att3002", "type": "attachment", "status": "current", "title": FILENAME,
        "version": {"number": 1},
        "_links": {"webui": "/display/DOC/Release+checklist?preview=/65537/3002/notes.txt",
                   "download": "/download/attachments/65537/notes.txt"},
    }], "size": 1});
    let replaced = json!({
        "id": ATT_ID, "type": "attachment", "status": "current", "title": FILENAME,
        "version": {"number": 3},
        "_links": {"webui": "/display/DOC/Release+checklist?preview=/65537/3001/notes.txt"},
    });
    let conflict = json!({"statusCode": 409, "message": "Attachment conflict"});
    let (created, replaced) = if status == 200 {
        (created, replaced)
    } else {
        (conflict.clone(), conflict)
    };
    for (p, body) in [(ATTACH_PATH, created), (DATA_PATH, replaced)] {
        Mock::given(method("POST"))
            .and(path(mock.path(p)))
            .respond_with(json_answer(mock, status, &body))
            .mount(mock.server())
            .await;
    }
}

async fn queued(h: &Harness, params: Value) -> Result<String, TestError> {
    queued_op(h, UPLOAD, params).await
}

async fn queued_op(h: &Harness, op: &str, params: Value) -> Result<String, TestError> {
    let env = h.submit(op, params).await;
    assert_eq!(env.status, Status::Pending, "{}", env.to_json_line());
    let id = request_id(&env)?;
    h.queued(&id, 10_000).await.ok_or("never queued")?;
    Ok(id)
}

fn not_approvable(res: Result<DecisionOutcome, DecisionError>) -> TestResult {
    assert!(
        matches!(
            res,
            Err(DecisionError::Invalid(InvalidReason::NotApprovable))
        ),
        "{res:?}"
    );
    Ok(())
}

async fn requests_with(mock: &MockDc, verb: &str) -> Vec<wiremock::Request> {
    mock.received()
        .await
        .into_iter()
        .filter(|r| r.method.as_str() == verb)
        .collect()
}

async fn purposes(h: &Harness, id: &str) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(t, _)| *t == EventType::PREVIEW_FETCH)
        .map(|(_, p)| p["purpose"].clone())
        .collect())
}

async fn records_of(h: &Harness, id: &str, t: EventType) -> Result<Vec<Value>, TestError> {
    Ok(h.events(id)
        .await?
        .into_iter()
        .filter(|(e, _)| *e == t)
        .map(|(_, p)| p)
        .collect())
}

async fn item_after(
    h: &Harness,
    id: &str,
    rev: u64,
) -> Result<atlas_duck_core::QueueItem, TestError> {
    for _ in 0..400 {
        if let Some(item) = h.approver().item(id)
            && item.candidate_rev.counter > rev
        {
            return Ok(item);
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    Err("the revision never advanced".into())
}

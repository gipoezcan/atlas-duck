//! The M12 exit criterion in process (T24): an MCP client with an API key reads Jira through the
//! user's PAT, proposes a write, the user approves it in the browser and the write lands; the
//! user's chain holds the records of every step and verifies, and the server anchor chain
//! verifies with the user's head in its last `HEADS` row.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use atlas_duck_atlassian::testing::TEST_PAT;
use atlas_duck_audit::EventType;
use atlas_duck_audit::types::{AuditCursor, AuditFilter};
use atlas_duck_server::anchor::{self, KIND_HEADS};
use atlas_duck_server::users::user_id_for;
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exit_criterion_flow() {
    let s = TestServer::start().await;
    let flow = exit_flow(&s, TEST_PAT).await;
    let uid = user_id_for(ALICE.0);
    let rt = s
        .registry
        .open_runtimes()
        .await
        .into_iter()
        .find(|r| r.user_id() == uid)
        .expect("alice's runtime is open");

    // Alice's chain: the server records and the request lifecycle, and it verifies.
    let page = rt
        .audit_store()
        .query(&AuditFilter::default(), AuditCursor::first(500))
        .unwrap();
    let kinds: Vec<EventType> = page.rows.iter().map(|r| r.event_type).collect();
    for want in [
        EventType::LOGIN,
        EventType::CREDENTIAL_CHANGED,
        EventType::API_KEY_CREATED,
        EventType::WRITE_APPROVED,
    ] {
        assert!(kinds.contains(&want), "{want:?} missing from {kinds:?}");
    }
    for id in [&flow.read_id, &flow.write_id] {
        assert!(
            page.rows
                .iter()
                .any(|r| r.request_id.as_deref() == Some(id.as_str())),
            "no record of {id}"
        );
    }
    let findings = rt.audit_store().full_verify();
    assert!(findings.is_empty(), "{findings:?}");

    // The anchor chain: a forced tick anchors alice's current head; the chain verifies.
    let row = s.anchor.tick().await.unwrap().expect("a HEADS row");
    assert_eq!(row.kind, KIND_HEADS);
    let heads = s.store.anchor_heads_for(row.seq).unwrap();
    let (chain, seq, hash) = rt.head();
    let mine = heads
        .iter()
        .find(|h| h.user_id == uid)
        .expect("alice anchored");
    assert_eq!(
        (&mine.chain_id, mine.head_seq, mine.record_hash),
        (&chain, seq, hash)
    );
    let report = anchor::verify(s.store.as_ref()).unwrap();
    assert_eq!(report.last_seq, row.seq);
}

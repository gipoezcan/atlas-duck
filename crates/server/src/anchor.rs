//! The server anchor chain writer and verifier (SM-6.3, PD-217): a hash-chained, append-only
//! table in `server.db` (rows v2: the body committed by its hash). Kinds: `ANCHOR_GENESIS`,
//! `SERVER_START`, `HEADS` (`{"leaves": [...]}` of every user head that changed since its last
//! anchoring, plus every user not anchored for 24 h), `RUNTIME_CLOSED` (`{"leaf"}` on eviction
//! and shutdown), `LOGIN_FAILED`, `SERVER_STOP`. Leaves name no user in clear; `anchor_heads`
//! holds the clear entries for verification and excerpts.
//!
//! A closed user's head is read from what the writer anchored last (no store is opened): once
//! per 24 h it is anchored again from that entry; a restart forgets these until the user opens.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use atlas_duck_audit::server_anchor::{
    GENESIS_PREV, heads_body_jcs, leaf_body_jcs, leaf_hash, row_hash,
};
use serde_json::Value;

use crate::clock::{Clock, rfc3339};
use crate::runtime::{Head, Registry};
use crate::store::{AnchorHead, AnchorRow, ServerStore, StoreError};

pub const KIND_LOGIN_FAILED: &str = "LOGIN_FAILED";
pub const KIND_GENESIS: &str = "ANCHOR_GENESIS";
pub const KIND_HEADS: &str = "HEADS";
pub const KIND_RUNTIME_CLOSED: &str = "RUNTIME_CLOSED";
pub const KIND_SERVER_START: &str = "SERVER_START";
pub const KIND_SERVER_STOP: &str = "SERVER_STOP";
/// Every user is anchored at least once per this many seconds.
pub const REANCHOR_SECS: i64 = 24 * 3600;

/// Appends one row whose body is `body_jcs`, with its `anchor_heads` entries.
fn append_raw(
    store: &dyn ServerStore,
    now: i64,
    kind: &str,
    body_jcs: &[u8],
    heads: &[AnchorHead],
) -> Result<AnchorRow, StoreError> {
    let ts = rfc3339(now);
    store.anchor_append(kind, &ts, body_jcs, heads, &|seq, prev| {
        row_hash(seq, &ts, kind, body_jcs, prev)
    })
}

/// Appends one operational row whose body is `body` in JCS; no user heads.
pub fn append_operational(
    store: &dyn ServerStore,
    now: i64,
    kind: &str,
    body: &Value,
) -> Result<AnchorRow, StoreError> {
    let body_jcs =
        serde_jcs::to_vec(body).map_err(|_| StoreError::Db("body not serializable".into()))?;
    append_raw(store, now, kind, &body_jcs, &[])
}

fn anchor_head(user_id: &str, head: &Head) -> (AnchorHead, [u8; 32]) {
    let (chain_id, seq, hash) = head;
    (
        AnchorHead {
            user_id: user_id.to_owned(),
            chain_id: chain_id.clone(),
            head_seq: *seq,
            record_hash: *hash,
        },
        leaf_hash(user_id, chain_id, *seq, hash),
    )
}

/// What the writer anchored last per user: the head and when.
type Anchored = HashMap<String, (Head, i64)>;

pub struct AnchorWriter {
    store: Arc<dyn ServerStore>,
    registry: Arc<Registry>,
    clock: Arc<dyn Clock>,
    anchored: Mutex<Anchored>,
}

impl AnchorWriter {
    pub fn new(
        store: Arc<dyn ServerStore>,
        registry: Arc<Registry>,
        clock: Arc<dyn Clock>,
    ) -> AnchorWriter {
        AnchorWriter {
            store,
            registry,
            clock,
            anchored: Mutex::new(HashMap::new()),
        }
    }

    fn anchored(&self) -> std::sync::MutexGuard<'_, Anchored> {
        self.anchored.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `ANCHOR_GENESIS` when the chain is empty, then `SERVER_START`.
    pub fn start(&self, started: &Value) -> Result<(), StoreError> {
        if self.store.anchor_last()?.is_none() {
            append_operational(
                self.store.as_ref(),
                self.clock.now(),
                KIND_GENESIS,
                &Value::Object(Default::default()),
            )?;
        }
        append_operational(
            self.store.as_ref(),
            self.clock.now(),
            KIND_SERVER_START,
            started,
        )
        .map(drop)
    }

    /// An operational row (`LOGIN_FAILED`, ...).
    pub fn operational(&self, kind: &str, body: &Value) -> Result<AnchorRow, StoreError> {
        append_operational(self.store.as_ref(), self.clock.now(), kind, body)
    }

    /// `RUNTIME_CLOSED` rows for the runtimes the registry evicted since the last call.
    pub fn record_closed(&self) -> Result<usize, StoreError> {
        let closed = self.registry.take_closed_heads();
        self.closed_rows(&closed)
    }

    fn closed_rows(&self, closed: &[(String, Head)]) -> Result<usize, StoreError> {
        let now = self.clock.now();
        for (user_id, head) in closed {
            let (entry, leaf) = anchor_head(user_id, head);
            append_raw(
                self.store.as_ref(),
                now,
                KIND_RUNTIME_CLOSED,
                &leaf_body_jcs(&leaf),
                &[entry],
            )?;
            self.anchored().insert(user_id.clone(), (head.clone(), now));
        }
        Ok(closed.len())
    }

    /// One `HEADS` row: the open users whose head changed since their last anchoring, and every
    /// user last anchored 24 h ago or longer. Nothing to anchor → no row (`None`).
    pub async fn tick(&self) -> Result<Option<AnchorRow>, StoreError> {
        self.record_closed()?;
        let now = self.clock.now();
        let mut due: Vec<(String, Head)> = Vec::new();
        let open = self.registry.open_runtimes().await;
        {
            let anchored = self.anchored();
            for rt in &open {
                let head = rt.head();
                let changed = anchored
                    .get(rt.user_id())
                    .is_none_or(|(h, at)| *h != head || now - at >= REANCHOR_SECS);
                if changed {
                    due.push((rt.user_id().to_owned(), head));
                }
            }
            for (user_id, (head, at)) in anchored.iter() {
                if now - at >= REANCHOR_SECS && !due.iter().any(|(u, _)| u == user_id) {
                    due.push((user_id.clone(), head.clone()));
                }
            }
        }
        if due.is_empty() {
            return Ok(None);
        }
        let (entries, leaves): (Vec<AnchorHead>, Vec<[u8; 32]>) =
            due.iter().map(|(u, h)| anchor_head(u, h)).unzip();
        let body = heads_body_jcs(&leaves).map_err(|_| StoreError::Db("duplicate leaf".into()))?;
        let row = append_raw(self.store.as_ref(), now, KIND_HEADS, &body, &entries)?;
        let mut anchored = self.anchored();
        for (u, h) in due {
            anchored.insert(u, (h, now));
        }
        Ok(Some(row))
    }

    /// Shutdown: closes every runtime (`APP_STOP` in each chain), anchors their final heads as
    /// `RUNTIME_CLOSED`, then `SERVER_STOP`.
    pub async fn shutdown(&self) -> Result<(), StoreError> {
        self.record_closed()?;
        let closed = self.registry.close_all().await;
        self.closed_rows(&closed)?;
        append_operational(
            self.store.as_ref(),
            self.clock.now(),
            KIND_SERVER_STOP,
            &Value::Object(Default::default()),
        )
        .map(drop)
    }

    /// The timer task: a tick every `interval`.
    pub fn spawn(self: &Arc<Self>, interval: std::time::Duration) -> tokio::task::JoinHandle<()> {
        let w = Arc::clone(self);
        tokio::spawn(async move {
            let mut t = tokio::time::interval(interval);
            t.tick().await;
            loop {
                t.tick().await;
                if w.tick().await.is_err() {
                    tracing::error!(event = "anchor_append_failed", kind = KIND_HEADS);
                }
            }
        })
    }
}

/// What a verification found intact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReport {
    pub rows: u64,
    pub last_seq: u64,
    pub last_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorError {
    /// `prev_hash` is not the previous row's hash.
    BrokenLink {
        seq: u64,
    },
    /// The stored hash is not the row's hash.
    BadHash {
        seq: u64,
    },
    /// A seq is missing (or the first row is not seq 1).
    Gap {
        seq: u64,
    },
    /// The body's leaves are not those of the row's `anchor_heads` entries.
    LeafMismatch {
        seq: u64,
    },
    Store(String),
}

/// Recomputes the chain and every leaf set (PD-217).
pub fn verify(store: &dyn ServerStore) -> Result<AnchorReport, AnchorError> {
    let rows = store
        .anchor_all()
        .map_err(|e| AnchorError::Store(e.to_string()))?;
    let mut prev = GENESIS_PREV;
    let mut expected = 1u64;
    for r in &rows {
        if r.seq != expected {
            return Err(AnchorError::Gap { seq: expected });
        }
        if r.prev_hash != prev {
            return Err(AnchorError::BrokenLink { seq: r.seq });
        }
        if row_hash(r.seq, &r.ts_utc, &r.kind, &r.body_jcs, &r.prev_hash) != r.hash {
            return Err(AnchorError::BadHash { seq: r.seq });
        }
        let heads = store
            .anchor_heads_for(r.seq)
            .map_err(|e| AnchorError::Store(e.to_string()))?;
        let leaves: Vec<[u8; 32]> = heads
            .iter()
            .map(|h| leaf_hash(&h.user_id, &h.chain_id, h.head_seq, &h.record_hash))
            .collect();
        let want = match r.kind.as_str() {
            KIND_HEADS => heads_body_jcs(&leaves).ok(),
            KIND_RUNTIME_CLOSED => match leaves.as_slice() {
                [one] => Some(leaf_body_jcs(one)),
                _ => None,
            },
            _ if heads.is_empty() => Some(r.body_jcs.clone()),
            _ => None,
        };
        if want.as_deref() != Some(r.body_jcs.as_slice()) {
            return Err(AnchorError::LeafMismatch { seq: r.seq });
        }
        prev = r.hash;
        expected += 1;
    }
    Ok(AnchorReport {
        rows: rows.len() as u64,
        last_seq: expected - 1,
        last_hash: prev,
    })
}

#[cfg(test)]
#[path = "tests/anchor.rs"]
mod tests;

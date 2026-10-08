//! Prune (§8.8, §8.5, §8.1, L36, L37): the prefix rule, the `prune_log` row chain, the L37
//! cadence, baseline and clamp, reference-checked crypto-shredding and legal hold. Runs on the
//! writer thread, between commands: automatic attempts are queued by the writer (after the
//! first corroboration of the process and after a commit whose `epoch` date moved on), a manual
//! run comes through [`crate::Store::prune`].

use std::collections::{BTreeMap, HashMap};

use chrono::{Days, NaiveDate};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde_json::{Value, json};

use crate::anchors::{Barrier, FirstRetainedAnchor};
use crate::clock::{UtcInstant, date_of, epoch_text, month_text, parse_epoch};
use crate::encoding::{self, ZERO_HASH};
use crate::error::AuditError;
use crate::types::{Confirmed, EventFlags, EventType};
use crate::writer::{PreparedEvent, Writer, int, lock, sql, ts_text};

/// `retention_days` default and minimum (§8.8, L09).
pub const RETENTION_DEFAULT: u32 = 100;
pub const RETENTION_MIN: u32 = 92;

/// A cutoff may advance at most this many epochs past its baseline without a confirmation (L37).
const MAX_ADVANCE_DAYS: u64 = 2;

/// One instance's audit-authoritative policy (C.3). T12 fills the view.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstancePolicy {
    pub origin: Option<String>,
    pub ca_fingerprint: Option<String>,
    pub proxy: Option<String>,
}

/// The audit-authoritative settings (C.3 `Settings`). Minimal until T12 builds the view from
/// `PRUNE` snapshots and `CONFIG_CHANGED`/`LEGAL_HOLD_CHANGED`; prune embeds [`Settings::to_json`]
/// in every `PRUNE` so verification judges each prune by the settings in force (L52).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub retention_days: u32,
    pub legal_hold: bool,
    pub anchor_dir: Option<String>,
    pub instances: BTreeMap<String, InstancePolicy>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            retention_days: RETENTION_DEFAULT,
            legal_hold: false,
            anchor_dir: None,
            instances: BTreeMap::new(),
        }
    }
}

impl Settings {
    /// `{anchor_dir, instances: {<id>: {ca_fingerprint, origin, proxy}}, legal_hold,
    /// retention_days}` (JCS sorts the keys).
    pub fn to_json(&self) -> Value {
        let instances: serde_json::Map<String, Value> = self
            .instances
            .iter()
            .map(|(id, p)| {
                (
                    id.clone(),
                    json!({
                        "ca_fingerprint": p.ca_fingerprint,
                        "origin": p.origin,
                        "proxy": p.proxy,
                    }),
                )
            })
            .collect();
        json!({
            "anchor_dir": self.anchor_dir,
            "instances": instances,
            "legal_hold": self.legal_hold,
            "retention_days": self.retention_days,
        })
    }
}

/// What one prune run did (C.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PruneOutcome {
    Pruned {
        prune_seq: u64,
        range_start: u64,
        first_retained_seq: u64,
        count: u64,
        cutoff: NaiveDate,
        baseline: NaiveDate,
        clamped: bool,
        destroyed_key_ids: Vec<u64>,
    },
    Skipped(PruneSkip),
}

/// Why a run wrote nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneSkip {
    /// No server `Date` corroborated the date in this process (§8.8).
    NotCorroborated,
    /// The head record's `epoch` is NULL (L36).
    HeadEpochNull,
    LegalHold,
    /// A `PRUNE` with the head's epoch exists (cadence, L37).
    AlreadyRanThisEpoch,
    /// `now` is before the head record's `ts_utc` (clock guard, §8.8).
    ClockBeforeHead,
    /// `now` is before the latest `PRUNE`'s `ts_utc` (clock guard, §8.8).
    ClockBeforeLastPrune,
    /// The cutoff is not later than the baseline.
    NothingToAdvance,
    /// The config file has not been reconciled in this process (§8.8 "before any prune").
    ConfigNotReconciled,
    /// The local date is behind the corroborated date (`clock_behind`): the epochs written now
    /// are not trusted to move the cutoff (plan decision, T06 review).
    ClockBehind,
}

/// One retained record as the prefix rule sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneRow {
    pub seq: u64,
    pub epoch: Option<NaiveDate>,
    pub ts: UtcInstant,
    pub flags: EventFlags,
    pub record_hash: [u8; 32],
}

/// L36: a NULL epoch takes the epoch of the first later record whose epoch is non-NULL; with
/// none, it has no effective epoch.
pub fn effective_epochs(epochs: &[Option<NaiveDate>]) -> Vec<Option<NaiveDate>> {
    let mut out = vec![None; epochs.len()];
    let mut next = None;
    for i in (0..epochs.len()).rev() {
        if epochs[i].is_some() {
            next = epochs[i];
        }
        out[i] = next;
    }
    out
}

/// The effective epochs prune uses. A NULL epoch resolves only through a later epoch that is
/// not flagged `clock_behind`: the first corroboration of a store whose local clock was behind
/// stamps a past local date, and the records written before it (GENESIS) must not inherit that
/// date (T06 review). A later, unflagged epoch holds them longer, never shorter. A flagged
/// record keeps its own epoch (held at `prev_epoch`, never ahead of the corroborated date).
pub fn guarded_effective_epochs(rows: &[PruneRow]) -> Vec<Option<NaiveDate>> {
    let trusted: Vec<Option<NaiveDate>> = rows
        .iter()
        .map(|r| r.epoch.filter(|_| !r.flags.contains(EventFlags::BEHIND)))
        .collect();
    effective_epochs(&trusted)
        .into_iter()
        .zip(rows)
        .map(|(fill, r)| r.epoch.or(fill))
        .collect()
}

/// §8.8: the longest prefix of records whose effective epoch is older than `cutoff` and which
/// carry `clock_forward` or have a `date(ts_utc)` older than `cutoff`, their own or that of
/// any later record; the `ts_utc` of a `clock_behind` record never counts.
pub fn prunable_prefix_len(
    rows: &[PruneRow],
    eff: &[Option<NaiveDate>],
    cutoff: NaiveDate,
) -> usize {
    // suffix_min[i] = min date(ts_utc) over rows j >= i that do not carry clock_behind
    let mut suffix_min: Vec<Option<NaiveDate>> = vec![None; rows.len() + 1];
    for i in (0..rows.len()).rev() {
        let own = (!rows[i].flags.contains(EventFlags::BEHIND)).then(|| date_of(rows[i].ts));
        suffix_min[i] = match (own, suffix_min[i + 1]) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
    let mut n = 0;
    for i in 0..rows.len() {
        let Some(e) = eff.get(i).copied().flatten() else {
            break; // no effective epoch: never prunable (L36)
        };
        if e >= cutoff {
            break;
        }
        let ts_ok = rows[i].flags.contains(EventFlags::FORWARD)
            || matches!(suffix_min[i], Some(d) if d < cutoff);
        if !ts_ok {
            break;
        }
        n += 1;
    }
    n
}

fn bad(what: String) -> AuditError {
    AuditError::AppendFailed(what)
}

fn u64_col(v: i64, what: &str) -> Result<u64, AuditError> {
    u64::try_from(v).map_err(|_| bad(format!("negative {what}")))
}

fn hash32(v: Vec<u8>, what: &str) -> Result<[u8; 32], AuditError> {
    v.try_into()
        .map_err(|_| bad(format!("{what} is not 32 bytes")))
}

/// Every retained record, ascending.
fn load_prune_rows(conn: &Connection) -> Result<Vec<PruneRow>, AuditError> {
    type Raw = (i64, Option<String>, String, i64, Vec<u8>);
    let mut st = conn
        .prepare("SELECT seq, epoch, ts_utc, flags, record_hash FROM events ORDER BY seq")
        .map_err(sql)?;
    let raw = st
        .query_map([], |r| -> rusqlite::Result<Raw> {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .map_err(sql)?;
    let mut out = Vec::new();
    for r in raw {
        let (seq, epoch, ts, flags, hash) = r.map_err(sql)?;
        let seq = u64_col(seq, "seq")?;
        let unreadable = |c: &str| bad(format!("record {seq} has an unreadable {c}"));
        out.push(PruneRow {
            seq,
            epoch: epoch
                .map(|e| parse_epoch(&e).ok_or_else(|| unreadable("epoch")))
                .transpose()?,
            ts: UtcInstant::parse_rfc3339_ms(&ts).ok_or_else(|| unreadable("ts_utc"))?,
            flags: EventFlags::from_bits(u64::try_from(flags).map_err(|_| unreadable("flags"))?),
            record_hash: hash.try_into().map_err(|_| unreadable("record_hash"))?,
        });
    }
    Ok(out)
}

/// The latest `prune_log` row: the baseline and what the next row chains to.
struct LatestRow {
    cutoff: NaiveDate,
    last_pruned: [u8; 32],
    first_retained_seq: u64,
    row_hash: [u8; 32],
}

fn latest_prune_row(conn: &Connection) -> Result<Option<LatestRow>, AuditError> {
    let r: Option<(String, Vec<u8>, i64, Vec<u8>)> = conn
        .query_row(
            "SELECT cutoff_epoch, last_pruned_record_hash, first_retained_seq, row_hash \
             FROM prune_log ORDER BY prune_seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(sql)?;
    r.map(|(cutoff, last, frs, row_hash)| {
        Ok(LatestRow {
            cutoff: parse_epoch(&cutoff)
                .ok_or_else(|| bad("the latest prune_log cutoff is unreadable".into()))?,
            last_pruned: hash32(last, "last_pruned_record_hash")?,
            first_retained_seq: u64_col(frs, "first_retained_seq")?,
            row_hash: hash32(row_hash, "row_hash")?,
        })
    })
    .transpose()
}

fn prune_exists_with_epoch(conn: &Connection, epoch: NaiveDate) -> Result<bool, AuditError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM events WHERE event_type = 'PRUNE' AND epoch = ?1)",
        [epoch_text(epoch)],
        |r| r.get(0),
    )
    .map_err(sql)
}

fn latest_prune_ts(conn: &Connection) -> Result<Option<UtcInstant>, AuditError> {
    let ts: Option<String> = conn
        .query_row(
            "SELECT ts_utc FROM events WHERE event_type = 'PRUNE' ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    ts.map(|t| {
        UtcInstant::parse_rfc3339_ms(&t)
            .ok_or_else(|| bad("the latest PRUNE has an unreadable ts_utc".into()))
    })
    .transpose()
}

/// The key `dek_for` would select for a record of `epoch` (selection only, never creates).
fn current_key(conn: &Connection, epoch: NaiveDate) -> Result<Option<u64>, AuditError> {
    let id: Option<i64> = conn
        .query_row(
            "SELECT key_id FROM keys WHERE month = ?1 AND wrapped_dek IS NOT NULL \
             ORDER BY key_id DESC LIMIT 1",
            [month_text(epoch)],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    id.map(|i| u64_col(i, "key_id")).transpose()
}

/// Live keys no retained record references (`events.key_id` is NOT NULL), minus `keep`.
fn unreferenced_keys(conn: &Connection, keep: &[u64]) -> Result<Vec<u64>, AuditError> {
    let mut st = conn
        .prepare(
            "SELECT key_id FROM keys WHERE wrapped_dek IS NOT NULL \
             AND key_id NOT IN (SELECT key_id FROM events) ORDER BY key_id",
        )
        .map_err(sql)?;
    let ids = st.query_map([], |r| r.get::<_, i64>(0)).map_err(sql)?;
    let mut out = Vec::new();
    for id in ids {
        let id = u64_col(id.map_err(sql)?, "key_id")?;
        if !keep.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

/// §8.1: after each prune, every free page back to the file system, then the WAL truncated.
/// `incremental_vacuum` frees one page per step, so it is stepped to the end.
fn vacuum_and_checkpoint(conn: &Connection) -> rusqlite::Result<()> {
    {
        let mut st = conn.prepare("PRAGMA incremental_vacuum")?;
        let mut rows = st.query([])?;
        while rows.next()?.is_some() {}
    }
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
}

impl Writer {
    /// One prune run (§8.8): the guards in order, then one transaction deleting the prefix,
    /// destroying unreferenced DEKs, writing the `prune_log` row and its `PRUNE`. After the
    /// commit the prune barrier is set before the new head is published (the anchor thread
    /// writes the first-retained anchor before the head passes the `PRUNE`), then vacuum and
    /// checkpoint.
    pub(crate) fn prune_run(
        &mut self,
        confirm: Option<&Confirmed>,
    ) -> Result<PruneOutcome, AuditError> {
        use PruneOutcome::Skipped;
        if !self.st.config_reconciled {
            return Ok(Skipped(PruneSkip::ConfigNotReconciled));
        }
        let now = self.st.clock.now_utc();
        let mono = self.st.clock.suspend_aware_elapsed();
        let Some(cd) = self.st.clock_state.corroborated_date(mono) else {
            return Ok(Skipped(PruneSkip::NotCorroborated));
        };
        let Some(head_epoch) = self.st.clock_state.prev_epoch else {
            return Ok(Skipped(PruneSkip::HeadEpochNull));
        };
        let s = self.st.settings.clone();
        if s.legal_hold {
            return Ok(Skipped(PruneSkip::LegalHold));
        }
        if s.retention_days < RETENTION_MIN {
            return Err(AuditError::Invalid("retention below the 92-day minimum"));
        }
        if confirm.is_none() && prune_exists_with_epoch(&self.conn, head_epoch)? {
            return Ok(Skipped(PruneSkip::AlreadyRanThisEpoch));
        }
        // What the PRUNE row would be stamped with now (the state is not changed).
        let peek = self.st.clock_state.clone().stamp(now, mono);
        if peek.clock_flags.contains(EventFlags::BEHIND)
            || self.st.clock_state.prev_flags.contains(EventFlags::BEHIND)
        {
            return Ok(Skipped(PruneSkip::ClockBehind));
        }
        let head_ts = self
            .st
            .clock_state
            .prev_ts
            .ok_or_else(|| bad("the head record has no ts_utc".into()))?;
        // The guard's own anomaly row (stamped `now`) must not disarm it.
        let floor = self.st.clock_floor.map_or(head_ts, |f| f.max(head_ts));
        if now < floor {
            self.st.clock_floor = Some(floor);
            self.log_prune_skip_once("now_before_head", now, mono)?;
            return Ok(Skipped(PruneSkip::ClockBeforeHead));
        }
        if let Some(t) = latest_prune_ts(&self.conn)?
            && now < t
        {
            self.log_prune_skip_once("now_before_last_prune", now, mono)?;
            return Ok(Skipped(PruneSkip::ClockBeforeLastPrune));
        }
        let retention = Days::new(u64::from(s.retention_days));
        let Some(raw_cutoff) = date_of(now)
            .min(cd)
            .min(head_epoch)
            .checked_sub_days(retention)
        else {
            return Ok(Skipped(PruneSkip::NothingToAdvance));
        };
        let rows = load_prune_rows(&self.conn)?;
        let eff = guarded_effective_epochs(&rows);
        let latest = latest_prune_row(&self.conn)?;
        let range_start = latest.as_ref().map_or(1, |r| r.first_retained_seq);
        if rows
            .iter()
            .enumerate()
            .any(|(i, r)| Some(r.seq) != range_start.checked_add(i as u64))
        {
            return Err(bad(
                "retained records are not contiguous from the prune log's first_retained_seq"
                    .into(),
            ));
        }
        let baseline = match &latest {
            Some(r) => r.cutoff,
            // The store's first prune: GENESIS's effective epoch (L37).
            None => match (rows.first(), eff.first()) {
                (Some(g), Some(Some(e))) if g.seq == 1 => *e,
                (Some(g), Some(None)) if g.seq == 1 => {
                    return Ok(Skipped(PruneSkip::NothingToAdvance));
                }
                _ => return Err(bad("no prune_log row, yet GENESIS is not retained".into())),
            },
        };
        let cap = baseline
            .checked_add_days(Days::new(MAX_ADVANCE_DAYS))
            .ok_or_else(|| bad("baseline out of range".into()))?;
        let (cutoff, clamped) = if confirm.is_some() || raw_cutoff <= cap {
            (raw_cutoff, false)
        } else {
            (cap, true)
        };
        let backlog = u32::try_from((raw_cutoff - cutoff).num_days().max(0)).unwrap_or(u32::MAX);
        self.st
            .shared
            .prune_backlog_days
            .store(backlog, std::sync::atomic::Ordering::Relaxed);
        if cutoff <= baseline {
            return Ok(Skipped(PruneSkip::NothingToAdvance));
        }
        let n = prunable_prefix_len(&rows, &eff, cutoff);
        let first_retained_seq = range_start + n as u64;
        let last_pruned = match n {
            0 => latest.as_ref().map_or(ZERO_HASH, |r| r.last_pruned),
            n => rows[n - 1].record_hash,
        };
        drop(rows);
        let prev_row_hash = latest.as_ref().map_or(ZERO_HASH, |r| r.row_hash);
        let genesis_hash = self
            .st
            .genesis_hash
            .ok_or_else(|| bad("GENESIS's record_hash is unknown to this process".into()))?;
        let prune_seq = self
            .st
            .head
            .seq
            .checked_add(1)
            .ok_or_else(|| bad("seq exhausted".into()))?;
        let cutoff_text = epoch_text(cutoff);
        let row_hash = encoding::prune_row_hash(
            &prev_row_hash,
            prune_seq,
            range_start,
            &cutoff_text,
            &last_pruned,
            first_retained_seq,
        );
        let destroyed_at = ts_text(now)?;
        let current_epochs = [Some(head_epoch), peek.epoch];
        // The barrier slot is taken before the transaction, so the barrier can always be set
        // after the commit; any error before the commit releases it (guard dropped).
        let guard = self.st.shared.anchors.reserve_prune_barrier()?;
        let snapshot = (self.st.clock_state.clone(), self.st.head.clone());
        let mut new_keys = HashMap::new();
        let st = &mut self.st;
        let result = (|| -> Result<(crate::types::Committed, Vec<u64>), AuditError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql)?;
            tx.execute(
                "DELETE FROM events WHERE seq < ?1",
                [int(first_retained_seq)?],
            )
            .map_err(sql)?;
            // Never the DEK used for new records: the head's month and the PRUNE's own.
            let mut keep = Vec::new();
            for e in current_epochs.into_iter().flatten() {
                if let Some(k) = current_key(&tx, e)? {
                    keep.push(k);
                }
            }
            let destroy = unreferenced_keys(&tx, &keep)?;
            for k in &destroy {
                tx.execute(
                    "UPDATE keys SET wrapped_dek = NULL, destroyed_at = ?2 \
                     WHERE key_id = ?1 AND wrapped_dek IS NOT NULL",
                    rusqlite::params![int(*k)?, destroyed_at],
                )
                .map_err(sql)?;
            }
            tx.execute(
                "INSERT INTO prune_log (prune_seq, range_start, cutoff_epoch, \
                 last_pruned_record_hash, first_retained_seq, prev_row_hash, row_hash) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    int(prune_seq)?,
                    int(range_start)?,
                    cutoff_text,
                    &last_pruned[..],
                    int(first_retained_seq)?,
                    &prev_row_hash[..],
                    &row_hash[..],
                ],
            )
            .map_err(sql)?;
            let payload = json!({
                "range": [range_start, first_retained_seq],
                "count": n,
                "cutoff": cutoff_text,
                "clamped": clamped,
                "baseline": epoch_text(baseline),
                "destroyed_key_ids": destroy,
                "prune_log_row_hash": hex::encode(row_hash),
                "settings": s.to_json(),
            });
            let ev = PreparedEvent::system(EventType::PRUNE, &payload)?;
            let c = st.append_in_tx(&tx, &ev, &mut new_keys)?;
            if c.seq != prune_seq {
                return Err(bad("PRUNE did not get the expected seq".into()));
            }
            let used: i64 = tx
                .query_row(
                    "SELECT key_id FROM events WHERE seq = ?1",
                    [int(c.seq)?],
                    |r| r.get(0),
                )
                .map_err(sql)?;
            if destroy.contains(&u64_col(used, "key_id")?) {
                return Err(bad("the PRUNE record would use a destroyed key".into()));
            }
            #[cfg(any(test, feature = "testing"))]
            st.hooks
                .fault(crate::testing::FaultPoint::AfterPruneTxBeforeCommit)?;
            tx.commit().map_err(sql)?;
            Ok((c, destroy))
        })();
        let (committed, destroyed_key_ids) = match result {
            Ok(v) => v,
            Err(e) => {
                (self.st.clock_state, self.st.head) = snapshot;
                return Err(e);
            }
        };
        // Committed: nothing below may roll the in-memory state back.
        {
            let mut cache = lock(&self.st.shared.dek_cache);
            for k in &destroyed_key_ids {
                cache.remove(k);
            }
        }
        #[cfg(any(test, feature = "testing"))]
        if let Err(e) = self
            .st
            .hooks
            .fault(crate::testing::FaultPoint::AfterPruneCommit)
        {
            // Simulated crash: the writer stops before the barrier and before publishing.
            self.st.crashed = true;
            return Err(e);
        }
        let armed = guard.arm(Barrier::Prune {
            seq: committed.seq,
            record_hash: committed.record_hash,
            first_retained: FirstRetainedAnchor {
                chain_id: self.st.head.chain_id.clone(),
                genesis_hash,
                first_retained_seq,
                first_retained_prev_hash: last_pruned,
            },
        });
        if armed.is_err() {
            // Unreachable while the slot is held; fail closed: no head anchor past the PRUNE
            // in this process (startup reconciles the first-retained anchor).
            self.st.shared.anchors.disable();
        }
        // The PRUNE is durable: the barrier stays until the anchor thread lifts it, and the
        // guard must not release a barrier it did not set.
        guard.complete();
        self.st.post_commit(new_keys, &[]);
        // Failures leave free pages or a WAL behind, nothing else; the next prune retries.
        let _ = vacuum_and_checkpoint(&self.conn);
        armed?;
        Ok(PruneOutcome::Pruned {
            prune_seq: committed.seq,
            range_start,
            first_retained_seq,
            count: n as u64,
            cutoff,
            baseline,
            clamped,
            destroyed_key_ids,
        })
    }

    /// `CLOCK_ANOMALY {kind: "prune_skipped", local, server, reason}` at most once per reason
    /// per process (plan decision); not marked logged if the append fails.
    fn log_prune_skip_once(
        &mut self,
        reason: &'static str,
        now: UtcInstant,
        mono: std::time::Duration,
    ) -> Result<(), AuditError> {
        if self.st.skips_logged.contains(reason) {
            return Ok(());
        }
        let server = self
            .st
            .clock_state
            .corroborated_at(mono)
            .map(ts_text)
            .transpose()?;
        let row = PreparedEvent::system(
            EventType::CLOCK_ANOMALY,
            &json!({
                "kind": "prune_skipped",
                "local": ts_text(now)?,
                "server": server,
                "reason": reason,
            }),
        )?;
        self.append_tx(vec![row])?;
        self.st.skips_logged.insert(reason);
        Ok(())
    }
}

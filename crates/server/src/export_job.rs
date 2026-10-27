//! Server-side audit export jobs (M14 PD-253..PD-256; SM-6.3, SM-6.4).
//!
//! A job, per PD-254: (1) the concurrency check (at most [`ExportConfig::max_concurrent`] jobs
//! server-wide, one running job per requester and target; 409 `audit/export_busy`); for an
//! auditor the `AUDITOR_READ {action: export}` is recorded by the route before the job starts;
//! (2) `AnchorWriter::anchor_user_now` appends a `HEADS` row `s1` naming the target's head `h`;
//! (3) `Store::export_through(through_seq(from, h))` into `<data>/exports/<job_id>/` (a
//! [`RustChosenPath::from_server_export_dir`], never a path from a request; the store appends its
//! `EXPORT` record to the target's chain, as on desktop); (4) the anchor-chain excerpt
//! `[s0, s1]` and its manifest beside the export's files, and `README.txt` with every file's
//! SHA-256, the pin `s1` and the exact `verify-export` command; (5) the tar stream on download
//! (`tar.rs`), after which the directory is removed.
//!
//! `s0` (PD-253, the tightest reading): the latest anchoring of the target's chain at or before
//! the export's `first_seq`, else the chain's first anchoring; at most [`MAX_EXCERPT_ROWS`] rows
//! (beyond that `s0` moves forward, and the verifier binds only what the span covers).
//!
//! Directories are `0700`, files `0600` (Unix); the job id is 128 random bits, bound to its
//! requester. Jobs expire after the configured TTL; the TTL sweep (start-up and hourly) removes
//! expired jobs, directories of jobs a previous process left running, and orphan directories.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use atlas_duck_audit::server_anchor::{
    EXCERPT_FILE, EXCERPT_FORMAT, EXCERPT_MANIFEST_FILE, ExcerptLimits, ExcerptManifest, LeafEntry,
    body_leaves, excerpt_line_jcs, leaf_hash,
};
use atlas_duck_audit::types::RustChosenPath;
use atlas_duck_audit::{ExportControl, ExportReceipt, TimeRange, UtcInstant};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::anchor::{AnchorRef, AnchorWriter};
use crate::clock::Clock;
use crate::errors::ApiError;
use crate::runtime::{Registry, RuntimeError};
use crate::store::{AnchorHead, ExportJobRecord, ServerStore};

/// PD-253: an excerpt holds at most this many rows.
pub const MAX_EXCERPT_ROWS: u64 = 100_000;
/// Anchor rows read per store call while an excerpt is written.
const EXCERPT_BATCH: u64 = 1000;
/// The export's own files and the two excerpt files, in archive order, then `README.txt`.
pub const ARCHIVE_FILES: [&str; 6] = [
    "manifest.json",
    "events.jsonl",
    "prune_log.jsonl",
    EXCERPT_FILE,
    EXCERPT_MANIFEST_FILE,
    README_FILE,
];
pub const README_FILE: &str = "README.txt";

pub const STATE_RUNNING: &str = "running";
pub const STATE_DONE: &str = "done";
pub const STATE_FAILED: &str = "failed";
pub const STATE_DOWNLOADED: &str = "downloaded";

/// `ATLAS_DUCK_EXPORT_TTL_HOURS`, `ATLAS_DUCK_EXPORT_MAX_CONCURRENT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportConfig {
    pub ttl_secs: i64,
    pub max_concurrent: usize,
}

impl ExportConfig {
    pub const DEFAULT: ExportConfig = ExportConfig {
        ttl_secs: 24 * 3600,
        max_concurrent: 2,
    };
}

/// A job slot taken by [`ExportJobs::reserve`]; released on drop unless launched.
pub struct Reservation {
    jobs: Arc<ExportJobs>,
    pub job_id: String,
    requester: String,
    target: String,
    launched: bool,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.launched {
            self.jobs.running().remove(&self.job_id);
        }
    }
}

struct Running {
    requester: String,
    target: String,
    cancel: Arc<AtomicBool>,
    done: Arc<AtomicU64>,
    total: Arc<AtomicU64>,
}

/// The export jobs of this process.
pub struct ExportJobs {
    store: Arc<dyn ServerStore>,
    registry: Arc<Registry>,
    anchor: Arc<AnchorWriter>,
    clock: Arc<dyn Clock>,
    /// `<data>/exports`.
    root: PathBuf,
    issuer: String,
    cfg: ExportConfig,
    running: Mutex<HashMap<String, Running>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    downloading: Mutex<HashSet<String>>,
}

/// What the job routes answer about a job.
pub fn job_json(j: &ExportJobRecord, progress: Option<(u64, u64)>) -> Value {
    let mut v = json!({
        "job_id": j.job_id,
        "target_user_id": j.target_user_id,
        "state": j.state,
        "created_at": crate::clock::rfc3339(j.created_at),
        "expires_at": crate::clock::rfc3339(j.expires_at),
    });
    if let Some((done, total)) = progress {
        v["progress"] = json!({"done": done, "total": total});
    }
    if j.state == STATE_DONE {
        v["manifest_sha256"] = json!(j.manifest_sha256);
        v["size"] = json!(j.size);
        v["file_name"] = json!(j.file_name);
        if let (Some(seq), Some(hash), Some(dir), Some(m)) = (
            j.anchor_seq,
            &j.anchor_hash,
            &j.file_name,
            &j.manifest_sha256,
        ) {
            v["anchor_head"] = json!({"seq": seq, "hash": hash});
            v["verify_command"] = json!(verify_command(dir, m, seq, hash));
        }
    }
    v
}

/// PD-253: the exact command line of the README and the job page.
pub fn verify_command(dir: &str, manifest_sha256: &str, seq: u64, hash: &str) -> String {
    format!(
        "atlas-duck verify-export {dir} --manifest-sha256 {manifest_sha256} --anchor-chain \
         {dir}/{EXCERPT_FILE} --anchor-chain-head {seq}:{hash}"
    )
}

fn random_id() -> Result<String, ApiError> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| ApiError::INTERNAL)?;
    Ok(hex::encode(b))
}

/// A job id as [`random_id`] makes them (it becomes a directory name).
pub fn valid_job_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// PD-255 (L249): the one place a server builds a [`RustChosenPath`]: the job's directory under
/// the data volume, from a random job id. `ci/check-dialog-proofs.mjs` allows this function only.
fn export_dir_path(root: &Path, job_id: &str) -> RustChosenPath {
    RustChosenPath::from_server_export_dir(root.join(job_id))
}

fn create_private_dir(p: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(p)
    }
    #[cfg(not(unix))]
    {
        std::fs::DirBuilder::new().create(p)
    }
}

fn create_private_file(p: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(p)
}

fn sha256_file(p: &Path) -> std::io::Result<[u8; 32]> {
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(h.finalize().into());
        }
        h.update(&buf[..n]);
    }
}

/// A finished job's results.
struct Produced {
    receipt: ExportReceipt,
    anchor: AnchorRef,
    size: u64,
}

#[derive(Debug)]
enum JobError {
    Cancelled,
    Failed(&'static str),
}

impl ExportJobs {
    pub fn new(
        store: Arc<dyn ServerStore>,
        registry: Arc<Registry>,
        anchor: Arc<AnchorWriter>,
        clock: Arc<dyn Clock>,
        data_dir: &Path,
        issuer: &str,
        cfg: ExportConfig,
    ) -> ExportJobs {
        ExportJobs {
            store,
            registry,
            anchor,
            clock,
            root: data_dir.join("exports"),
            issuer: issuer.to_owned(),
            cfg,
            running: Mutex::new(HashMap::new()),
            tasks: Mutex::new(Vec::new()),
            downloading: Mutex::new(HashSet::new()),
        }
    }

    fn running(&self) -> std::sync::MutexGuard<'_, HashMap<String, Running>> {
        self.running.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn downloads(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.downloading.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The job's directory.
    pub fn job_dir(&self, job_id: &str) -> PathBuf {
        self.root.join(job_id)
    }

    /// (1) The concurrency check: a slot with a fresh job id, or 409 `audit/export_busy`.
    pub fn reserve(
        self: &Arc<Self>,
        requester: &str,
        target: &str,
    ) -> Result<Reservation, ApiError> {
        let job_id = random_id()?;
        let mut running = self.running();
        if running.len() >= self.cfg.max_concurrent
            || running
                .values()
                .any(|r| r.requester == requester && r.target == target)
        {
            return Err(ApiError::EXPORT_BUSY);
        }
        running.insert(
            job_id.clone(),
            Running {
                requester: requester.to_owned(),
                target: target.to_owned(),
                cancel: Arc::new(AtomicBool::new(false)),
                done: Arc::new(AtomicU64::new(0)),
                total: Arc::new(AtomicU64::new(0)),
            },
        );
        Ok(Reservation {
            jobs: self.clone(),
            job_id,
            requester: requester.to_owned(),
            target: target.to_owned(),
            launched: false,
        })
    }

    /// Starts the reserved job; answers its first state.
    pub fn launch(
        self: &Arc<Self>,
        mut r: Reservation,
        from_utc: UtcInstant,
    ) -> Result<ExportJobRecord, ApiError> {
        let now = self.clock.now();
        let job = ExportJobRecord {
            job_id: r.job_id.clone(),
            requester_user_id: r.requester.clone(),
            target_user_id: r.target.clone(),
            state: STATE_RUNNING.into(),
            created_at: now,
            expires_at: now.saturating_add(self.cfg.ttl_secs),
            manifest_sha256: None,
            size: None,
            file_name: None,
            anchor_seq: None,
            anchor_hash: None,
        };
        self.store
            .export_job_insert(&job)
            .map_err(|_| ApiError::STORE_UNAVAILABLE)?;
        r.launched = true;
        let (cancel, done, total) = {
            let running = self.running();
            let Some(slot) = running.get(&r.job_id) else {
                return Err(ApiError::INTERNAL);
            };
            (slot.cancel.clone(), slot.done.clone(), slot.total.clone())
        };
        let me = self.clone();
        let first = job.clone();
        let handle = tokio::spawn(async move {
            let res = me.produce(&first, from_utc, cancel, done, total).await;
            me.finish(first, res);
        });
        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        tasks.retain(|t| !t.is_finished());
        tasks.push(handle);
        Ok(job)
    }

    fn finish(&self, mut job: ExportJobRecord, res: Result<Produced, JobError>) {
        match res {
            Ok(p) => {
                job.state = STATE_DONE.into();
                job.manifest_sha256 = Some(hex::encode(p.receipt.manifest_sha256));
                job.size = Some(p.size);
                job.file_name = Some(p.receipt.dir_name.clone());
                job.anchor_seq = Some(p.anchor.seq);
                job.anchor_hash = Some(hex::encode(p.anchor.hash));
                tracing::info!(event = "export_done", job_id = %job.job_id, rows = p.receipt.rows);
            }
            Err(e) => {
                job.state = STATE_FAILED.into();
                let _ = std::fs::remove_dir_all(self.job_dir(&job.job_id));
                let reason = match e {
                    JobError::Cancelled => "cancelled",
                    JobError::Failed(why) => why,
                };
                tracing::warn!(event = "export_failed", job_id = %job.job_id, reason);
            }
        }
        if self.store.export_job_update(&job).is_err() {
            tracing::error!(event = "export_job_update_failed", job_id = %job.job_id);
        }
        self.running().remove(&job.job_id);
    }

    /// Steps (2)..(4) of PD-254.
    async fn produce(
        &self,
        job: &ExportJobRecord,
        from_utc: UtcInstant,
        cancel: Arc<AtomicBool>,
        done: Arc<AtomicU64>,
        total: Arc<AtomicU64>,
    ) -> Result<Produced, JobError> {
        let target = job.target_user_id.clone();
        let _pin = self.registry.pin_view(&target);
        let audit = match self.registry.audit_view(&target).await {
            Ok(s) => s,
            Err(RuntimeError::UnknownUser) => return Err(JobError::Failed("user_unknown")),
            Err(_) => return Err(JobError::Failed("store_unavailable")),
        };
        let (seq, hash, chain) = audit.head();
        if seq == 0 {
            return Err(JobError::Failed("no_records"));
        }
        let anchored = self
            .anchor
            .anchor_user_now(&target, &(chain, seq, hash))
            .map_err(|_| JobError::Failed("anchor_append_failed"))?;
        tracing::info!(event = "anchor_head", seq = anchored.seq, hash = %hex::encode(anchored.hash));
        std::fs::create_dir_all(&self.root).map_err(|_| JobError::Failed("export_dir"))?;
        let dir = self.job_dir(&job.job_id);
        create_private_dir(&dir).map_err(|_| JobError::Failed("export_dir"))?;
        let out = export_dir_path(&self.root, &job.job_id);
        let c = cancel.clone();
        let receipt = tokio::task::spawn_blocking(move || {
            let progress = move |d: u64, t: u64| {
                done.store(d, Ordering::SeqCst);
                total.store(t, Ordering::SeqCst);
            };
            audit.export_through(
                TimeRange::through_seq(from_utc, seq),
                out,
                &ExportControl {
                    progress: &progress,
                    cancel: &c,
                },
            )
        })
        .await
        .map_err(|_| JobError::Failed("export_panicked"))?
        .map_err(|e| match e {
            atlas_duck_audit::error::AuditError::Cancelled => JobError::Cancelled,
            atlas_duck_audit::error::AuditError::Invalid(_) => JobError::Failed("no_records"),
            _ => JobError::Failed("export_failed"),
        })?;
        if cancel.load(Ordering::SeqCst) {
            return Err(JobError::Cancelled);
        }
        let export_dir = dir.join(&receipt.dir_name);
        let (store, issuer, user) = (self.store.clone(), self.issuer.clone(), target.clone());
        let (r, a) = (receipt.clone(), anchored);
        let size = tokio::task::spawn_blocking(move || {
            write_excerpt(store.as_ref(), &user, &r, a, &issuer, &export_dir)?;
            write_readme(&r, a, &issuer, &export_dir)?;
            archive_size(&r.dir_name, &export_dir)
        })
        .await
        .map_err(|_| JobError::Failed("excerpt_panicked"))?
        .map_err(|_| JobError::Failed("excerpt_failed"))?;
        Ok(Produced {
            receipt,
            anchor: anchored,
            size,
        })
    }

    /// A job of `requester` (another requester's is unknown): the record and, while it runs,
    /// its progress.
    pub fn get(
        &self,
        requester: &str,
        job_id: &str,
    ) -> Result<(ExportJobRecord, Option<(u64, u64)>), ApiError> {
        if !valid_job_id(job_id) {
            return Err(ApiError::EXPORT_UNKNOWN);
        }
        let job = self
            .store
            .export_job_get(job_id)
            .map_err(|_| ApiError::STORE_UNAVAILABLE)?
            .filter(|j| j.requester_user_id == requester)
            .ok_or(ApiError::EXPORT_UNKNOWN)?;
        let progress = self.running().get(job_id).map(|r| {
            (
                r.done.load(Ordering::SeqCst),
                r.total.load(Ordering::SeqCst),
            )
        });
        Ok((job, progress))
    }

    /// The members of a finished job's archive, checked before a download starts.
    pub fn archive(&self, job: &ExportJobRecord) -> Result<Vec<crate::tar::Entry>, ApiError> {
        if job.state == STATE_RUNNING {
            return Err(ApiError::EXPORT_BUSY);
        }
        if job.state == STATE_FAILED {
            return Err(ApiError::EXPORT_FAILED);
        }
        if job.state != STATE_DONE || job.expires_at <= self.clock.now() {
            return Err(ApiError::EXPORT_EXPIRED);
        }
        let Some(dir_name) = &job.file_name else {
            return Err(ApiError::EXPORT_FAILED);
        };
        let dir = self.job_dir(&job.job_id).join(dir_name);
        let mut entries = Vec::new();
        for f in ARCHIVE_FILES {
            let path = dir.join(f);
            let size = std::fs::metadata(&path)
                .map_err(|_| ApiError::EXPORT_EXPIRED)?
                .len();
            entries.push(crate::tar::Entry {
                name: format!("{dir_name}/{f}"),
                path,
                size,
            });
        }
        crate::tar::check(&entries).map_err(|_| ApiError::EXPORT_FAILED)?;
        Ok(entries)
    }

    /// Marks a download of `job_id` as running; `false` when one already is.
    pub fn begin_download(&self, job_id: &str) -> bool {
        self.downloads().insert(job_id.to_owned())
    }

    /// The end of a download: on a completed stream the job is `downloaded` and its directory
    /// removed; a cut one leaves the job downloadable until it expires.
    pub fn end_download(&self, job_id: &str, completed: bool) {
        self.downloads().remove(job_id);
        if !completed {
            return;
        }
        let _ = std::fs::remove_dir_all(self.job_dir(job_id));
        if let Ok(Some(mut j)) = self.store.export_job_get(job_id) {
            j.state = STATE_DOWNLOADED.into();
            let _ = self.store.export_job_update(&j);
        }
    }

    /// The TTL sweep (start-up and hourly; M13's scheduler takes it over at merge): expired jobs
    /// go with their directories; at start-up (`startup`) jobs a previous process left running
    /// are failed and their directories removed; directories no job names are removed. Answers
    /// how many directories went.
    pub fn sweep(&self, startup: bool) -> usize {
        let now = self.clock.now();
        let mut removed = 0;
        if startup && let Ok(left) = self.store.export_jobs_running() {
            for mut j in left {
                j.state = STATE_FAILED.into();
                let _ = self.store.export_job_update(&j);
            }
        }
        if let Ok(expired) = self.store.export_jobs_expired(now) {
            for j in expired {
                if self.running().contains_key(&j.job_id) || self.downloads().contains(&j.job_id) {
                    continue;
                }
                let _ = self.store.export_job_delete(&j.job_id);
            }
        }
        let Ok(dir) = std::fs::read_dir(&self.root) else {
            return 0;
        };
        for e in dir.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if self.running().contains_key(&name) || self.downloads().contains(&name) {
                continue;
            }
            let keep = valid_job_id(&name)
                && matches!(self.store.export_job_get(&name), Ok(Some(j)) if j.state == STATE_DONE && j.expires_at > now);
            if !keep && std::fs::remove_dir_all(e.path()).is_ok() {
                removed += 1;
            }
        }
        removed
    }

    /// Shutdown (PD-181 of M10): every running job is cancelled and awaited, so no export is cut
    /// by the stores closing after it.
    pub async fn shutdown(&self) {
        for r in self.running().values() {
            r.cancel.store(true, Ordering::SeqCst);
        }
        let tasks: Vec<_> =
            std::mem::take(&mut *self.tasks.lock().unwrap_or_else(|e| e.into_inner()));
        for t in tasks {
            let _ = t.await;
        }
    }

    /// Jobs running now (tests).
    pub fn running_count(&self) -> usize {
        self.running().len()
    }

    /// Waits for every job started so far (tests).
    #[cfg(any(test, feature = "testing"))]
    pub async fn wait_idle(&self) {
        let tasks: Vec<_> =
            std::mem::take(&mut *self.tasks.lock().unwrap_or_else(|e| e.into_inner()));
        for t in tasks {
            let _ = t.await;
        }
    }
}

/// `(anchor_seq -> head)` of the target's leaf entries over the export's chains, and `s0`.
fn span(
    store: &dyn ServerStore,
    user_id: &str,
    receipt: &ExportReceipt,
    s1: u64,
) -> Result<(HashMap<u64, AnchorHead>, u64), crate::store::StoreError> {
    let mut heads: HashMap<u64, AnchorHead> = HashMap::new();
    for chain in &receipt.chain_ids {
        // Every head of the chain (the store's seqs are SQLite integers).
        for (anchor_seq, h) in store.anchor_heads_for_chain(chain, i64::MAX as u64)? {
            if h.user_id == user_id && anchor_seq <= s1 {
                heads.entry(anchor_seq).or_insert(h);
            }
        }
    }
    let at_or_before = heads
        .iter()
        .filter(|(_, h)| h.head_seq <= receipt.first_seq)
        .map(|(s, _)| *s)
        .max();
    let s0 = at_or_before
        .or_else(|| heads.keys().copied().min())
        .unwrap_or(s1)
        .max(s1.saturating_sub(MAX_EXCERPT_ROWS - 1))
        .max(1);
    Ok((heads, s0))
}

/// Step (4): `anchor-chain.jsonl` over `[s0, s1]` and its manifest, beside the export's files.
fn write_excerpt(
    store: &dyn ServerStore,
    user_id: &str,
    receipt: &ExportReceipt,
    s1: AnchorRef,
    issuer: &str,
    dir: &Path,
) -> std::io::Result<()> {
    let bad = |_| std::io::Error::other("anchor store");
    let (heads, s0) = span(store, user_id, receipt, s1.seq).map_err(bad)?;
    let mut f = std::io::BufWriter::new(create_private_file(&dir.join(EXCERPT_FILE))?);
    let mut first = s0;
    let mut last_chain = None;
    while first <= s1.seq {
        let last = first.saturating_add(EXCERPT_BATCH - 1).min(s1.seq);
        for row in store.anchor_range(first, last).map_err(bad)? {
            let entry = heads.get(&row.seq).and_then(|h| {
                let leaf = leaf_hash(&h.user_id, &h.chain_id, h.head_seq, &h.record_hash);
                let leaves = body_leaves(&row.body_jcs, &ExcerptLimits::DEFAULT).ok()?;
                let index = leaves.iter().position(|l| *l == leaf)? as u64;
                Some(LeafEntry {
                    user_id: h.user_id.clone(),
                    chain_id: h.chain_id.clone(),
                    head_seq: h.head_seq,
                    record_hash: h.record_hash,
                    leaf_index: index,
                })
            });
            if row.seq == s1.seq {
                last_chain = entry.as_ref().map(|e| e.chain_id.clone());
            }
            let full = entry.as_ref().map(Some);
            f.write_all(&excerpt_line_jcs(
                row.seq,
                &row.ts_utc,
                &row.kind,
                &row.body_jcs,
                &row.prev_hash,
                &row.hash,
                full,
            ))?;
            f.write_all(b"\n")?;
        }
        first = last.saturating_add(1);
    }
    f.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    let chain_id = last_chain
        .or_else(|| receipt.chain_ids.last().cloned())
        .unwrap_or_default();
    let m = ExcerptManifest {
        format: EXCERPT_FORMAT.to_owned(),
        issuer: issuer.to_owned(),
        first_seq: s0,
        last_seq: s1.seq,
        last_hash: hex::encode(s1.hash),
        chain_id,
    };
    let mut mf = create_private_file(&dir.join(EXCERPT_MANIFEST_FILE))?;
    mf.write_all(&m.to_jcs())?;
    mf.sync_all()
}

/// `README.txt`: what the archive holds, every file's SHA-256, the pin and the command.
fn write_readme(
    receipt: &ExportReceipt,
    s1: AnchorRef,
    issuer: &str,
    dir: &Path,
) -> std::io::Result<()> {
    let manifest = hex::encode(receipt.manifest_sha256);
    let hash = hex::encode(s1.hash);
    let mut text = format!(
        "atlas-duck server audit export\n\n\
         Issuer: {issuer}\n\
         Rows {} to {} of chain {}\n\n\
         Files and their SHA-256:\n",
        receipt.first_seq,
        receipt.last_seq,
        receipt.chain_ids.join(", "),
    );
    for f in &ARCHIVE_FILES[..5] {
        text.push_str(&format!(
            "  {f:<28} {}\n",
            hex::encode(sha256_file(&dir.join(f))?)
        ));
    }
    text.push_str(&format!(
        "\nAnchor head (the pin): {}:{hash}\n\n\
         Verify, from the directory that holds this one:\n  {}\n\
         or on the server: atlas-duck-server verify-export ... with the same flags.\n\n\
         Take the manifest SHA-256 and the anchor head from the export page or the server's\n\
         anchor_head log line, not from this file: a copy of this file proves nothing.\n",
        s1.seq,
        verify_command(&receipt.dir_name, &manifest, s1.seq, &hash)
    ));
    let mut f = create_private_file(&dir.join(README_FILE))?;
    f.write_all(text.as_bytes())?;
    f.sync_all()
}

/// The tar archive's length (the `size` of a finished job).
fn archive_size(dir_name: &str, dir: &Path) -> std::io::Result<u64> {
    let mut entries = Vec::new();
    for f in ARCHIVE_FILES {
        let path = dir.join(f);
        let size = std::fs::metadata(&path)?.len();
        entries.push(crate::tar::Entry {
            name: format!("{dir_name}/{f}"),
            path,
            size,
        });
    }
    crate::tar::check(&entries).map_err(|_| std::io::Error::other("archive name or size"))?;
    Ok(crate::tar::archive_len(&entries))
}

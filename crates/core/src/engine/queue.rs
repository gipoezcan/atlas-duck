//! Limits and admission (§3.3, §5.2, L44): the pending-request counts per agent key and in total,
//! the optional `max_pending_bytes` cap over static reservations, and the fetch slots.
//!
//! Admission is one check-and-count under one lock, so concurrent submits can never overshoot a
//! limit. What it hands out is a [`Ticket`]: it holds the request's place in every count until
//! it is dropped, and dropping is the only way to give the place back, so a place is returned
//! exactly once. The engine keeps the ticket in the request's entry and drops it when the request
//! becomes terminal (`Engine::after_change`); a submit that stops before the entry exists drops
//! it on return.
//!
//! RF-2b: a refusal is a bare [`Busy`], answered with the one constant `envelope::busy`, and a
//! [`Reservation`] can only be built from static values (the op's cap, the script limit), never
//! from a fetched size, so admission depends on nothing but the count and kind of pending
//! requests (§10.2).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use atlas_duck_ipc::envelope::Envelope;
use atlas_duck_ipc::proto::{ClientKind, ConnectionMeta};
use atlas_duck_ipc::sandbox::ScriptLimits;
use atlas_duck_registry::{OpClass, OperationSpec, RELEASE_CAP_BYTES};

use super::envelope;
use crate::config::limits::LimitsConfig;
use crate::ops::confluence::PAGE_BODY_LIMIT;

pub const MIB: u64 = 1024 * 1024;
/// §3.3: pending requests per agent key.
pub const PENDING_PER_AGENT: u32 = 32;
/// §3.3: pending requests in total.
pub const PENDING_TOTAL: u32 = 256;
/// §5.2: direct reads in `Fetching` at once.
pub const FETCH_SLOTS: usize = 8;
/// §9.4: concurrent real script runs.
pub const SCRIPT_SLOTS: usize = 2;
/// §9.4: concurrent dry runs and submit-time compile checks.
pub const DRY_SLOTS: usize = 2;
/// §5.2: `candidate_cache_mb` default.
pub const CANDIDATE_CACHE_MB: u64 = 512;
/// An upload's multipart part headers beside the file (PD-109, [`Reservation::upload`]): two
/// part headers and the closing line, each boundary under 64 bytes, the filename at most 255
/// characters and the comment at most 1000 (4 UTF-8 bytes each at most): under 8 KiB.
pub const UPLOAD_PART_HEADERS: u64 = 8 * 1024;

/// The limits the engine runs with (§3.3, §5.2). Only `max_pending_bytes`,
/// `candidate_cache_bytes` and `comments_cap` come from `config.toml` (`config::limits`), and
/// `script` from `[scripts]` (`config::scripts`); the rest are the spec's constants (tests scale
/// them through `TestHooks`). Fixed for the run, except the comments cap and the script limits:
/// Settings changes them live ([`Admission::set_comments_cap`], PD-76;
/// [`Admission::set_script_limits`], PD-139).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub per_agent: u32,
    pub total: u32,
    /// `None` = off (the default).
    pub max_pending_bytes: Option<u64>,
    pub fetching: usize,
    pub candidate_cache_bytes: u64,
    /// The configured script limits at start (`[scripts]`, §9.4, PD-139): the ceiling of an
    /// agent's `--limits`, and the source of a script's static reservation (`max_result_mb`). The
    /// set in force is [`Admission::script_limits`].
    pub script: ScriptLimits,
    /// The configured `jira.issue.get --comments` cap at start (Δ7, PD-63; `[limits]
    /// jira_comments_cap`). `None` = the registry's `caps.comments_cap` (100). The one in force is
    /// [`Admission::comments_cap`].
    pub comments_cap: Option<u32>,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            per_agent: PENDING_PER_AGENT,
            total: PENDING_TOTAL,
            max_pending_bytes: None,
            fetching: FETCH_SLOTS,
            candidate_cache_bytes: CANDIDATE_CACHE_MB * MIB,
            script: ScriptLimits::default(),
            comments_cap: None,
        }
    }
}

impl Limits {
    /// The defaults with the configured keys applied.
    pub fn from_config(c: &LimitsConfig) -> Limits {
        let d = Limits::default();
        Limits {
            max_pending_bytes: c.max_pending_bytes_mb.map(|mb| mb.saturating_mul(MIB)),
            candidate_cache_bytes: c
                .candidate_cache_mb
                .map_or(d.candidate_cache_bytes, |mb| mb.saturating_mul(MIB)),
            comments_cap: c.jira_comments_cap,
            ..d
        }
    }
}

/// Where an agent's requests come from, for the pending limit (§3.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyOrigin {
    /// `peer_origin_exe`, or for a CLI connection without one, `peer_exe`.
    Exe(PathBuf),
    /// An MCP connection without an origin: its `connection_id`.
    Connection(String),
    /// Nothing known: every such request of one `agent_name` shares a bucket.
    Unknown,
}

/// §3.3: `agent_name` + `peer_origin_exe`; unnamed agents are bucketed by the origin; an MCP
/// connection without an origin by its `connection_id`; a CLI connection without one by
/// `peer_exe`. Plan decision (spec silent): a *named* MCP agent without an origin is keyed by name
/// + `connection_id` too. Fairness only: every part is self-reported or spoofable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentKey {
    /// The normalized name (§3.3), as on the session.
    pub agent_name: Option<String>,
    pub origin: KeyOrigin,
}

impl AgentKey {
    pub fn new(agent_name: Option<&str>, client: ClientKind, conn: &ConnectionMeta) -> AgentKey {
        let origin = match (&conn.peer.peer_origin_exe, client) {
            (Some(exe), _) => KeyOrigin::Exe(exe.clone()),
            (None, ClientKind::Mcp) => KeyOrigin::Connection(conn.connection_id.clone()),
            (None, ClientKind::Cli) => match &conn.peer.peer_exe {
                Some(exe) => KeyOrigin::Exe(exe.clone()),
                None => KeyOrigin::Unknown,
            },
        };
        AgentKey {
            agent_name: agent_name.map(str::to_owned),
            origin,
        }
    }
}

/// A request's static reservation against `max_pending_bytes` (§5.2). Built only from static
/// values, never from a fetched size (RF-2b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation(u64);

impl Reservation {
    /// A read: the 16 MiB release cap, or its op's static cap if lower.
    pub fn read(spec: &OperationSpec) -> Reservation {
        Reservation(spec.caps.static_result_cap_bytes.min(RELEASE_CAP_BYTES))
    }

    /// A script: its static `max_result_mb` (§9.4), the configured one (PD-139).
    pub fn script(limits: &ScriptLimits) -> Reservation {
        Reservation(u64::from(limits.max_result_mb).saturating_mul(MIB))
    }

    /// Writes reserve nothing (§5.2 names reads and scripts), except the two that hold a large
    /// body while pending ([`Reservation::page_update`], [`Reservation::upload`]).
    pub fn none() -> Reservation {
        Reservation(0)
    }

    /// `confluence.page.update` (T23, T15 review I-1): a pending update keeps the current page's
    /// storage and, behind a conflict, the base version's, each up to
    /// [`PAGE_BODY_LIMIT`](crate::ops::confluence::PAGE_BODY_LIMIT) bytes. Never more than the
    /// cap (T23 review I-1): under a `max_pending_bytes` below 32 MiB one update still fits an
    /// empty queue instead of being `busy` for good.
    pub fn page_update(limits: &Limits) -> Reservation {
        Reservation(2 * PAGE_BODY_LIMIT as u64).within(limits)
    }

    /// `confluence.attachment.upload` (T23 review I-2), from the op's static `upload_max_bytes`
    /// (`n`): a pending upload keeps the base64 content in the validated params and again in the
    /// write's params, a third time in the delivery view of an edited upload
    /// (`EditView::executed_params`), each up to `4 * ceil(n / 3)` characters (the schema's
    /// `maxLength`), and the multipart wire body in its request list: the decoded file (`n`) plus
    /// [`UPLOAD_PART_HEADERS`]. Never more than the cap, like a page update.
    pub fn upload(n: u64, limits: &Limits) -> Reservation {
        let base64 = n.div_ceil(3).saturating_mul(4);
        let held = base64
            .saturating_mul(3)
            .saturating_add(n)
            .saturating_add(UPLOAD_PART_HEADERS);
        Reservation(held).within(limits)
    }

    /// At most the cap in force (no cap: unchanged, `admit` ignores bytes then).
    fn within(self, limits: &Limits) -> Reservation {
        Reservation(
            limits
                .max_pending_bytes
                .map_or(self.0, |cap| self.0.min(cap)),
        )
    }

    /// The reservation of a registry op: reads reserve, writes do not, except a page update
    /// (its enrichment bodies, [`Reservation::page_update`]) and an upload (its file,
    /// [`Reservation::upload`]).
    pub fn for_op(spec: &OperationSpec, limits: &Limits) -> Reservation {
        match spec.class {
            OpClass::Read => Reservation::read(spec),
            OpClass::Write if spec.id == "confluence.page.update" => {
                Reservation::page_update(limits)
            }
            OpClass::Write => spec
                .caps
                .upload_max_bytes
                .map_or(Reservation::none(), |n| Reservation::upload(n, limits)),
        }
    }

    pub fn bytes(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Default)]
struct Counts {
    per_agent: HashMap<AgentKey, u32>,
    total: u32,
    bytes: u64,
}

fn lock(m: &Mutex<Counts>) -> MutexGuard<'_, Counts> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The pending counts and the reservation sum (§3.3, §5.2).
#[derive(Debug)]
pub struct Admission {
    limits: Limits,
    counts: Arc<Mutex<Counts>>,
    /// The comments cap in force (0 = `None`): `limits.comments_cap` until Settings changes it.
    comments_cap: AtomicU32,
    /// The configured script limits in force: `limits.script` until Settings changes them.
    script: Mutex<ScriptLimits>,
}

impl Admission {
    pub fn new(limits: Limits) -> Admission {
        Admission {
            limits,
            counts: Arc::new(Mutex::new(Counts::default())),
            comments_cap: AtomicU32::new(limits.comments_cap.unwrap_or(0)),
            script: Mutex::new(limits.script),
        }
    }

    /// The configured script limits in force (§9.4, PD-139): the ceiling of a submitted run's
    /// `--limits`, the `script_limits` of `ops describe --instance` and the base of a script's
    /// static reservation.
    pub fn script_limits(&self) -> ScriptLimits {
        *self.script.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// PD-139: a Settings change of the script limits applies to every run submitted from now on
    /// (the caller logged it first); a pending run keeps the limits it was validated with.
    pub fn set_script_limits(&self, limits: ScriptLimits) {
        *self.script.lock().unwrap_or_else(PoisonError::into_inner) = limits;
    }

    /// The limits of the run as started (the comments cap in force is [`Self::comments_cap`]).
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The configured `jira.issue.get --comments` cap in force; `None` = the registry's.
    pub fn comments_cap(&self) -> Option<u32> {
        Some(self.comments_cap.load(Ordering::SeqCst)).filter(|n| *n > 0)
    }

    /// PD-76: a Settings change of `jira_comments_cap` applies to every request validated from
    /// now on (the caller logged it first).
    pub fn set_comments_cap(&self, cap: Option<u32>) {
        self.comments_cap.store(cap.unwrap_or(0), Ordering::SeqCst);
    }

    /// Counts the request in, or refuses with [`Busy`] (one answer for every limit kind, L44).
    /// Nothing changes on a refusal.
    pub fn admit(&self, key: AgentKey, reservation: Reservation) -> Result<Ticket, Busy> {
        let mut c = lock(&self.counts);
        let mine = c.per_agent.get(&key).copied().unwrap_or(0);
        let bytes = c.bytes.saturating_add(reservation.0);
        let over_bytes = self.limits.max_pending_bytes.is_some_and(|cap| bytes > cap);
        if mine >= self.limits.per_agent || c.total >= self.limits.total || over_bytes {
            return Err(Busy);
        }
        c.per_agent.insert(key.clone(), mine + 1);
        c.total += 1;
        c.bytes = bytes;
        Ok(Ticket {
            counts: self.counts.clone(),
            key,
            bytes: reservation.0,
        })
    }

    /// Requests counted in now.
    pub fn pending_total(&self) -> u32 {
        lock(&self.counts).total
    }

    pub fn pending_for(&self, key: &AgentKey) -> u32 {
        lock(&self.counts).per_agent.get(key).copied().unwrap_or(0)
    }

    /// The sum of the static reservations (not actual sizes).
    pub fn reserved_bytes(&self) -> u64 {
        lock(&self.counts).bytes
    }
}

/// A refused admission. It carries nothing (which limit, how full, what size), so the answer
/// cannot depend on anything but the refusal itself (§3.3, RF-2b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Busy;

impl Busy {
    /// The constant `busy` envelope: exit 11, `retry_after_s` 30, nothing queued.
    pub fn envelope(self) -> Envelope {
        envelope::busy()
    }
}

/// One admitted request's place in the counts. Dropping it gives the place back; that happens
/// exactly once (a `Ticket` is neither `Clone` nor `Copy`).
pub struct Ticket {
    counts: Arc<Mutex<Counts>>,
    key: AgentKey,
    bytes: u64,
}

impl Ticket {
    /// The static reservation this ticket holds.
    pub fn reservation(&self) -> u64 {
        self.bytes
    }

    /// Gives the place back now (the same as dropping it).
    pub fn release(self) {}
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut c = lock(&self.counts);
        c.total = c.total.saturating_sub(1);
        c.bytes = c.bytes.saturating_sub(self.bytes);
        if let Some(n) = c.per_agent.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                c.per_agent.remove(&self.key);
            }
        }
    }
}

impl std::fmt::Debug for Ticket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ticket")
            .field("bytes", &self.bytes)
            .finish()
    }
}

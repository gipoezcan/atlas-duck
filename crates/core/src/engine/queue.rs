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
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use atlas_duck_ipc::envelope::Envelope;
use atlas_duck_ipc::proto::{ClientKind, ConnectionMeta};
use atlas_duck_ipc::sandbox::ScriptLimits;
use atlas_duck_registry::{OpClass, OperationSpec, RELEASE_CAP_BYTES};

use super::envelope;
use crate::config::limits::LimitsConfig;

pub const MIB: u64 = 1024 * 1024;
/// §3.3: pending requests per agent key.
pub const PENDING_PER_AGENT: u32 = 32;
/// §3.3: pending requests in total.
pub const PENDING_TOTAL: u32 = 256;
/// §5.2: direct reads in `Fetching` at once.
pub const FETCH_SLOTS: usize = 8;
/// §5.2: `candidate_cache_mb` default.
pub const CANDIDATE_CACHE_MB: u64 = 512;

/// The limits the engine runs with (§3.3, §5.2). Only `max_pending_bytes` and
/// `candidate_cache_bytes` come from `config.toml` (`config::limits`); the rest are the spec's
/// constants (tests scale them through `TestHooks`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub per_agent: u32,
    pub total: u32,
    /// `None` = off (the default).
    pub max_pending_bytes: Option<u64>,
    pub fetching: usize,
    pub candidate_cache_bytes: u64,
    /// A script's static reservation in MiB (§9.4 `max_result_mb`; Settings arrive in M6).
    pub max_result_mb: u32,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            per_agent: PENDING_PER_AGENT,
            total: PENDING_TOTAL,
            max_pending_bytes: None,
            fetching: FETCH_SLOTS,
            candidate_cache_bytes: CANDIDATE_CACHE_MB * MIB,
            max_result_mb: ScriptLimits::default().max_result_mb,
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

    /// A script: its static `max_result_mb` (§9.4).
    pub fn script(limits: &Limits) -> Reservation {
        Reservation(u64::from(limits.max_result_mb).saturating_mul(MIB))
    }

    /// Writes reserve nothing (§5.2 names reads and scripts).
    pub fn none() -> Reservation {
        Reservation(0)
    }

    /// The reservation of a registry op: reads reserve, writes do not.
    pub fn for_op(spec: &OperationSpec) -> Reservation {
        match spec.class {
            OpClass::Read => Reservation::read(spec),
            OpClass::Write => Reservation::none(),
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
}

impl Admission {
    pub fn new(limits: Limits) -> Admission {
        Admission {
            limits,
            counts: Arc::new(Mutex::new(Counts::default())),
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
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

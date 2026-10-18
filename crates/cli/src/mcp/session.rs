//! The MCP server's one IPC connection (PD-115, PD-128): opened by the first connected tool call
//! (nothing connects at `initialize` or `tools/list`), shared by every concurrent call through
//! `SharedClient`, and opened again only after it closed.
//!
//! The core keys an MCP agent's approval session by `connection_id`, so every reconnect starts a
//! new approval session (the accepted cost of PD-115, L155). A connection therefore counts as
//! gone only when `SharedClient::is_closed()` says so (its reader saw EOF, an error or a protocol
//! violation, or its writer failed); an error answer, a wrong-shaped reply, a deadline or a
//! dropped tool call never reconnects.
//!
//! Reaching the app is single-flight: one tool call discovers, launches, connects and says
//! `hello` while the others wait for it, each bounded by its own deadline. A failed attempt
//! answers only the call that made it and leaves the state as it was: the next call tries again
//! (§4.6 "re-runs the §3.2 checks and `hello` on the next tool call"; no negative answer is
//! cached).

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use atlas_duck_ipc::build_info::BUILD_ID;
use atlas_duck_ipc::client::SharedClient;
use atlas_duck_ipc::envelope::Envelope;
use atlas_duck_ipc::proto::{AgentNameSource, ClientKind, Hello};

use super::config::McpConfig;
use crate::connected::{Connector, OWN_LIMIT, cwd_basename, reach};
use crate::deadline::Deadline;
use crate::interrupt::Never;
use crate::launch;

enum State {
    /// No connection yet.
    Idle,
    Connected(SharedClient),
    /// The connection closed (`SharedClient::is_closed`); the next call reconnects.
    Closed,
}

/// The agent fields of the configuration (PD-122).
struct AgentFlags {
    /// `--agent`, else a non-empty `ATLAS_DUCK_AGENT` (argv applies that fallback).
    agent: Option<String>,
    source: AgentNameSource,
    /// `--agent` was passed, even as `""`.
    given: bool,
}

impl AgentFlags {
    fn of(cfg: &McpConfig) -> AgentFlags {
        AgentFlags {
            agent: cfg.agent.clone(),
            source: cfg.agent_source,
            given: cfg.agent_given,
        }
    }
}

pub(crate) struct Session {
    connector: Arc<dyn Connector>,
    agent: AgentFlags,
    /// Never held across an await.
    state: Mutex<State>,
    /// Held while one call reaches the app (single flight).
    connecting: tokio::sync::Mutex<()>,
    /// Built at the first attempt to connect and reused by every reconnect (PD-122: the agent
    /// name is read once).
    hello: OnceLock<Hello>,
    /// Bound of the wait for another call's attempt when the deadline is unbounded
    /// (`ATLAS_DUCK_MCP_TIMEOUT=0`): `OWN_LIMIT` (tests: shorter).
    lock_limit: Duration,
}

impl Session {
    pub(crate) fn new(cfg: &McpConfig, connector: Arc<dyn Connector>) -> Session {
        Session {
            connector,
            agent: AgentFlags::of(cfg),
            state: Mutex::new(State::Idle),
            connecting: tokio::sync::Mutex::new(()),
            hello: OnceLock::new(),
            lock_limit: OWN_LIMIT,
        }
    }

    /// [`Session::new`] with another bound of the unbounded deadline's lock wait.
    #[cfg(test)]
    pub(crate) fn with_lock_limit(mut self, limit: Duration) -> Session {
        self.lock_limit = limit;
        self
    }

    /// The shared connection, reaching the app first if there is none or it closed. `deadline`
    /// bounds the wait for another call's attempt as well as this call's own discover, launch
    /// poll, connect and `hello`. `Err` is the envelope to answer: nothing was queued.
    /// `client_name` is the tool call's `clientInfo.name`; only the first attempt reads it.
    pub(crate) async fn client(
        &self,
        deadline: &Deadline,
        client_name: Option<&str>,
    ) -> Result<SharedClient, Envelope> {
        if let Some(client) = self.live() {
            return Ok(client);
        }
        // `ATLAS_DUCK_MCP_TIMEOUT=0`: each attempt is bounded by its own step limits, but attempts
        // run one after another, so a waiter gives up after `lock_limit` instead of queueing
        // behind every earlier failing attempt (T7 review M-2).
        let at = deadline
            .at()
            .unwrap_or_else(|| std::time::Instant::now() + self.lock_limit);
        let at = tokio::time::Instant::from_std(at);
        let _flight = match tokio::time::timeout_at(at, self.connecting.lock()).await {
            Ok(guard) => guard,
            // Nothing was sent: nothing queued.
            Err(_) => return Err(*launch::launch_timeout()),
        };
        // Another call may have connected while this one waited.
        if let Some(client) = self.live() {
            return Ok(client);
        }
        let hello = self
            .hello
            .get_or_init(|| hello_for(&self.agent, client_name))
            .clone();
        // No interrupt source in MCP mode: a tool call ends by its deadline or its cancellation.
        let client = reach(&*self.connector, &hello, deadline, &mut Never)
            .await
            .map_err(|env| *env)?
            .into_shared();
        *self.state() = State::Connected(client.clone());
        Ok(client)
    }

    /// Records that the connection closed, if it did: a no-op while the current client is open,
    /// so a call holding an older client cannot drop a newer one (each needless reconnect splits
    /// the agent's approval session). Reconnecting does not depend on it: `client` treats a
    /// client that reports `is_closed()` as closed anyway.
    pub(crate) fn mark_closed(&self) {
        let mut state = self.state();
        if let State::Connected(client) = &*state
            && client.is_closed()
        {
            *state = State::Closed;
        }
    }

    /// The current client if it is open.
    fn live(&self) -> Option<SharedClient> {
        let mut state = self.state();
        match &*state {
            State::Connected(client) if !client.is_closed() => Some(client.clone()),
            State::Connected(_) => {
                *state = State::Closed;
                None
            }
            State::Idle | State::Closed => None,
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The MCP server's `hello` (§3.3, PD-122): client kind `mcp`, and the agent name from `--agent`
/// (an empty one is no name at all, and nothing fills the gap), else `ATLAS_DUCK_AGENT`, else the
/// client's `clientInfo.name` (an empty one is no name).
fn hello_for(agent: &AgentFlags, client_name: Option<&str>) -> Hello {
    let (agent_name, agent_name_source) = match (&agent.agent, client_name) {
        (Some(name), _) => (Some(name.clone()), agent.source),
        (None, _) if agent.given => (None, AgentNameSource::None),
        (None, Some(name)) if !name.is_empty() => {
            (Some(name.to_owned()), AgentNameSource::McpClientInfo)
        }
        (None, _) => (None, AgentNameSource::None),
    };
    Hello {
        build_id: BUILD_ID.to_owned(),
        client_kind: ClientKind::Mcp,
        agent_name,
        agent_name_source,
        cwd_basename: cwd_basename(),
    }
}

/// [`hello_for`] from a configuration (tests).
#[cfg(test)]
pub(crate) fn hello_of(cfg: &McpConfig, client_name: Option<&str>) -> Hello {
    hello_for(&AgentFlags::of(cfg), client_name)
}

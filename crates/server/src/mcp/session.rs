//! Which user and credential created each MCP session (T19 Step 2, M14 PD-243). A session id seen
//! first in a response to user A's key belongs to A and that key; B's key, or another credential
//! of A (an OAuth token for a session an API key opened), naming it is refused. At most `MAX_SESSIONS` bindings are
//! kept; the oldest goes first (its rmcp session has long expired by then).

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};

pub const MAX_SESSIONS: usize = 10_000;

#[derive(Default)]
struct Inner {
    owner: HashMap<String, (String, String)>,
    order: VecDeque<String>,
}

#[derive(Default)]
pub struct McpSessions {
    inner: Mutex<Inner>,
}

impl McpSessions {
    pub fn new() -> McpSessions {
        McpSessions::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Records `session` as `user_id`'s through `credential` (the first binding wins).
    pub fn bind(&self, session: &str, user_id: &str, credential: &str) {
        let mut g = self.lock();
        if g.owner.contains_key(session) {
            return;
        }
        while g.order.len() >= MAX_SESSIONS {
            match g.order.pop_front() {
                Some(old) => {
                    g.owner.remove(&old);
                }
                None => break,
            }
        }
        g.owner.insert(
            session.to_owned(),
            (user_id.to_owned(), credential.to_owned()),
        );
        g.order.push_back(session.to_owned());
    }

    /// True only for a session this user created with this credential. Batch-4a review: an
    /// unknown id is refused here too (404), not left to rmcp.
    pub fn may_use(&self, session: &str, user_id: &str, credential: &str) -> bool {
        self.lock()
            .owner
            .get(session)
            .is_some_and(|(u, c)| u == user_id && c == credential)
    }

    pub fn forget(&self, session: &str) {
        let mut g = self.lock();
        if g.owner.remove(session).is_some() {
            g.order.retain(|s| s != session);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sessions_belong_to_their_creator() {
        let s = McpSessions::new();
        s.bind("s1", "a", "api_key:k1");
        s.bind("s1", "b", "api_key:k2");
        assert!(s.may_use("s1", "a", "api_key:k1"));
        assert!(
            !s.may_use("s1", "b", "api_key:k2"),
            "the first binding wins"
        );
        assert!(
            !s.may_use("s1", "a", "oauth:g1"),
            "another credential of the user"
        );
        assert!(
            !s.may_use("unknown", "b", "api_key:k2"),
            "unknown ids are refused"
        );
        s.forget("s1");
        assert!(
            !s.may_use("s1", "a", "api_key:k1"),
            "a forgotten session is unknown"
        );
    }
}

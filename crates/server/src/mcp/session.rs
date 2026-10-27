//! Which user created each MCP session (T19 Step 2). A session id seen first in a response to
//! user A's key belongs to A; B's key naming it is refused. At most `MAX_SESSIONS` bindings are
//! kept; the oldest goes first (its rmcp session has long expired by then).

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};

pub const MAX_SESSIONS: usize = 10_000;

#[derive(Default)]
struct Inner {
    owner: HashMap<String, String>,
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

    /// Records `session` as `user_id`'s (the first binding wins).
    pub fn bind(&self, session: &str, user_id: &str) {
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
        g.owner.insert(session.to_owned(), user_id.to_owned());
        g.order.push_back(session.to_owned());
    }

    /// False when the session belongs to another user. An unknown id passes: rmcp answers it
    /// (404) itself, and no session exists that this map does not name.
    pub fn may_use(&self, session: &str, user_id: &str) -> bool {
        self.lock()
            .owner
            .get(session)
            .is_none_or(|owner| owner == user_id)
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
        s.bind("s1", "a");
        s.bind("s1", "b");
        assert!(s.may_use("s1", "a"));
        assert!(!s.may_use("s1", "b"), "the first binding wins");
        assert!(s.may_use("unknown", "b"));
        s.forget("s1");
        assert!(s.may_use("s1", "b"));
    }
}

//! Login failure rate limits per username and per client IP (SM-2.2, PD-201): an in-memory
//! sliding window of failure times per key, checked before the bind so a limited key never
//! reaches the directory. A success clears the username's window, not the IP's. Not persisted
//! (a restart resets, L222). At most `MAX_KEYS` keys; the key whose newest failure is oldest
//! is evicted first.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

pub const MAX_KEYS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    User,
    Ip,
}

pub struct LoginLimiter {
    limit_user: usize,
    limit_ip: usize,
    window: i64,
    max_keys: usize,
    failures: Mutex<HashMap<(Kind, String), VecDeque<i64>>>,
}

/// Seconds until the oldest counted failure leaves the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryAfter(pub u64);

impl LoginLimiter {
    pub fn new(limit_user: u32, limit_ip: u32, window_secs: u64) -> LoginLimiter {
        LoginLimiter {
            limit_user: limit_user as usize,
            limit_ip: limit_ip as usize,
            window: i64::try_from(window_secs).unwrap_or(i64::MAX),
            max_keys: MAX_KEYS,
            failures: Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    fn with_max_keys(mut self, n: usize) -> LoginLimiter {
        self.max_keys = n;
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(Kind, String), VecDeque<i64>>> {
        self.failures.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `Err` with the wait when either the username or the IP is at its limit.
    pub fn check(&self, user: &str, ip: &str, now: i64) -> Result<(), RetryAfter> {
        let mut map = self.lock();
        self.wait_locked(&mut map, user, ip, now)
    }

    /// Batch-2 review I1: the check and the count of this attempt under one lock, so parallel
    /// attempts cannot all pass before any failure is recorded. The attempt counts as a failure
    /// until [`Self::release`] takes it back (success, or a directory that could not answer).
    pub fn reserve(&self, user: &str, ip: &str, now: i64) -> Result<(), RetryAfter> {
        let mut map = self.lock();
        self.wait_locked(&mut map, user, ip, now)?;
        self.push_locked(&mut map, user, ip, now);
        Ok(())
    }

    /// Takes back one attempt [`Self::reserve`] counted at `at`.
    pub fn release(&self, user: &str, ip: &str, at: i64) {
        let mut map = self.lock();
        for key in [(Kind::User, user.to_owned()), (Kind::Ip, ip.to_owned())] {
            if let Some(q) = map.get_mut(&key) {
                if let Some(pos) = q.iter().rposition(|t| *t == at) {
                    q.remove(pos);
                }
                if q.is_empty() {
                    map.remove(&key);
                }
            }
        }
    }

    fn wait_locked(
        &self,
        map: &mut HashMap<(Kind, String), VecDeque<i64>>,
        user: &str,
        ip: &str,
        now: i64,
    ) -> Result<(), RetryAfter> {
        let mut wait = None;
        for (key, limit) in [
            ((Kind::User, user.to_owned()), self.limit_user),
            ((Kind::Ip, ip.to_owned()), self.limit_ip),
        ] {
            if let Some(q) = map.get_mut(&key) {
                while q.front().is_some_and(|t| *t <= now - self.window) {
                    q.pop_front();
                }
                if q.len() >= limit
                    && let Some(oldest) = q.front()
                {
                    let secs = (oldest + self.window - now).max(1);
                    let secs = u64::try_from(secs).unwrap_or(1);
                    wait = Some(wait.map_or(secs, |w: u64| w.max(secs)));
                }
            }
        }
        match wait {
            Some(s) => Err(RetryAfter(s)),
            None => Ok(()),
        }
    }

    pub fn record_failure(&self, user: &str, ip: &str, now: i64) {
        let mut map = self.lock();
        self.push_locked(&mut map, user, ip, now);
    }

    fn push_locked(
        &self,
        map: &mut HashMap<(Kind, String), VecDeque<i64>>,
        user: &str,
        ip: &str,
        now: i64,
    ) {
        for key in [(Kind::User, user.to_owned()), (Kind::Ip, ip.to_owned())] {
            if !map.contains_key(&key) && map.len() >= self.max_keys {
                let victim = map
                    .iter()
                    .min_by_key(|(_, q)| q.back().copied().unwrap_or(i64::MIN))
                    .map(|(k, _)| k.clone());
                if let Some(v) = victim {
                    map.remove(&v);
                }
            }
            map.entry(key).or_default().push_back(now);
        }
    }

    /// A successful login clears the username's window only.
    pub fn record_success(&self, user: &str) {
        self.lock().remove(&(Kind::User, user.to_owned()));
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_counts_at_once_and_release_takes_it_back() {
        let l = LoginLimiter::new(2, 20, 900);
        assert_eq!(l.reserve("alice", "1.1.1.1", 10), Ok(()));
        assert_eq!(l.reserve("alice", "1.1.1.2", 10), Ok(()));
        // Two attempts in flight already fill alice's window.
        assert!(l.reserve("alice", "1.1.1.3", 10).is_err());
        l.release("alice", "1.1.1.1", 10);
        assert_eq!(l.reserve("alice", "1.1.1.3", 11), Ok(()));
        l.release("alice", "1.1.1.2", 10);
        l.release("alice", "1.1.1.3", 11);
        assert!(l.is_empty() || l.check("alice", "9.9.9.9", 12).is_ok());
    }

    #[test]
    fn username_limit_and_retry_after() {
        let l = LoginLimiter::new(5, 20, 900);
        for i in 0..5 {
            assert_eq!(l.check("alice", "1.1.1.1", 100 + i), Ok(()));
            l.record_failure("alice", "1.1.1.1", 100 + i);
        }
        assert_eq!(l.check("alice", "2.2.2.2", 110), Err(RetryAfter(890)));
        // The window slides: the first failure (100) leaves at 1000.
        assert_eq!(l.check("alice", "2.2.2.2", 1000), Ok(()));
        // Another user from the same IP is not limited by alice's count.
        assert_eq!(l.check("bob", "3.3.3.3", 110), Ok(()));
    }

    #[test]
    fn ip_limit_across_usernames() {
        let l = LoginLimiter::new(5, 20, 900);
        for i in 0..20 {
            l.record_failure(&format!("user{i}"), "9.9.9.9", 50);
        }
        assert!(l.check("fresh", "9.9.9.9", 60).is_err());
        assert_eq!(l.check("fresh", "8.8.8.8", 60), Ok(()));
    }

    #[test]
    fn success_clears_the_username_not_the_ip() {
        let l = LoginLimiter::new(2, 3, 900);
        l.record_failure("alice", "1.1.1.1", 1);
        l.record_failure("alice", "1.1.1.1", 2);
        assert!(l.check("alice", "5.5.5.5", 3).is_err());
        l.record_success("alice");
        assert_eq!(l.check("alice", "5.5.5.5", 3), Ok(()));
        l.record_failure("bob", "1.1.1.1", 4);
        assert!(l.check("carol", "1.1.1.1", 5).is_err(), "IP window kept");
    }

    #[test]
    fn key_cap_evicts_the_stalest() {
        let l = LoginLimiter::new(1, 100, 900).with_max_keys(4);
        l.record_failure("old", "ip-old", 1);
        l.record_failure("new", "ip-new", 50);
        l.record_failure("newer", "ip-newer", 60);
        assert!(l.len() <= 4);
        assert_eq!(
            l.check("old", "x", 70),
            Ok(()),
            "the stalest key was evicted"
        );
        assert!(l.check("newer", "x", 70).is_err());
    }
}

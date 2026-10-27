//! A sliding-window request limit per key (client IP), in memory like M12's login limiter: at most
//! `limit` requests per `window` seconds; at most [`MAX_KEYS`] keys, the stalest evicted first.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

pub const MAX_KEYS: usize = 100_000;

pub struct WindowLimiter {
    limit: usize,
    window: i64,
    hits: Mutex<HashMap<String, VecDeque<i64>>>,
}

impl WindowLimiter {
    pub fn new(limit: u32, window_secs: i64) -> WindowLimiter {
        WindowLimiter {
            limit: limit as usize,
            window: window_secs.max(1),
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Counts one request of `key` at `now`; `Err(retry_after_secs)` when the key is at its limit
    /// (the refused request is not counted).
    pub fn hit(&self, key: &str, now: i64) -> Result<(), u64> {
        let mut map = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        let start = now - self.window;
        if let Some(q) = map.get_mut(key) {
            while q.front().is_some_and(|t| *t <= start) {
                q.pop_front();
            }
            if q.len() >= self.limit {
                let oldest = q.front().copied().unwrap_or(now);
                return Err(u64::try_from(oldest + self.window - now)
                    .unwrap_or(1)
                    .max(1));
            }
        }
        if !map.contains_key(key) && map.len() >= MAX_KEYS {
            let stalest = map
                .iter()
                .min_by_key(|(_, q)| q.back().copied().unwrap_or(i64::MIN))
                .map(|(k, _)| k.clone());
            if let Some(k) = stalest {
                map.remove(&k);
            }
        }
        map.entry(key.to_owned()).or_default().push_back(now);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn limit_per_key_and_window() {
        let l = WindowLimiter::new(2, 100);
        assert_eq!(l.hit("a", 0), Ok(()));
        assert_eq!(l.hit("a", 10), Ok(()));
        assert_eq!(l.hit("a", 20), Err(80));
        assert_eq!(l.hit("b", 20), Ok(()));
        // The first hit leaves the window at 100.
        assert_eq!(l.hit("a", 100), Ok(()));
        assert_eq!(l.hit("a", 101), Err(9));
    }
}

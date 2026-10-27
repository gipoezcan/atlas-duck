//! An in-memory `ServerStore` for unit tests (feature `testing`, never a release build). Same
//! contract as the SQLite store, checked by the shared conformance tests.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use super::{
    AnchorHasher, AnchorHead, AnchorRow, ApiKeyRecord, InstanceRecord, PatRecord, Sealed,
    ServerStore, SessionRecord, StoreError, StoreResult, UserRecord, UserState,
};

#[derive(Default)]
struct Inner {
    users: BTreeMap<String, UserRecord>,
    states: BTreeMap<String, UserState>,
    keystore: BTreeMap<(String, String), Sealed>,
    pats: BTreeMap<(String, String), PatRecord>,
    sessions: BTreeMap<[u8; 32], SessionRecord>,
    keys: BTreeMap<String, ApiKeyRecord>,
    instances: BTreeMap<String, InstanceRecord>,
    anchors: Vec<AnchorRow>,
    heads: Vec<(u64, AnchorHead)>,
}

#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

impl MemoryStore {
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl ServerStore for MemoryStore {
    fn upsert_user(&self, u: &UserRecord) -> StoreResult<()> {
        let mut g = self.lock();
        if g.users
            .values()
            .any(|o| o.username == u.username && o.user_id != u.user_id)
        {
            return Err(StoreError::Duplicate);
        }
        let entry = g
            .users
            .entry(u.user_id.clone())
            .or_insert_with(|| u.clone());
        entry.display_name = u.display_name.clone();
        entry.roles = u.roles.clone();
        entry.data_key_wrapped = u.data_key_wrapped.clone();
        Ok(())
    }

    fn user(&self, user_id: &str) -> StoreResult<Option<UserRecord>> {
        Ok(self.lock().users.get(user_id).cloned())
    }

    fn user_by_name(&self, username: &str) -> StoreResult<Option<UserRecord>> {
        Ok(self
            .lock()
            .users
            .values()
            .find(|u| u.username == username)
            .cloned())
    }

    fn users_all(&self) -> StoreResult<Vec<(UserRecord, UserState)>> {
        let g = self.lock();
        let mut v: Vec<(UserRecord, UserState)> = g
            .users
            .values()
            .map(|u| {
                let st = g.states.get(&u.user_id).cloned().unwrap_or_default();
                (u.clone(), st)
            })
            .collect();
        v.sort_by(|a, b| a.0.username.cmp(&b.0.username));
        Ok(v)
    }

    fn user_state(&self, user_id: &str) -> StoreResult<Option<UserState>> {
        let g = self.lock();
        Ok(g.users
            .contains_key(user_id)
            .then(|| g.states.get(user_id).cloned().unwrap_or_default()))
    }

    fn user_set_last_login(&self, user_id: &str, at: i64) -> StoreResult<()> {
        let mut g = self.lock();
        if g.users.contains_key(user_id) {
            g.states
                .entry(user_id.to_owned())
                .or_default()
                .last_login_at = Some(at);
        }
        Ok(())
    }

    fn user_deactivate(
        &self,
        user_id: &str,
        at: i64,
        by: &str,
        retention_until: i64,
    ) -> StoreResult<bool> {
        let mut g = self.lock();
        if !g.users.contains_key(user_id) {
            return Ok(false);
        }
        let st = g.states.entry(user_id.to_owned()).or_default();
        if st.deactivated_at.is_some() {
            return Ok(false);
        }
        st.deactivated_at = Some(at);
        st.deactivated_by = Some(by.to_owned());
        st.retention_until = Some(retention_until);
        Ok(true)
    }

    fn ks_get(&self, user_id: &str, entry: &str) -> StoreResult<Option<Sealed>> {
        Ok(self
            .lock()
            .keystore
            .get(&(user_id.to_owned(), entry.to_owned()))
            .cloned())
    }

    fn ks_set(&self, user_id: &str, entry: &str, v: &Sealed) -> StoreResult<()> {
        self.lock()
            .keystore
            .insert((user_id.to_owned(), entry.to_owned()), v.clone());
        Ok(())
    }

    fn ks_delete(&self, user_id: &str, entry: &str) -> StoreResult<bool> {
        Ok(self
            .lock()
            .keystore
            .remove(&(user_id.to_owned(), entry.to_owned()))
            .is_some())
    }

    fn pat_put(&self, p: &PatRecord) -> StoreResult<()> {
        self.lock()
            .pats
            .insert((p.user_id.clone(), p.alias.clone()), p.clone());
        Ok(())
    }

    fn pat_get(&self, user_id: &str, alias: &str) -> StoreResult<Option<PatRecord>> {
        Ok(self
            .lock()
            .pats
            .get(&(user_id.to_owned(), alias.to_owned()))
            .cloned())
    }

    fn pat_list(&self, user_id: &str) -> StoreResult<Vec<PatRecord>> {
        Ok(self
            .lock()
            .pats
            .values()
            .filter(|p| p.user_id == user_id)
            .cloned()
            .collect())
    }

    fn pat_delete(&self, user_id: &str, alias: &str) -> StoreResult<bool> {
        Ok(self
            .lock()
            .pats
            .remove(&(user_id.to_owned(), alias.to_owned()))
            .is_some())
    }

    fn pats_for_alias(&self, alias: &str) -> StoreResult<Vec<PatRecord>> {
        Ok(self
            .lock()
            .pats
            .values()
            .filter(|p| p.alias == alias)
            .cloned()
            .collect())
    }

    fn session_put(&self, s: &SessionRecord) -> StoreResult<()> {
        self.lock().sessions.insert(s.id_hash, s.clone());
        Ok(())
    }

    fn session_get(&self, id_hash: &[u8; 32]) -> StoreResult<Option<SessionRecord>> {
        Ok(self.lock().sessions.get(id_hash).cloned())
    }

    fn session_touch(
        &self,
        id_hash: &[u8; 32],
        last_seen: i64,
        idle_expiry: i64,
    ) -> StoreResult<()> {
        if let Some(s) = self.lock().sessions.get_mut(id_hash) {
            s.last_seen = last_seen;
            s.idle_expiry = idle_expiry;
        }
        Ok(())
    }

    fn session_delete(&self, id_hash: &[u8; 32]) -> StoreResult<bool> {
        Ok(self.lock().sessions.remove(id_hash).is_some())
    }

    fn session_delete_expired(&self, now: i64) -> StoreResult<u64> {
        let mut g = self.lock();
        let before = g.sessions.len();
        g.sessions
            .retain(|_, s| s.absolute_expiry > now && s.idle_expiry > now);
        Ok((before - g.sessions.len()) as u64)
    }

    fn sessions_all(&self) -> StoreResult<Vec<SessionRecord>> {
        Ok(self.lock().sessions.values().cloned().collect())
    }

    fn sessions_delete_for_user(&self, user_id: &str) -> StoreResult<u64> {
        let mut g = self.lock();
        let before = g.sessions.len();
        g.sessions.retain(|_, s| s.user_id != user_id);
        Ok((before - g.sessions.len()) as u64)
    }

    fn api_keys_revoke_all(&self, user_id: &str, at: i64) -> StoreResult<Vec<ApiKeyRecord>> {
        let mut out: Vec<ApiKeyRecord> = Vec::new();
        for k in self.lock().keys.values_mut() {
            if k.user_id == user_id && k.revoked_at.is_none() {
                k.revoked_at = Some(at);
                out.push(k.clone());
            }
        }
        out.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        Ok(out)
    }
    fn api_key_insert(&self, k: &ApiKeyRecord) -> StoreResult<()> {
        let mut g = self.lock();
        if g.keys.contains_key(&k.id) || g.keys.values().any(|o| o.prefix == k.prefix) {
            return Err(StoreError::Duplicate);
        }
        g.keys.insert(k.id.clone(), k.clone());
        Ok(())
    }

    fn api_key_by_prefix(&self, prefix: &str) -> StoreResult<Option<ApiKeyRecord>> {
        Ok(self
            .lock()
            .keys
            .values()
            .find(|k| k.prefix == prefix)
            .cloned())
    }

    fn api_key_list(&self, user_id: &str) -> StoreResult<Vec<ApiKeyRecord>> {
        let mut v: Vec<ApiKeyRecord> = self
            .lock()
            .keys
            .values()
            .filter(|k| k.user_id == user_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        Ok(v)
    }

    fn api_key_revoke(&self, user_id: &str, id: &str, at: i64) -> StoreResult<bool> {
        match self.lock().keys.get_mut(id) {
            Some(k) if k.user_id == user_id && k.revoked_at.is_none() => {
                k.revoked_at = Some(at);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn api_key_touch_last_used(&self, user_id: &str, id: &str, at: i64) -> StoreResult<()> {
        if let Some(k) = self.lock().keys.get_mut(id)
            && k.user_id == user_id
        {
            k.last_used_at = Some(at);
        }
        Ok(())
    }

    fn api_key_count_active(&self, user_id: &str, now: i64) -> StoreResult<u64> {
        Ok(self
            .lock()
            .keys
            .values()
            .filter(|k| k.user_id == user_id && k.revoked_at.is_none() && k.expires_at > now)
            .count() as u64)
    }

    fn instance_put(&self, i: &InstanceRecord) -> StoreResult<()> {
        let mut g = self.lock();
        if g.instances.contains_key(&i.alias) {
            return Err(StoreError::Duplicate);
        }
        g.instances.insert(i.alias.clone(), i.clone());
        Ok(())
    }

    fn instance_list(&self) -> StoreResult<Vec<InstanceRecord>> {
        Ok(self.lock().instances.values().cloned().collect())
    }

    fn instance_delete(&self, alias: &str) -> StoreResult<bool> {
        Ok(self.lock().instances.remove(alias).is_some())
    }

    fn anchor_append(
        &self,
        kind: &str,
        ts_utc: &str,
        body_jcs: &[u8],
        heads: &[AnchorHead],
        hash: AnchorHasher<'_>,
    ) -> StoreResult<AnchorRow> {
        let mut g = self.lock();
        let (seq, prev_hash) = match g.anchors.last() {
            None => (1, [0u8; 32]),
            Some(r) => (r.seq + 1, r.hash),
        };
        let row = AnchorRow {
            seq,
            ts_utc: ts_utc.to_owned(),
            kind: kind.to_owned(),
            body_jcs: body_jcs.to_vec(),
            prev_hash,
            hash: hash(seq, &prev_hash),
        };
        g.anchors.push(row.clone());
        g.heads.extend(heads.iter().map(|h| (seq, h.clone())));
        Ok(row)
    }

    fn anchor_all(&self) -> StoreResult<Vec<AnchorRow>> {
        Ok(self.lock().anchors.clone())
    }

    fn anchor_latest_heads(&self) -> StoreResult<Vec<AnchorHead>> {
        let mut latest: BTreeMap<String, AnchorHead> = BTreeMap::new();
        for (_, h) in &self.lock().heads {
            latest.insert(h.user_id.clone(), h.clone());
        }
        Ok(latest.into_values().collect())
    }

    fn snapshot_to(&self, _path: &std::path::Path) -> StoreResult<()> {
        Err(StoreError::Db("the memory store has no file".into()))
    }

    fn restore_from(&self, _path: &std::path::Path) -> StoreResult<()> {
        Err(StoreError::Db("the memory store has no file".into()))
    }

    fn anchor_last(&self) -> StoreResult<Option<AnchorRow>> {
        Ok(self.lock().anchors.last().cloned())
    }

    fn anchor_heads_for(&self, anchor_seq: u64) -> StoreResult<Vec<AnchorHead>> {
        Ok(self
            .lock()
            .heads
            .iter()
            .filter(|(s, _)| *s == anchor_seq)
            .map(|(_, h)| h.clone())
            .collect())
    }

    fn anchor_heads_for_chain(
        &self,
        chain_id: &str,
        upto_seq: u64,
    ) -> StoreResult<Vec<(u64, AnchorHead)>> {
        Ok(self
            .lock()
            .heads
            .iter()
            .filter(|(_, h)| h.chain_id == chain_id && h.head_seq <= upto_seq)
            .cloned()
            .collect())
    }
}

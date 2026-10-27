//! An in-memory `ServerStore` for unit tests (feature `testing`, never a release build). Same
//! contract as the SQLite store, checked by the shared conformance tests.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use super::{
    AccessRecord, AnchorHasher, AnchorHead, AnchorRow, ApiKeyRecord, CLIENT_ENDED_SECS,
    CLIENT_UNUSED_SECS, CodeRecord, ConsentRequestRecord, ExportJobRecord, GrantRecord,
    InstanceRecord, OAuthClientRecord, PatRecord, Redeem, RefreshRecord, Rotate, Sealed,
    ServerStore, SessionRecord, StoreError, StoreResult, UserRecord,
};

#[derive(Default)]
struct Inner {
    users: BTreeMap<String, UserRecord>,
    keystore: BTreeMap<(String, String), Sealed>,
    pats: BTreeMap<(String, String), PatRecord>,
    sessions: BTreeMap<[u8; 32], SessionRecord>,
    keys: BTreeMap<String, ApiKeyRecord>,
    instances: BTreeMap<String, InstanceRecord>,
    anchors: Vec<AnchorRow>,
    heads: Vec<(u64, AnchorHead)>,
    clients: BTreeMap<String, OAuthClientRecord>,
    consents: BTreeMap<[u8; 32], ConsentRequestRecord>,
    grants: BTreeMap<String, GrantRecord>,
    codes: BTreeMap<[u8; 32], CodeRecord>,
    access: BTreeMap<[u8; 32], AccessRecord>,
    refresh: BTreeMap<[u8; 32], RefreshRecord>,
    jobs: BTreeMap<String, ExportJobRecord>,
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

    fn oauth_client_insert(&self, c: &OAuthClientRecord) -> StoreResult<()> {
        let mut g = self.lock();
        if g.clients.contains_key(&c.client_id) {
            return Err(StoreError::Duplicate);
        }
        g.clients.insert(c.client_id.clone(), c.clone());
        Ok(())
    }

    fn oauth_client_get(&self, client_id: &str) -> StoreResult<Option<OAuthClientRecord>> {
        Ok(self.lock().clients.get(client_id).cloned())
    }

    fn oauth_client_count(&self) -> StoreResult<u64> {
        Ok(self.lock().clients.len() as u64)
    }

    fn oauth_purge(&self, now: i64) -> StoreResult<u64> {
        let mut g = self.lock();
        let stale: Vec<String> = g
            .clients
            .values()
            .filter(|c| {
                let grants: Vec<&GrantRecord> = g
                    .grants
                    .values()
                    .filter(|x| x.client_id == c.client_id)
                    .collect();
                if grants.is_empty() {
                    return c.created_at <= now - CLIENT_UNUSED_SECS;
                }
                let any_live = grants
                    .iter()
                    .any(|x| x.revoked_at.is_none() && x.expires_at > now);
                let last_end = grants
                    .iter()
                    .map(|x| x.revoked_at.unwrap_or(x.expires_at).min(x.expires_at))
                    .max()
                    .unwrap_or(i64::MAX);
                !any_live && last_end <= now - CLIENT_ENDED_SECS
            })
            .map(|c| c.client_id.clone())
            .collect();
        for id in &stale {
            let gone: Vec<String> = g
                .grants
                .values()
                .filter(|x| &x.client_id == id)
                .map(|x| x.grant_id.clone())
                .collect();
            g.codes.retain(|_, c| !gone.contains(&c.grant_id));
            g.access.retain(|_, a| !gone.contains(&a.grant_id));
            g.refresh.retain(|_, r| !gone.contains(&r.grant_id));
            g.grants.retain(|_, x| &x.client_id != id);
            g.consents.retain(|_, r| &r.client_id != id);
            g.clients.remove(id);
        }
        g.consents.retain(|_, r| r.expires_at > now);
        g.codes.retain(|_, c| c.expires_at > now);
        g.access.retain(|_, a| a.expires_at > now);
        let ended: Vec<String> = g
            .grants
            .values()
            .filter(|x| x.revoked_at.is_some() || x.expires_at <= now)
            .map(|x| x.grant_id.clone())
            .collect();
        g.refresh.retain(|_, r| !ended.contains(&r.grant_id));
        Ok(stale.len() as u64)
    }

    fn consent_put(&self, r: &ConsentRequestRecord) -> StoreResult<()> {
        let mut g = self.lock();
        if g.consents.contains_key(&r.id_hash) {
            return Err(StoreError::Duplicate);
        }
        g.consents.insert(r.id_hash, r.clone());
        Ok(())
    }

    fn consent_get(
        &self,
        id_hash: &[u8; 32],
        session_hash: &[u8; 32],
    ) -> StoreResult<Option<ConsentRequestRecord>> {
        Ok(self
            .lock()
            .consents
            .get(id_hash)
            .filter(|r| &r.session_hash == session_hash)
            .cloned())
    }

    fn consent_take(
        &self,
        id_hash: &[u8; 32],
        session_hash: &[u8; 32],
    ) -> StoreResult<Option<ConsentRequestRecord>> {
        let mut g = self.lock();
        if g.consents
            .get(id_hash)
            .is_some_and(|r| &r.session_hash == session_hash)
        {
            return Ok(g.consents.remove(id_hash));
        }
        Ok(None)
    }

    fn grant_insert(&self, x: &GrantRecord) -> StoreResult<()> {
        let mut g = self.lock();
        if g.grants.contains_key(&x.grant_id) {
            return Err(StoreError::Duplicate);
        }
        g.grants.insert(x.grant_id.clone(), x.clone());
        Ok(())
    }

    fn grant_get(&self, grant_id: &str) -> StoreResult<Option<GrantRecord>> {
        Ok(self.lock().grants.get(grant_id).cloned())
    }

    fn grant_list(&self, user_id: &str) -> StoreResult<Vec<GrantRecord>> {
        let mut v: Vec<GrantRecord> = self
            .lock()
            .grants
            .values()
            .filter(|x| x.user_id == user_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.grant_id.cmp(&b.grant_id))
        });
        Ok(v)
    }

    fn grant_revoke(&self, grant_id: &str, reason: &str, at: i64) -> StoreResult<bool> {
        match self.lock().grants.get_mut(grant_id) {
            Some(x) if x.revoked_at.is_none() => {
                x.revoked_at = Some(at);
                x.revoke_reason = Some(reason.to_owned());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn grant_revoke_all(
        &self,
        user_id: &str,
        reason: &str,
        at: i64,
    ) -> StoreResult<Vec<GrantRecord>> {
        let mut out: Vec<GrantRecord> = Vec::new();
        for x in self.lock().grants.values_mut() {
            if x.user_id == user_id && x.revoked_at.is_none() {
                x.revoked_at = Some(at);
                x.revoke_reason = Some(reason.to_owned());
                out.push(x.clone());
            }
        }
        out.sort_by(|a, b| (a.created_at, &a.grant_id).cmp(&(b.created_at, &b.grant_id)));
        Ok(out)
    }

    fn grant_touch(&self, grant_id: &str, at: i64) -> StoreResult<()> {
        if let Some(x) = self.lock().grants.get_mut(grant_id) {
            x.last_used_at = Some(at);
        }
        Ok(())
    }

    fn code_insert(&self, c: &CodeRecord) -> StoreResult<()> {
        let mut g = self.lock();
        if g.codes.contains_key(&c.hash) {
            return Err(StoreError::Duplicate);
        }
        g.codes.insert(c.hash, c.clone());
        Ok(())
    }

    fn code_redeem(&self, hash: &[u8; 32], now: i64) -> Result<(CodeRecord, GrantRecord), Redeem> {
        let mut g = self.lock();
        let Some(code) = g.codes.get_mut(hash) else {
            return Err(Redeem::Unknown);
        };
        if code.redeemed_at.is_some() {
            return Err(Redeem::Reused(code.grant_id.clone()));
        }
        code.redeemed_at = Some(now);
        let code = code.clone();
        if now >= code.expires_at {
            return Err(Redeem::Expired);
        }
        let grant = g
            .grants
            .get(&code.grant_id)
            .cloned()
            .ok_or(Redeem::Unknown)?;
        Ok((code, grant))
    }

    fn access_insert(&self, a: &AccessRecord) -> StoreResult<()> {
        let mut g = self.lock();
        if g.access.contains_key(&a.hash) {
            return Err(StoreError::Duplicate);
        }
        g.access.insert(a.hash, a.clone());
        Ok(())
    }

    fn access_get(&self, hash: &[u8; 32]) -> StoreResult<Option<AccessRecord>> {
        Ok(self.lock().access.get(hash).cloned())
    }

    fn refresh_insert(&self, r: &RefreshRecord) -> StoreResult<()> {
        let mut g = self.lock();
        if g.refresh.contains_key(&r.hash) {
            return Err(StoreError::Duplicate);
        }
        g.refresh.insert(r.hash, r.clone());
        Ok(())
    }

    fn refresh_rotate(
        &self,
        hash: &[u8; 32],
        new: &RefreshRecord,
        now: i64,
        idle_secs: i64,
    ) -> Result<GrantRecord, Rotate> {
        let mut g = self.lock();
        let Some(old) = g.refresh.get(hash).cloned() else {
            return Err(Rotate::Unknown);
        };
        if old.rotated_at.is_some() {
            return Err(Rotate::Reused(old.grant_id));
        }
        let grant = g
            .grants
            .get(&old.grant_id)
            .cloned()
            .ok_or(Rotate::Unknown)?;
        if !grant.live(now) || now - old.last_used_at >= idle_secs || new.grant_id != grant.grant_id
        {
            return Err(Rotate::Expired);
        }
        if g.refresh.contains_key(&new.hash) {
            return Err(Rotate::Store(StoreError::Duplicate));
        }
        if let Some(o) = g.refresh.get_mut(hash) {
            o.rotated_at = Some(now);
        }
        g.refresh.insert(new.hash, new.clone());
        Ok(grant)
    }

    fn refresh_grant(&self, hash: &[u8; 32]) -> StoreResult<Option<String>> {
        Ok(self.lock().refresh.get(hash).map(|r| r.grant_id.clone()))
    }

    fn export_job_insert(&self, j: &ExportJobRecord) -> StoreResult<()> {
        let mut g = self.lock();
        if g.jobs.contains_key(&j.job_id) {
            return Err(StoreError::Duplicate);
        }
        g.jobs.insert(j.job_id.clone(), j.clone());
        Ok(())
    }

    fn export_job_get(&self, job_id: &str) -> StoreResult<Option<ExportJobRecord>> {
        Ok(self.lock().jobs.get(job_id).cloned())
    }

    fn export_job_update(&self, j: &ExportJobRecord) -> StoreResult<()> {
        if let Some(x) = self.lock().jobs.get_mut(&j.job_id) {
            x.state = j.state.clone();
            x.expires_at = j.expires_at;
            x.manifest_sha256 = j.manifest_sha256.clone();
            x.size = j.size;
            x.file_name = j.file_name.clone();
        }
        Ok(())
    }

    fn export_jobs_running(&self) -> StoreResult<Vec<ExportJobRecord>> {
        let mut v: Vec<ExportJobRecord> = self
            .lock()
            .jobs
            .values()
            .filter(|j| j.state == "running")
            .cloned()
            .collect();
        v.sort_by_key(|j| j.created_at);
        Ok(v)
    }

    fn export_jobs_expired(&self, now: i64) -> StoreResult<Vec<ExportJobRecord>> {
        let mut v: Vec<ExportJobRecord> = self
            .lock()
            .jobs
            .values()
            .filter(|j| j.expires_at <= now)
            .cloned()
            .collect();
        v.sort_by_key(|j| j.created_at);
        Ok(v)
    }

    fn export_job_delete(&self, job_id: &str) -> StoreResult<bool> {
        Ok(self.lock().jobs.remove(job_id).is_some())
    }
}

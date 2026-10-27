//! User ids and the per-user data layout (PD-199): `user_id` = the first 32 lowercase hex chars
//! of `SHA-256("atlas-duck/user/v1\0" || lowercase(username))`, stable, path-safe and not a
//! username; `<data>/users/<user_id>/` holds the user's M2 store.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::master_key::{MasterKey, SecretKey};
use crate::store::{ServerStore, StoreError, UserRecord};

const USER_ID_DOMAIN: &[u8] = b"atlas-duck/user/v1\0";

/// PD-199: `^[A-Za-z0-9._-]{1,64}$`, checked before any bind (no DN/UPN injection).
pub fn valid_username(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// The canonical (lowercase) form of a valid username.
pub fn canonical(username: &str) -> String {
    username.to_ascii_lowercase()
}

pub fn user_id_for(username: &str) -> String {
    let mut h = Sha256::new();
    h.update(USER_ID_DOMAIN);
    h.update(canonical(username).as_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..16])
}

/// `<data>/users/<user_id>`.
/// Is the user active (M14 seam for M13's deactivation)? Until M13's schema v2 merges this means
/// "the user row exists"; at merge it also reads `deactivated_at` (T7 consent, T8 bearer, T17).
pub fn is_active(store: &dyn crate::store::ServerStore, user_id: &str) -> bool {
    matches!(store.user(user_id), Ok(Some(_)))
}

pub fn user_dir(data: &Path, user_id: &str) -> PathBuf {
    data.join("users").join(user_id)
}

#[derive(Debug)]
pub enum EnsureError {
    Store(StoreError),
    Key,
}

/// Creates the user on first login (a fresh data key wrapped by the master key) or refreshes
/// the display name and roles (SM-2.3: re-read at every login). Answers the row and whether it
/// was created now.
pub fn ensure_user(
    store: &dyn ServerStore,
    master: &MasterKey,
    username: &str,
    display_name: Option<String>,
    roles: Vec<String>,
    now: i64,
) -> Result<(UserRecord, bool), EnsureError> {
    let username = canonical(username);
    let user_id = user_id_for(&username);
    let existing = store.user(&user_id).map_err(EnsureError::Store)?;
    let created = existing.is_none();
    let record = match existing {
        Some(mut u) => {
            u.display_name = display_name;
            u.roles = roles;
            u
        }
        None => {
            let dk = SecretKey::random().map_err(|_| EnsureError::Key)?;
            let wrapped = master.wrap(&user_id, &dk).map_err(|_| EnsureError::Key)?;
            UserRecord {
                user_id,
                username,
                display_name,
                roles,
                data_key_wrapped: wrapped.to_json(),
                created_at: now,
            }
        }
    };
    store.upsert_user(&record).map_err(EnsureError::Store)?;
    Ok((record, created))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::master_key::WrappedKey;
    use crate::store::memory::MemoryStore;

    #[test]
    fn user_id_is_stable_case_insensitive_and_path_safe() {
        let a = user_id_for("Alice");
        assert_eq!(a, user_id_for("alice"));
        assert_eq!(a.len(), 32);
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_ne!(a, user_id_for("alice2"));
        let mut h = Sha256::new();
        h.update(b"atlas-duck/user/v1\0alice");
        assert_eq!(a, hex::encode(&h.finalize()[..16]));
    }

    #[test]
    fn username_shape() {
        for ok in ["alice", "a.b-c_d", "A1", &"x".repeat(64)] {
            assert!(valid_username(ok), "{ok}");
        }
        for bad in [
            "",
            "a b",
            "a@b",
            "a*",
            "a)(",
            "jürgen",
            "a\0",
            &"x".repeat(65),
            "cn=x,dc=y",
        ] {
            assert!(!valid_username(bad), "{bad}");
        }
    }

    #[test]
    fn ensure_user_creates_once_then_refreshes_roles() {
        let s = MemoryStore::new();
        let mk = MasterKey::for_tests("k1", [3; 32]);
        let (u, created) = ensure_user(&s, &mk, "Alice", None, vec!["user".into()], 10).unwrap();
        assert!(created);
        assert_eq!(u.username, "alice");
        let w = WrappedKey::from_json(&u.data_key_wrapped).unwrap();
        assert!(mk.unwrap(&u.user_id, &w).is_ok());
        let (again, created) = ensure_user(
            &s,
            &mk,
            "alice",
            Some("Alice A".into()),
            vec!["user".into(), "admin".into()],
            20,
        )
        .unwrap();
        assert!(!created);
        assert_eq!(
            again.data_key_wrapped, u.data_key_wrapped,
            "the data key is kept"
        );
        assert_eq!(again.roles, ["user", "admin"]);
        assert_eq!(again.created_at, 10);
    }
}

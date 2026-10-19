//! "Change recovery passphrase" (§8.6, PD-169): the KEK in memory is sealed again under the new
//! passphrase (Argon2id, recovery layout 1), the blob is opened with the second entry and
//! compared before anything is written, and the `recovery` row and its `CREDENTIAL_CHANGED
//! {change: recovery_passphrase}` commit in one writer transaction, so neither exists without the
//! other. The two Argon2id runs (64 MiB each) happen on the caller's thread and never hold up
//! appends; the writer only checks that the blob seals the KEK still in force.

use std::collections::HashMap;
use std::sync::atomic::Ordering;

use rusqlite::TransactionBehavior;
use secrecy::SecretString;
use serde_json::json;

use crate::crypto::Kek;
use crate::error::{AuditError, OpenError};
use crate::recovery::{
    RECOVERY_BLOB_LEN, RECOVERY_LAYOUT, check_new_passphrase, new_recovery_blob, recovery_layout,
};
use crate::store::Store;
use crate::types::{Committed, EventType};
use crate::writer::{Cmd, PreparedEvent, Writer, lock, sql, ts_text};

/// `Invalid` text: the new recovery passphrase is shorter than `MIN_PASSPHRASE_CHARS`.
pub const PASSPHRASE_TOO_SHORT: &str = "the new recovery passphrase is too short";
/// `Invalid` text: the two entries of the new recovery passphrase differ (after NFC).
pub const PASSPHRASE_MISMATCH: &str = "the two entries of the new recovery passphrase differ";

/// `CREDENTIAL_CHANGED.change` of this change; `append` refuses it (store-owned).
pub(crate) const RECOVERY_PASSPHRASE_CHANGE: &str = "recovery_passphrase";

fn open_err(e: OpenError) -> AuditError {
    match e {
        OpenError::PassphraseTooShort => AuditError::Invalid(PASSPHRASE_TOO_SHORT),
        OpenError::PassphraseMismatch => AuditError::Invalid(PASSPHRASE_MISMATCH),
        other => AuditError::Io(other.to_string()),
    }
}

/// `Store::change_recovery_passphrase`.
pub(crate) fn change(
    store: &Store,
    new: &SecretString,
    new_confirm: &SecretString,
) -> Result<Committed, AuditError> {
    store.ensure_open()?;
    // The pure rules first (length, NFC equality), before 64 MiB are spent on a derivation.
    check_new_passphrase(new, new_confirm).map_err(open_err)?;
    // The generation before the KEK: a restore after this read is refused on the writer.
    let generation = store.generation();
    let kek = store.current_kek();
    let blob = new_recovery_blob(new, new_confirm, &kek).map_err(open_err)?;
    let mut event = PreparedEvent::system(
        EventType::CREDENTIAL_CHANGED,
        &json!({ "change": RECOVERY_PASSPHRASE_CHANGE }),
    )?;
    event.for_generation = Some(generation);
    store.writer_call(|reply| Cmd::ChangeRecoveryPassphrase {
        blob,
        kek,
        event: Box::new(event),
        reply,
    })
}

impl Writer {
    /// The writer half: refuses a blob made before a restore replaced the store (its generation)
    /// or sealed for another KEK than the one in force, then one transaction: the `recovery` row
    /// rewritten, `event` appended. On any error both roll back and the in-memory clock state and
    /// head are restored.
    pub(crate) fn change_recovery_run(
        &mut self,
        blob: &[u8],
        kek: &Kek,
        event: &PreparedEvent,
    ) -> Result<Committed, AuditError> {
        let generation = self.st.shared.generation.load(Ordering::SeqCst);
        if event.for_generation != Some(generation) || *kek != lock(&self.st.shared.keys).kek {
            return Err(AuditError::Invalid(
                "the store was restored while the passphrase was changed; nothing was written",
            ));
        }
        if blob.len() != RECOVERY_BLOB_LEN || recovery_layout(blob) != Some(RECOVERY_LAYOUT) {
            return Err(AuditError::Invalid("the new recovery blob is malformed"));
        }
        let snapshot = (self.st.clock_state.clone(), self.st.head.clone());
        let mut new_keys = HashMap::new();
        let st = &mut self.st;
        let result = (|| -> Result<Committed, AuditError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql)?;
            let created_at = ts_text(st.clock.now_utc())?;
            let n = tx
                .execute(
                    "UPDATE recovery SET blob = ?1, created_at = ?2 WHERE id = 1",
                    rusqlite::params![blob, created_at],
                )
                .map_err(sql)?;
            if n != 1 {
                return Err(AuditError::AppendFailed(
                    "the store has no recovery row".into(),
                ));
            }
            #[cfg(any(test, feature = "testing"))]
            st.hooks
                .fault(crate::testing::FaultPoint::RecoveryRowWritten)?;
            let c = st.append_in_tx(&tx, event, &mut new_keys)?;
            tx.commit().map_err(sql)?;
            Ok(c)
        })();
        match &result {
            Ok(_) => self.st.post_commit(new_keys, &[]),
            Err(_) => (self.st.clock_state, self.st.head) = snapshot,
        }
        result
    }
}

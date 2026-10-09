//! `StubConfirmer` (C.7 `core::testing`): scripted answers for the native confirmation seam.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::core::{Confirm, NativeConfirmer};

/// Runs inside `confirm`, on the dialog's thread, before the answer is popped (e.g. a request
/// expiring while the dialog is open, or a slow user).
pub type ConfirmHook = Arc<dyn Fn(&str) + Send + Sync>;

/// Pops one scripted answer per dialog (an empty script answers `Cancel`, the safe default) and
/// records every dialog text it was shown.
#[derive(Default)]
pub struct StubConfirmer {
    answers: Mutex<VecDeque<Confirm>>,
    texts: Mutex<Vec<String>>,
    hook: Mutex<Option<ConfirmHook>>,
}

impl std::fmt::Debug for StubConfirmer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StubConfirmer")
            .field("answers", &self.answers)
            .field("texts", &self.texts)
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl StubConfirmer {
    pub fn new(answers: Vec<Confirm>) -> StubConfirmer {
        StubConfirmer {
            answers: Mutex::new(answers.into()),
            texts: Mutex::new(Vec::new()),
            hook: Mutex::new(None),
        }
    }

    /// Queues more answers.
    pub fn push(&self, answer: Confirm) {
        lock(&self.answers).push_back(answer);
    }

    /// Every dialog text shown so far, in order.
    pub fn texts(&self) -> Vec<String> {
        lock(&self.texts).clone()
    }

    /// Runs `hook` in every later `confirm` call while the dialog is "open".
    pub fn set_hook(&self, hook: ConfirmHook) {
        *lock(&self.hook) = Some(hook);
    }
}

impl NativeConfirmer for StubConfirmer {
    fn confirm(&self, text: &str) -> Confirm {
        lock(&self.texts).push(text.to_owned());
        let hook = lock(&self.hook).clone();
        if let Some(h) = hook {
            h(text);
        }
        lock(&self.answers).pop_front().unwrap_or(Confirm::Cancel)
    }
}

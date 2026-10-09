//! `StubConfirmer` (C.7 `core::testing`): scripted answers for the native confirmation seam.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::core::{Confirm, NativeConfirmer};

/// Pops one scripted answer per dialog (an empty script answers `Cancel`, the safe default) and
/// records every dialog text it was shown.
#[derive(Debug, Default)]
pub struct StubConfirmer {
    answers: Mutex<VecDeque<Confirm>>,
    texts: Mutex<Vec<String>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl StubConfirmer {
    pub fn new(answers: Vec<Confirm>) -> StubConfirmer {
        StubConfirmer {
            answers: Mutex::new(answers.into()),
            texts: Mutex::new(Vec::new()),
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
}

impl NativeConfirmer for StubConfirmer {
    fn confirm(&self, text: &str) -> Confirm {
        lock(&self.texts).push(text.to_owned());
        lock(&self.answers).pop_front().unwrap_or(Confirm::Cancel)
    }
}

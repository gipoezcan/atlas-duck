//! M3 PD-13: the synchronous `DecisionApi` / `InstanceAdmin` calls run on the blocking pool, never
//! on the main thread or an async worker.

use super::CommandError;

/// Runs `f` on the blocking pool and returns its result; a task that panicked or was cancelled is
/// `CommandError::Internal` (its payload is never reported).
pub async fn blocking<T, F>(f: F) -> Result<T, CommandError>
where
    F: FnOnce() -> Result<T, CommandError> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|_| CommandError::Internal)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_results_through_and_maps_a_panic_to_internal() {
        let ok = tauri::async_runtime::block_on(blocking(|| Ok::<_, CommandError>(7)));
        assert_eq!(ok, Ok(7));
        let err = tauri::async_runtime::block_on(blocking(|| {
            Err::<u8, _>(CommandError::InvalidArgument { field: "x" })
        }));
        assert_eq!(err, Err(CommandError::InvalidArgument { field: "x" }));
        let panicked = tauri::async_runtime::block_on(blocking(|| -> Result<u8, CommandError> {
            panic!("boom")
        }));
        assert_eq!(panicked, Err(CommandError::Internal));
    }

    #[test]
    fn runs_off_the_calling_thread() {
        let caller = std::thread::current().id();
        let ran_on = tauri::async_runtime::block_on(blocking(|| Ok(std::thread::current().id())));
        assert!(matches!(ran_on, Ok(id) if id != caller));
    }
}

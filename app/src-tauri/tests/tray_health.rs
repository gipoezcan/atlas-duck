//! T36b item 1 (T21b review M-1, §8.5 "Settings and the tray"): the tray's store-health lines come
//! from a snapshot of the `StoreHealthView` kept in `AppState`, filled where the app reads the health
//! and never read from the store by the tray. A mock-runtime test, so an integration test (only
//! those executables get the Common-Controls v6 manifest the mock runtime needs on Windows).

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use atlas_duck_app_lib::state::{AppState, StartupSummary};
use atlas_duck_app_lib::status::{self, StatusInputs};
use atlas_duck_core::StoreHealthView;
use tauri::Manager;

fn health() -> StoreHealthView {
    StoreHealthView {
        storage_low: false,
        anchor_write_failing: false,
        anchor_thread_dead: false,
        anchors_blocked: false,
        open_incidents: 0,
        prune_backlog_days: 0,
        prune_backlog: None,
        last_prune_failed: false,
        shred_checkpoint_pending: false,
        settings_unreadable: false,
        anchor_dir_write_failing: false,
        anchor_dir_lines_pending: 0,
        anchors_missing: None,
        re_anchor_offered: false,
    }
}

/// Nothing happens in a window to tell the tray the store's health changed (an anchor write that
/// starts failing, storage running low), so while the core serves the app re-reads it on a timer, on
/// the blocking pool, and the tray follows. Here no core serves, so each tick finds no health and
/// drops the snapshot: the tray rebuilds. The ticker ends with the quit signal.
#[test]
fn the_health_ticker_refreshes_the_snapshot_and_ends_with_quit() {
    use std::time::Duration;

    use atlas_duck_app_lib::state::ServeSlot;

    let app = tauri::test::mock_app();
    let handle = app.handle().clone();
    handle.manage(AppState::new(StartupSummary::Ready, None));
    handle.manage(ServeSlot::default());
    let rebuilds = Arc::new(AtomicU32::new(0));
    let counter = rebuilds.clone();
    handle.state::<AppState>().set_tray_refresh(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    let stale = StoreHealthView {
        storage_low: true,
        ..health()
    };
    assert!(status::note_health(&handle, Some(stale)));
    assert_eq!(rebuilds.load(Ordering::SeqCst), 1);

    let ticker = status::spawn_health_ticker(handle.clone(), Duration::from_millis(20));
    let start = std::time::Instant::now();
    while rebuilds.load(Ordering::SeqCst) < 2 {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the ticker never refreshed the snapshot"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(handle.state::<AppState>().health(), None);
    // Nothing changes on later ticks: no more rebuilds.
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(rebuilds.load(Ordering::SeqCst), 2);

    handle.state::<ServeSlot>().quit().cancel();
    tauri::async_runtime::block_on(async {
        tokio::time::timeout(Duration::from_secs(10), ticker)
            .await
            .expect("the ticker ends with the quit signal")
    })
    .expect("the ticker task");
}

/// The core-free gather (what the tray calls on the main thread) copies the cached snapshot and
/// never reads the store; the header's `gather` has no serving core here, so it shows no health and
/// drops the snapshot (a stale snapshot of a locked or quitting app is not shown). The tray rebuild
/// the app registered at startup runs after a change, and only then.
#[test]
fn the_core_free_gather_reads_the_cached_health() {
    let app = tauri::test::mock_app();
    let handle = app.handle().clone();
    handle.manage(AppState::new(StartupSummary::Ready, None));
    assert_eq!(
        status::gather_gate(&handle).health,
        None,
        "nothing cached yet"
    );

    let rebuilds = Arc::new(AtomicU32::new(0));
    let counter = rebuilds.clone();
    handle.state::<AppState>().set_tray_refresh(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    let rebuilt = || rebuilds.load(Ordering::SeqCst);

    let h = StoreHealthView {
        storage_low: true,
        ..health()
    };
    assert!(status::note_health(&handle, Some(h.clone())), "a change");
    assert_eq!(rebuilt(), 1);
    assert!(
        !status::note_health(&handle, Some(h.clone())),
        "the same snapshot"
    );
    assert_eq!(rebuilt(), 1, "no rebuild without a change");
    assert_eq!(status::gather_gate(&handle).health, Some(h.clone()));

    // No serving core to read: the header's gather shows no health and drops the snapshot.
    assert_eq!(status::gather(&handle).health, None);
    assert_eq!(
        status::gather_gate(&handle).health,
        None,
        "the snapshot is dropped"
    );
    assert_eq!(rebuilt(), 2, "dropping it changes the tray too");

    assert!(status::note_health(&handle, Some(h)));
    // The snapshot is the one the status lines are built from.
    let inputs = StatusInputs {
        health: status::gather_gate(&handle).health,
        ..StatusInputs::default()
    };
    let ids: Vec<&str> = status::lines(&inputs).iter().map(|l| l.id).collect();
    assert_eq!(ids, ["storage_low"]);
    assert!(status::note_health(&handle, None), "cleared");
    assert_eq!(status::gather_gate(&handle).health, None);
    assert_eq!(rebuilt(), 4);
}

//! What a waiting tool call tells its client (PD-125) and the wait a client's cancel ends
//! (PD-126).
//!
//! Only a call that carries `_meta.progressToken` hears anything: "submitted" once the submit is
//! answered `pending`, each status change the app relays (once per tool call), and heartbeats
//! without a message on a fixed timer from the call's receipt, which nothing the app sends moves
//! (§4.5). A notification is sent whole before the next one and before the result: `notify` ends
//! once rmcp handed the line to the transport, and the wait awaits it. So `progress` rises in
//! wire order and nothing follows the response (MCP forbids it).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use atlas_duck_ipc::envelope::Status;
use atlas_duck_ipc::proto::ProgressNotification;
use rmcp::model::{ProgressNotificationParam, ProgressToken};
use rmcp::{Peer, RoleServer};
use tokio::sync::mpsc;
use tokio::time::{Instant, Interval, MissedTickBehavior, interval_at};

use super::server::SendFuture;

/// PD-125 (R11): the heartbeat period of a waiting tool call (the rig sets a short one).
pub(crate) const HEARTBEAT_EVERY: Duration = Duration::from_secs(5);

/// Where notifications go: the call's rmcp peer (a recording fake in the tests).
pub(crate) trait ProgressPeer: Send + Sync {
    /// Sends one notification; ends once it was handed to the transport.
    fn notify(&self, p: ProgressNotificationParam) -> SendFuture<'_, ()>;
}

impl ProgressPeer for Peer<RoleServer> {
    fn notify(&self, p: ProgressNotificationParam) -> SendFuture<'_, ()> {
        Box::pin(async move {
            // A transport that is gone (stdin EOF) takes the result with it; nothing to report.
            let _ = self.notify_progress(p).await;
        })
    }
}

/// The notifications of one tool call.
pub(crate) struct Progress {
    /// `None`: the call asked for none, and nothing is sent.
    token: Option<ProgressToken>,
    /// The `progress` of the last notification: the first one carries 1 (MCP: increasing).
    counter: u32,
    /// The last status relayed. The server sends `request.progress` once per await, so two
    /// awaits of one id on the shared connection each get both copies (Δ1): a repeat is dropped.
    last_status: Option<Status>,
    peer: Arc<dyn ProgressPeer>,
    /// The IPC call's progress callback runs inside the call's future, which the wait polls; it
    /// hands each change over here.
    changes_in: mpsc::UnboundedSender<ProgressNotification>,
    changes: mpsc::UnboundedReceiver<ProgressNotification>,
}

impl Progress {
    pub(crate) fn new(token: Option<ProgressToken>, peer: Arc<dyn ProgressPeer>) -> Progress {
        let (changes_in, changes) = mpsc::unbounded_channel();
        Progress {
            token,
            counter: 0,
            last_status: None,
            peer,
            changes_in,
            changes,
        }
    }

    /// The `on_progress` callback of `SharedClient::call_with_progress`.
    pub(crate) fn relay(&self) -> impl FnMut(ProgressNotification) + Send + 'static {
        let changes = self.changes_in.clone();
        move |n| {
            // The receiver lives as long as `self`; a change after the wait is moot.
            let _ = changes.send(n);
        }
    }

    /// The submit was answered `pending` with this id (§4.6: "immediately after submit").
    pub(crate) async fn submitted(&mut self, request_id: &str) {
        self.last_status = Some(Status::Pending);
        self.send(Some(format!(
            "submitted request_id={request_id} status=pending"
        )))
        .await;
    }

    /// A status change the app relayed; a repeat of the last one is dropped.
    async fn status(&mut self, n: ProgressNotification) {
        if self.last_status == Some(n.status) {
            return;
        }
        self.last_status = Some(n.status);
        let message = format!("request_id={} status={}", n.request_id, wire_name(n.status));
        self.send(Some(message)).await;
    }

    /// A heartbeat: no message.
    async fn heartbeat(&mut self) {
        self.send(None).await;
    }

    async fn send(&mut self, message: Option<String>) {
        let Some(token) = self.token.clone() else {
            return;
        };
        self.counter = self.counter.saturating_add(1);
        let mut p = ProgressNotificationParam::new(token, f64::from(self.counter));
        p.message = message;
        self.peer.notify(p).await;
    }
}

/// A status as the envelope spells it (`executing`, not `Executing`).
fn wire_name(status: Status) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

enum Step<T> {
    Cancelled,
    Beat,
    Change(ProgressNotification),
    Done(T),
}

/// Waits for `fut` and relays its progress: the status changes `progress.relay()` hands over and,
/// only with a progress token, heartbeats on `interval_at(receipt + every, every)` (the first one
/// period after receipt, never at once; late ticks delay the next). `None`: `cancelled` came
/// first (a client's `notifications/cancelled`, or stdin EOF); `fut` is dropped and nothing more
/// is sent. `Some`: the timer is gone before the output is returned, and the changes that came
/// with the answer are relayed first, so no notification follows the result.
pub(crate) async fn wait_with_progress<F: Future>(
    fut: F,
    progress: &mut Progress,
    receipt: Instant,
    every: Duration,
    cancelled: impl Future<Output = ()>,
) -> Option<F::Output> {
    tokio::pin!(fut);
    tokio::pin!(cancelled);
    let mut timer = progress.token.is_some().then(|| {
        let mut timer = interval_at(receipt + every, every);
        timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        timer
    });
    let out = loop {
        let step = tokio::select! {
            biased;
            () = &mut cancelled => Step::Cancelled,
            () = tick(&mut timer) => Step::Beat,
            Some(n) = progress.changes.recv() => Step::Change(n),
            out = &mut fut => Step::Done(out),
        };
        let sent = match step {
            Step::Cancelled => return None,
            Step::Done(out) => break out,
            Step::Beat => unless(&mut cancelled, progress.heartbeat()).await,
            Step::Change(n) => unless(&mut cancelled, progress.status(n)).await,
        };
        if !sent {
            return None;
        }
    };
    drop(timer);
    while let Ok(n) = progress.changes.try_recv() {
        progress.status(n).await;
    }
    Some(out)
}

/// The next tick; never without a timer.
async fn tick(timer: &mut Option<Interval>) {
    match timer {
        Some(timer) => {
            timer.tick().await;
        }
        None => std::future::pending().await,
    }
}

/// `send` to its end, unless `cancelled` comes first (`false`).
async fn unless<C: Future<Output = ()>>(
    cancelled: &mut Pin<&mut C>,
    send: impl Future<Output = ()>,
) -> bool {
    tokio::select! {
        biased;
        () = cancelled.as_mut() => false,
        () = send => true,
    }
}

#[cfg(test)]
mod tests {
    //! Timer tests on a paused clock over fake futures and a recording peer only: no rig, no
    //! transport, no IO (Global Constraints "Tests").

    #![allow(clippy::unwrap_used, clippy::expect_used)]

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use rmcp::model::NumberOrString;
    use tokio::sync::oneshot;
    use tokio::time::sleep_until;

    use super::*;

    const ID: &str = "req_00000000000000000000000000000001";

    /// Records each notification with the (paused) time it was sent.
    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Vec<(Instant, ProgressNotificationParam)>>,
    }

    impl Recorder {
        fn sent(&self) -> Vec<(Instant, ProgressNotificationParam)> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl ProgressPeer for Recorder {
        fn notify(&self, p: ProgressNotificationParam) -> SendFuture<'_, ()> {
            self.sent.lock().unwrap().push((Instant::now(), p));
            Box::pin(async {})
        }
    }

    fn token() -> ProgressToken {
        ProgressToken(NumberOrString::Number(7))
    }

    fn change(status: Status) -> ProgressNotification {
        ProgressNotification {
            request_id: ID.to_owned(),
            status,
        }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// `fut`, or a failed test: a stalled wait leaves a paused runtime nothing to advance to,
    /// so without this bound it would park for ever.
    async fn bounded<T>(fut: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(600), fut)
            .await
            .expect("the wait never ended")
    }

    /// Offsets from `receipt` of the notifications without a message.
    fn beats(sent: &[(Instant, ProgressNotificationParam)], receipt: Instant) -> Vec<Duration> {
        sent.iter()
            .filter(|(_, p)| p.message.is_none())
            .map(|(at, _)| *at - receipt)
            .collect()
    }

    fn counters(sent: &[(Instant, ProgressNotificationParam)]) -> Vec<f64> {
        sent.iter().map(|(_, p)| p.progress).collect()
    }

    /// Heartbeats at receipt + 5, 10, 15 s and none at receipt; status changes at irregular
    /// times (one at a tick's instant) move none of them; `progress` is 1, 2, 3, … across all.
    #[tokio::test(start_paused = true)]
    async fn heartbeat_schedule_from_receipt_paused_clock() -> TestResult {
        let peer = Arc::new(Recorder::default());
        let mut progress = Progress::new(Some(token()), peer.clone());
        let receipt = Instant::now();
        let (decide, decision) = oneshot::channel::<u8>();
        let mut relay = progress.relay();
        let schedule = [
            (1_300, Status::Executing),
            (4_990, Status::Pending),
            (7_700, Status::Executing),
            (10_000, Status::Pending),
            (13_100, Status::Executing),
        ];
        let app = async move {
            for (at, status) in schedule {
                sleep_until(receipt + ms(at)).await;
                relay(change(status));
            }
            sleep_until(receipt + ms(17_000)).await;
            let _ = decide.send(42);
        };
        let waiting = wait_with_progress(
            decision,
            &mut progress,
            receipt,
            HEARTBEAT_EVERY,
            std::future::pending(),
        );
        let (out, ()) = bounded(async { tokio::join!(waiting, app) }).await;
        assert_eq!(out.and_then(Result::ok), Some(42));

        let sent = peer.sent();
        assert_eq!(beats(&sent, receipt), [ms(5_000), ms(10_000), ms(15_000)]);
        let changes: Vec<(Duration, String)> = sent
            .iter()
            .filter_map(|(at, p)| p.message.clone().map(|m| (*at - receipt, m)))
            .collect();
        let want: Vec<(Duration, String)> = schedule
            .iter()
            .map(|(at, status)| {
                (
                    ms(*at),
                    format!("request_id={ID} status={}", wire_name(*status)),
                )
            })
            .collect();
        assert_eq!(changes, want);
        assert_eq!(counters(&sent), (1..=8).map(f64::from).collect::<Vec<_>>());
        assert!(
            sent.iter()
                .all(|(_, p)| p.progress_token == token() && p.total.is_none() && p.meta.is_none())
        );
        Ok(())
    }

    /// The answer at 12 s (between ticks) and at 15 s (with a tick due at the same instant):
    /// the output is returned then, and nothing is sent after it, however long the clock runs.
    #[tokio::test(start_paused = true)]
    async fn no_progress_after_result() -> TestResult {
        for (done_at, beats_before) in [(12_000, 2..=2), (15_000, 2..=3)] {
            let peer = Arc::new(Recorder::default());
            let mut progress = Progress::new(Some(token()), peer.clone());
            let receipt = Instant::now();
            let (decide, decision) = oneshot::channel::<()>();
            let app = async move {
                sleep_until(receipt + ms(done_at)).await;
                let _ = decide.send(());
            };
            let waiting = wait_with_progress(
                decision,
                &mut progress,
                receipt,
                HEARTBEAT_EVERY,
                std::future::pending(),
            );
            let (out, ()) = bounded(async { tokio::join!(waiting, app) }).await;
            assert!(matches!(out, Some(Ok(()))), "{done_at}");
            let returned = Instant::now();
            assert_eq!(returned - receipt, ms(done_at));
            let at_result = peer.sent();
            assert!(
                beats_before.contains(&at_result.len()),
                "{done_at}: {}",
                at_result.len()
            );
            assert!(at_result.iter().all(|(at, _)| *at <= returned));
            tokio::time::sleep(Duration::from_secs(30)).await;
            assert_eq!(
                peer.sent().len(),
                at_result.len(),
                "{done_at}: sent after the result"
            );
        }
        Ok(())
    }

    /// Sets its flag when dropped.
    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// PD-126: the cancel ends the wait with `None` and drops the waited future at once; the
    /// timer stops with it.
    #[tokio::test(start_paused = true)]
    async fn cancelled_wait_drops_the_call_and_stops_the_timer() -> TestResult {
        let peer = Arc::new(Recorder::default());
        let mut progress = Progress::new(Some(token()), peer.clone());
        let receipt = Instant::now();
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = DropFlag(dropped.clone());
        let never = async move {
            let _flag = flag;
            std::future::pending::<()>().await;
        };
        let out = bounded(wait_with_progress(
            never,
            &mut progress,
            receipt,
            HEARTBEAT_EVERY,
            sleep_until(receipt + ms(7_000)),
        ))
        .await;
        assert!(out.is_none());
        assert_eq!(Instant::now() - receipt, ms(7_000));
        assert!(dropped.load(Ordering::SeqCst), "the waited future was kept");
        assert_eq!(beats(&peer.sent(), receipt), [ms(5_000)]);
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(peer.sent().len(), 1);
        Ok(())
    }

    /// No token: no timer and no notification, status changes included; the output still comes.
    #[tokio::test(start_paused = true)]
    async fn nothing_without_a_token() -> TestResult {
        let peer = Arc::new(Recorder::default());
        let mut progress = Progress::new(None, peer.clone());
        progress.submitted(ID).await;
        let receipt = Instant::now();
        let (decide, decision) = oneshot::channel::<()>();
        let mut relay = progress.relay();
        let app = async move {
            sleep_until(receipt + ms(3_000)).await;
            relay(change(Status::Executing));
            sleep_until(receipt + ms(12_000)).await;
            let _ = decide.send(());
        };
        let waiting = wait_with_progress(
            decision,
            &mut progress,
            receipt,
            HEARTBEAT_EVERY,
            std::future::pending(),
        );
        let (out, ()) = bounded(async { tokio::join!(waiting, app) }).await;
        assert!(matches!(out, Some(Ok(()))));
        assert!(peer.sent().is_empty());
        Ok(())
    }

    /// "submitted" carries `progress: 1` and the id; a `pending` change right after it and a
    /// repeated `executing` are dropped; a change that arrives with the answer is sent before the
    /// output is returned.
    #[tokio::test(start_paused = true)]
    async fn submitted_then_each_change_once() -> TestResult {
        let peer = Arc::new(Recorder::default());
        let mut progress = Progress::new(Some(token()), peer.clone());
        progress.submitted(ID).await;
        let receipt = Instant::now();
        let mut relay = progress.relay();
        let answer = async move {
            sleep_until(receipt + ms(1_000)).await;
            relay(change(Status::Pending));
            relay(change(Status::Executing));
            sleep_until(receipt + ms(2_000)).await;
            relay(change(Status::Executing));
            sleep_until(receipt + ms(3_000)).await;
            // Handed over in the same poll that answers.
            relay(change(Status::Succeeded));
            7
        };
        let out = bounded(wait_with_progress(
            answer,
            &mut progress,
            receipt,
            HEARTBEAT_EVERY,
            std::future::pending(),
        ))
        .await;
        assert_eq!(out, Some(7));
        let messages: Vec<(f64, Option<String>)> = peer
            .sent()
            .into_iter()
            .map(|(_, p)| (p.progress, p.message))
            .collect();
        assert_eq!(
            messages,
            [
                (
                    1.0,
                    Some(format!("submitted request_id={ID} status=pending"))
                ),
                (2.0, Some(format!("request_id={ID} status=executing"))),
                (3.0, Some(format!("request_id={ID} status=succeeded"))),
            ]
        );
        Ok(())
    }
}

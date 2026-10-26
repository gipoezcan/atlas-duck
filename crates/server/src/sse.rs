//! Server-sent UI events (`GET /api/events`, SM-5.2, PD-206): the user's UI events with the
//! desktop's names and payloads (`event: <name>`, `data: <json>`), a keep-alive comment every
//! 15 s, `event: resync` (empty data) when the stream fell behind the per-user channel, and the
//! end of the stream once the session expired (checked at every keep-alive). An open stream pins
//! the user's runtime (PD-209).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::response::sse::{Event, Sse};
use futures::Stream;
use tokio::sync::broadcast::error::RecvError;

use crate::runtime::{Pin, SseEvent};
use crate::session::SessionTable;

/// PD-206.
#[cfg(not(test))]
pub const KEEPALIVE: Duration = Duration::from_secs(15);
#[cfg(test)]
pub const KEEPALIVE: Duration = Duration::from_millis(200);

struct State {
    rx: tokio::sync::broadcast::Receiver<SseEvent>,
    tick: tokio::time::Interval,
    sessions: Arc<SessionTable>,
    cookie: String,
    _pin: Option<Pin>,
}

/// The stream of one connection: events, `resync` on lag, keep-alives, the end at expiry.
pub fn stream(
    rx: tokio::sync::broadcast::Receiver<SseEvent>,
    pin: Option<Pin>,
    sessions: Arc<SessionTable>,
    cookie: String,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut tick = tokio::time::interval(KEEPALIVE);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let state = State {
        rx,
        tick,
        sessions,
        cookie,
        _pin: pin,
    };
    let s = futures::stream::unfold(state, |mut st| async move {
        tokio::select! {
            got = st.rx.recv() => {
                let ev = match got {
                    Ok(e) => Event::default().event(e.name).data(e.data.to_string()),
                    Err(RecvError::Lagged(_)) => Event::default().event("resync").data(""),
                    Err(RecvError::Closed) => return None,
                };
                Some((Ok(ev), st))
            }
            _ = st.tick.tick() => {
                if !st.sessions.is_live(&st.cookie) {
                    return None;
                }
                Some((Ok(Event::default().comment("keep-alive")), st))
            }
        }
    });
    Sse::new(s)
}

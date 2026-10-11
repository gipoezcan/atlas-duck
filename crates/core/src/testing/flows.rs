//! `Flow` and its `proptest` strategy (Task 29): the lifecycle flows the cross-cutting
//! properties (I-19 audit coverage, U-32) run over. Executing a flow needs a mock server, so the
//! runner lives with the tests (`tests/common/flows.rs`); this file is only the vocabulary and
//! the generator.

use proptest::prelude::*;

/// One scripted human-and-agent exchange over a fresh harness. Every flow ends with its request
/// settled; [`Flow::Quit`] ends the app and may only come last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flow {
    /// A read the human releases, delivered by `await`.
    ReadRelease,
    /// A read the human denies.
    ReadDeny,
    /// A read the instance answers with an error status (an upstream-error item), released.
    ReadUpstreamError,
    /// A read that hit a cap (an outcome item), released.
    ReadOutcome,
    /// A read cancelled by the client while its fetch is in flight.
    ReadCancelMidFetch,
    /// A read that expires while its fetch is in flight.
    ReadExpireMidFetch,
    /// A write the human approves as it is.
    WriteApprove,
    /// A write the human denies.
    WriteDeny,
    /// A write the human edits and then approves.
    WriteEditApprove,
    /// A write whose target changed between enrichment and the stale check; denied afterwards.
    WriteStaleChanged,
    /// A write cancelled by the client while its enrichment fetch is in flight.
    EnrichCancel,
    /// A connection test of the stored token.
    ConnectionTest,
    /// `doctor`.
    Doctor,
    /// The app quits (§2.5): only ever the last flow.
    Quit,
}

impl Flow {
    /// Every flow but `Quit`.
    pub const ALL_BUT_QUIT: [Flow; 13] = [
        Flow::ReadRelease,
        Flow::ReadDeny,
        Flow::ReadUpstreamError,
        Flow::ReadOutcome,
        Flow::ReadCancelMidFetch,
        Flow::ReadExpireMidFetch,
        Flow::WriteApprove,
        Flow::WriteDeny,
        Flow::WriteEditApprove,
        Flow::WriteStaleChanged,
        Flow::EnrichCancel,
        Flow::ConnectionTest,
        Flow::Doctor,
    ];
}

/// A flow other than `Quit`.
pub fn flow() -> impl Strategy<Value = Flow> {
    prop::sample::select(Flow::ALL_BUT_QUIT.to_vec())
}

/// 1 to 8 flows; `Quit` only as the last of them.
pub fn flow_sequences() -> impl Strategy<Value = Vec<Flow>> {
    (
        prop::collection::vec(flow(), 1..=8),
        prop::bool::weighted(0.15),
    )
        .prop_map(|(mut flows, quit)| {
            if quit {
                flows.truncate(7);
                flows.push(Flow::Quit);
            }
            flows
        })
}

//! The U-24 converter fault (PD-64): `TestHooks::converter_fault` makes the engine's executor
//! contexts carry one, and `ops::jira_body` appends it to the Markdown converter's output before
//! the hard check, so a test can prove that an escaping failure is rejected at validation.
//! `convert` itself has no fault API; production builds have neither the hook nor the field.

/// One unrecorded construct appended to converted wiki text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConverterFault {
    /// `{include:…}`: an unrecorded include.
    Include,
    /// `[~…]`: an unrecorded mention.
    Mention,
    /// `{html}…{html}`: an unrecorded macro (one paired span on its own line).
    Html,
}

impl ConverterFault {
    /// The appended text; each one is the T4 fuzz's fault string, so on any converter output it
    /// is exactly one unrecorded construct of its kind.
    pub fn text(self) -> &'static str {
        match self {
            ConverterFault::Include => "{include:Injected}",
            ConverterFault::Mention => "[~injected]",
            ConverterFault::Html => "{html}<b>x</b>{html}",
        }
    }

    /// `out` with the fault on a line of its own (`out` ends in `\n`); the converter's record of
    /// its containers stays valid, since nothing before the end moves.
    pub fn apply(self, out: &str) -> String {
        format!("{out}{}\n", self.text())
    }
}

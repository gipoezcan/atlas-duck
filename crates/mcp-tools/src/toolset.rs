//! Which tool set a front end serves.

/// `--tools full|generic` (§4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolSet {
    Full,
    Generic,
}

//! The sandbox `ScriptRunner` of the desktop app and the server (M14 PD-247): the glue between
//! core's script engine and the M8 sandbox host ([`glue`], re-exported at the root), the startup
//! probe and its holder ([`probe`]), and the glue's log event names ([`diag`]). Moved here from
//! the Tauri app by M14 Task 11 unchanged in behaviour; the app re-exports both under their old
//! module paths and keeps only the Tauri thread start of the probe.

#![deny(unsafe_code)]

pub mod diag;
mod glue;
pub mod probe;

pub use glue::*;

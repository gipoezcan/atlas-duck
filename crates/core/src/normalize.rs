//! Agent-string normalization at `hello`/submit (§3.3, C.0): every character the
//! `preview::invisible` classifier flags is removed, plus `\t`, `\r` and `\n` (`reason` keeps
//! `\n`); then the string is cut to its limit in Unicode scalars (plan decision: truncate rather
//! than reject; the raw originals stay in the `REQUEST_RECEIVED` payload). `unusual` is set when
//! anything was removed or cut.

use atlas_duck_ipc::proto::Hello;
use atlas_duck_preview::invisible;

/// §3.3: `agent_name` ≤ 64 characters (also MCP `clientInfo.name`).
pub const MAX_AGENT_NAME_CHARS: usize = 64;
/// §3.3: `cwd_basename` ≤ 64 characters.
pub const MAX_CWD_BASENAME_CHARS: usize = 64;
/// §3.3: `reason` ≤ 1 000 characters.
pub const MAX_REASON_CHARS: usize = 1_000;

/// The display strings of one `hello`, normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedHello {
    pub agent_name: Option<String>,
    pub cwd_basename: String,
    /// Something was stripped or truncated in `agent_name` or `cwd_basename`.
    pub unusual: bool,
}

/// Strip, cut, then strip again until nothing is removed: a cut can split an RGI sequence and
/// leave a lone ZWJ, variation selector or tag character that the classifier then flags. The
/// result is a fixpoint, so normalizing it again changes nothing.
fn normalize(s: &str, keep_newlines: bool, max_chars: usize) -> (String, bool) {
    let (mut out, removed) = invisible::strip(s, keep_newlines);
    let Some((cut, _)) = out.char_indices().nth(max_chars) else {
        return (out, removed);
    };
    out.truncate(cut);
    loop {
        let (again, removed) = invisible::strip(&out, keep_newlines);
        if !removed {
            return (out, true);
        }
        out = again;
    }
}

/// `agent_name` (and MCP `clientInfo.name`): stripped, newlines removed, ≤ 64 scalars.
pub fn normalize_agent_name(s: &str) -> (String, bool) {
    normalize(s, false, MAX_AGENT_NAME_CHARS)
}

/// `cwd_basename`: stripped, newlines removed, ≤ 64 scalars.
pub fn normalize_cwd_basename(s: &str) -> (String, bool) {
    normalize(s, false, MAX_CWD_BASENAME_CHARS)
}

/// `reason`: stripped, `\n` kept, ≤ 1 000 scalars.
pub fn normalize_reason(s: &str) -> (String, bool) {
    normalize(s, true, MAX_REASON_CHARS)
}

pub fn normalize_hello(h: &Hello) -> NormalizedHello {
    // A name made only of removed characters is no name (shown and bucketed as unnamed).
    let (agent_name, name_unusual) = match h.agent_name.as_deref() {
        Some(n) => {
            let (n, unusual) = normalize_agent_name(n);
            ((!n.is_empty()).then_some(n), unusual)
        }
        None => (None, false),
    };
    let (cwd_basename, cwd_unusual) = normalize_cwd_basename(&h.cwd_basename);
    NormalizedHello {
        agent_name,
        cwd_basename,
        unusual: name_unusual || cwd_unusual,
    }
}

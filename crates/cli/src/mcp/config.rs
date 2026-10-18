//! `atlas-duck mcp` configuration (PD-116, PD-122 flag/env part): the flags argv parsed and the
//! `ATLAS_DUCK_MCP_TIMEOUT` variable. A bad variable is a `usage` failure printed on stderr only
//! (PD-117): stdout carries nothing but JSON-RPC frames.

use std::ffi::OsString;
use std::time::Duration;

use atlas_duck_ipc::proto::AgentNameSource;

use crate::argv::{GlobalOpts, ParseError};
use crate::deadline::MAX_TIMEOUT;

/// The environment variable that bounds how long a tool call waits for a decision.
pub(crate) const TIMEOUT_ENV: &str = "ATLAS_DUCK_MCP_TIMEOUT";

/// §4.6: the default wait of a tool call.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(50);

/// `--tools full|generic` (§4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolSet {
    Full,
    Generic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct McpConfig {
    pub tools: ToolSet,
    // The default instance (PD-124) is read by the tool bodies (Task 8).
    #[allow(dead_code)]
    pub instance: Option<String>,
    /// `--agent`, else a non-empty `ATLAS_DUCK_AGENT` (the session's hello, PD-122).
    pub agent: Option<String>,
    pub agent_source: AgentNameSource,
    /// `--agent` was passed, even as `""`: the `clientInfo.name` fallback does not apply (PD-122).
    pub agent_given: bool,
    /// How long a tool call waits for a decision; `None` = 0 = return `pending` at once.
    // The tool bodies' deadline (Task 8).
    #[allow(dead_code)]
    pub timeout: Option<Duration>,
}

impl McpConfig {
    /// The flags argv parsed (`opts` carries `agent`/`agent_source` with the `ATLAS_DUCK_AGENT`
    /// fallback applied) plus `ATLAS_DUCK_MCP_TIMEOUT` from `lookup`.
    pub(crate) fn from_env(
        opts: &GlobalOpts,
        tools: ToolSet,
        instance: Option<String>,
        agent_given: bool,
        lookup: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<McpConfig, ParseError> {
        Ok(McpConfig {
            tools,
            instance,
            agent: opts.agent.clone(),
            agent_source: opts.agent_source,
            agent_given,
            timeout: parse_timeout(lookup(TIMEOUT_ENV))?,
        })
    }
}

/// Decimal seconds `0..`: unset is 50 s, `0` is `None`, a value above `MAX_TIMEOUT` clamps.
fn parse_timeout(raw: Option<OsString>) -> Result<Option<Duration>, ParseError> {
    let bad = |why: &str| ParseError {
        stderr_only: true,
        ..ParseError::arg(format!("{TIMEOUT_ENV} {why}"), TIMEOUT_ENV)
    };
    let Some(raw) = raw else {
        return Ok(Some(DEFAULT_TIMEOUT));
    };
    let Some(text) = raw.to_str() else {
        return Err(bad("is not valid UTF-8"));
    };
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(
            "must be a whole number of seconds (0 = return pending at once)",
        ));
    }
    // Only digits: parsing can fail by overflow alone, which clamps.
    let secs = text.parse::<u64>().unwrap_or(u64::MAX);
    Ok(match secs {
        0 => None,
        n => Some(Duration::from_secs(n).min(MAX_TIMEOUT)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> GlobalOpts {
        GlobalOpts {
            agent: Some("a".into()),
            agent_source: AgentNameSource::Flag,
            reason: None,
            timeout: None,
            instance: None,
            output: crate::argv::OutputMode::Json,
            help: false,
        }
    }

    fn with(raw: Option<OsString>) -> Result<McpConfig, ParseError> {
        McpConfig::from_env(&opts(), ToolSet::Full, None, false, &|k| {
            (k == TIMEOUT_ENV).then(|| raw.clone()).flatten()
        })
    }

    fn secs(s: &str) -> Option<Duration> {
        Some(Duration::from_secs(s.parse().unwrap_or(0)))
    }

    #[test]
    fn mcp_timeout_env_parse_table() {
        let table: [(Option<&str>, Option<Duration>); 5] = [
            (None, Some(Duration::from_secs(50))),
            (Some("0"), None),
            (Some("7"), secs("7")),
            (Some("007"), secs("7")),
            (Some("99999999999999999999999999"), Some(MAX_TIMEOUT)),
        ];
        for (raw, want) in table {
            let got = with(raw.map(OsString::from)).map(|c| c.timeout);
            assert_eq!(got, Ok(want), "{raw:?}");
        }
        for raw in ["", "x", "-1", "+1", "1.5", " 5", "5 ", "1e3"] {
            let e = with(Some(raw.into())).err();
            let e = e.unwrap_or_else(|| ParseError::new("accepted"));
            assert!(e.message.contains(TIMEOUT_ENV), "{raw:?}: {}", e.message);
            assert!(e.stderr_only, "{raw:?}");
            assert_eq!(
                e.details.get("arg"),
                Some(&serde_json::Value::from(TIMEOUT_ENV)),
                "{raw:?}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn mcp_timeout_env_refuses_non_unicode() {
        use std::os::windows::ffi::OsStringExt;
        let e = with(Some(OsString::from_wide(&[0x35, 0xD800]))).err();
        let e = e.unwrap_or_else(|| ParseError::new("accepted"));
        assert!(e.message.contains(TIMEOUT_ENV), "{}", e.message);
    }

    #[cfg(unix)]
    #[test]
    fn mcp_timeout_env_refuses_non_unicode() {
        use std::os::unix::ffi::OsStringExt;
        let e = with(Some(OsString::from_vec(vec![0x35, 0xff]))).err();
        let e = e.unwrap_or_else(|| ParseError::new("accepted"));
        assert!(e.message.contains(TIMEOUT_ENV), "{}", e.message);
    }

    #[test]
    fn from_env_carries_the_flags() {
        let cfg = McpConfig::from_env(&opts(), ToolSet::Generic, Some("x".into()), true, &|_| None);
        assert_eq!(
            cfg,
            Ok(McpConfig {
                tools: ToolSet::Generic,
                instance: Some("x".into()),
                agent: Some("a".into()),
                agent_source: AgentNameSource::Flag,
                agent_given: true,
                timeout: Some(Duration::from_secs(50)),
            })
        );
    }
}

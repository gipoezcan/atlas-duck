//! The environment of the black-box server suite (M14 PD-260, T23) and its summary lines. The
//! cases live in `tests/e2e.rs`; this library holds the parts a unit test can check without a
//! server: the argument (environment) parser and the outcome lines.

use std::fmt;

/// `usage` of the suite, printed (exit 2) when its environment is incomplete.
pub const USAGE: &str = "usage: ATLAS_DUCK_E2E_BASE_URL=<url> ATLAS_DUCK_E2E_USERS_FILE=<file> \
[ATLAS_DUCK_E2E_CA_FILE=<pem>] [ATLAS_DUCK_E2E_JIRA=mock|none] [ATLAS_DUCK_E2E_MOCK_CA_DIR=<dir>] [ATLAS_DUCK_E2E_SCRIPTS=met|not_met] \
[ATLAS_DUCK_E2E_ADMIN_EXEC=<command prefix>] [ATLAS_DUCK_E2E_METRICS_URL=<url>] [ATLAS_DUCK_E2E_VERIFY_EXEC=<command prefix>] \
cargo test -p atlas-duck-server-e2e --test e2e";

/// Which Jira the server under test can reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Jira {
    /// A Jira mock the server reaches over HTTPS; its test CA (made with
    /// `ATLAS_DUCK_E2E_MAKE_CA=<dir>`) is in the server's CA bundle and in this directory.
    Mock { ca_dir: String },
    /// None: the cases that need Jira are reported `skip`.
    None,
}

/// The suite's environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Env {
    /// The server's public URL without a trailing slash (also the `Origin` of browser requests).
    pub base_url: String,
    /// The PD-261 users file (`{"users": [{"username", "password", "groups"}]}`).
    pub users_file: String,
    /// A PEM bundle the client trusts besides the platform roots (the review environment's CA).
    pub ca_file: Option<String>,
    pub jira: Jira,
    /// The `/readyz` `scripts` state the run expects (`met` in the container).
    pub scripts: String,
    /// A command prefix that runs the server's admin CLI (`docker exec <c> /app/atlas-duck-server admin`).
    pub admin_exec: Option<String>,
    /// A command prefix that runs the image's `verify-export` on a local export dir.
    pub verify_exec: Option<String>,
    /// `http://host:port/metrics` of the server's metrics listener (`ATLAS_DUCK_METRICS_LISTEN`;
    /// the main port has no `/metrics`).
    pub metrics_url: Option<String>,
}

/// Reads the environment through `get`; `Err` is the usage line (exit 2).
pub fn parse_env(get: impl Fn(&str) -> Option<String>) -> Result<Env, String> {
    let set = |k: &str| get(k).filter(|v| !v.is_empty());
    let (Some(base), Some(users_file)) = (
        set("ATLAS_DUCK_E2E_BASE_URL"),
        set("ATLAS_DUCK_E2E_USERS_FILE"),
    ) else {
        return Err(USAGE.to_owned());
    };
    if !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err(format!(
            "ATLAS_DUCK_E2E_BASE_URL must be an http(s) URL\n{USAGE}"
        ));
    }
    let jira = match set("ATLAS_DUCK_E2E_JIRA").as_deref() {
        None | Some("none") => Jira::None,
        Some("mock") => match set("ATLAS_DUCK_E2E_MOCK_CA_DIR") {
            Some(ca_dir) => Jira::Mock { ca_dir },
            None => {
                return Err(format!(
                    "ATLAS_DUCK_E2E_JIRA=mock needs ATLAS_DUCK_E2E_MOCK_CA_DIR\n{USAGE}"
                ));
            }
        },
        Some(_) => return Err(format!("ATLAS_DUCK_E2E_JIRA must be mock or none\n{USAGE}")),
    };
    let scripts = set("ATLAS_DUCK_E2E_SCRIPTS").unwrap_or_else(|| "met".to_owned());
    if scripts != "met" && scripts != "not_met" {
        return Err(format!(
            "ATLAS_DUCK_E2E_SCRIPTS must be met or not_met\n{USAGE}"
        ));
    }
    Ok(Env {
        base_url: base.trim_end_matches('/').to_owned(),
        users_file,
        ca_file: set("ATLAS_DUCK_E2E_CA_FILE"),
        jira,
        scripts,
        admin_exec: set("ATLAS_DUCK_E2E_ADMIN_EXEC"),
        verify_exec: set("ATLAS_DUCK_E2E_VERIFY_EXEC"),
        metrics_url: set("ATLAS_DUCK_E2E_METRICS_URL"),
    })
}

/// What a case came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Fail(String),
    Skip(String),
}

/// One summary line: `ok|fail|skip <case> <ms>`, the reason on the next line (indented).
pub struct Line<'a> {
    pub case: &'a str,
    pub ms: u128,
    pub outcome: &'a Outcome,
}

impl fmt::Display for Line<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (word, why) = match self.outcome {
            Outcome::Ok => ("ok", None),
            Outcome::Fail(w) => ("fail", Some(w)),
            Outcome::Skip(w) => ("skip", Some(w)),
        };
        write!(f, "{word} {} {}", self.case, self.ms)?;
        if let Some(w) = why {
            for l in w.lines() {
                write!(f, "\n    {l}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Result<Env, String> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        parse_env(move |k| owned.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()))
    }

    #[test]
    fn without_its_environment_the_suite_prints_usage() {
        assert_eq!(env(&[]), Err(USAGE.to_owned()));
        assert_eq!(
            env(&[("ATLAS_DUCK_E2E_BASE_URL", "http://127.0.0.1:8080")]),
            Err(USAGE.to_owned())
        );
        assert_eq!(
            env(&[
                ("ATLAS_DUCK_E2E_BASE_URL", ""),
                ("ATLAS_DUCK_E2E_USERS_FILE", "u.json")
            ]),
            Err(USAGE.to_owned())
        );
    }

    #[test]
    fn a_full_environment_parses() {
        let e = env(&[
            ("ATLAS_DUCK_E2E_BASE_URL", "https://duck.example.test/"),
            ("ATLAS_DUCK_E2E_USERS_FILE", "u.json"),
            ("ATLAS_DUCK_E2E_JIRA", "mock"),
            ("ATLAS_DUCK_E2E_MOCK_CA_DIR", "ca"),
            (
                "ATLAS_DUCK_E2E_ADMIN_EXEC",
                "docker exec c /app/atlas-duck-server admin",
            ),
        ]);
        assert_eq!(
            e,
            Ok(Env {
                base_url: "https://duck.example.test".into(),
                users_file: "u.json".into(),
                ca_file: None,
                jira: Jira::Mock {
                    ca_dir: "ca".into()
                },
                scripts: "met".into(),
                admin_exec: Some("docker exec c /app/atlas-duck-server admin".into()),
                verify_exec: None,
                metrics_url: None,
            })
        );
        for bad in [
            ("ATLAS_DUCK_E2E_JIRA", "real"),
            ("ATLAS_DUCK_E2E_JIRA", "mock"),
            ("ATLAS_DUCK_E2E_SCRIPTS", "maybe"),
        ] {
            let r = env(&[
                ("ATLAS_DUCK_E2E_BASE_URL", "http://x"),
                ("ATLAS_DUCK_E2E_USERS_FILE", "u.json"),
                bad,
            ]);
            assert!(r.is_err(), "{bad:?}");
        }
        assert!(
            env(&[
                ("ATLAS_DUCK_E2E_BASE_URL", "ftp://x"),
                ("ATLAS_DUCK_E2E_USERS_FILE", "u.json")
            ])
            .is_err()
        );
    }

    #[test]
    fn summary_lines() {
        let ok = Outcome::Ok;
        assert_eq!(
            Line {
                case: "health_and_ready",
                ms: 12,
                outcome: &ok
            }
            .to_string(),
            "ok health_and_ready 12"
        );
        let skip = Outcome::Skip("needs Jira".into());
        assert_eq!(
            Line {
                case: "pat_entry",
                ms: 0,
                outcome: &skip
            }
            .to_string(),
            "skip pat_entry 0\n    needs Jira"
        );
    }
}

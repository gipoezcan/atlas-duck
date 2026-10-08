# atlas-duck

atlas-duck is a desktop app (Tauri, Rust) that sits between AI agents and Jira/Confluence Data Center. It is meant to give agents scoped, audited access to Atlassian content, and to run agent-supplied scripts in a confined sandbox, so the agent never holds credentials or an open-ended API client.

This repository is at milestone M1, the skeleton: a tray app that starts, checks its data directory, takes a single-instance lock, probes its own sandbox on each OS and writes a diagnostic log. The Atlassian features, settings and script execution come in later milestones. The M1 go/no-go record per OS is in `docs/m1/go-no-go.md`.

To try a build, read [TESTING.md](TESTING.md). The design spec and the implementation plans are in [docs/superpowers](docs/superpowers) (`specs/` and `plans/`).

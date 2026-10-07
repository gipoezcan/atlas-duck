# atlas-duck — Design Spec

**Date:** 2026-10-07
**Status:** Draft for review (after three adversarial review passes: multi-lens, local security, consistency)
**Author:** Yavuz Ege Özcan (with Claude)

atlas-duck is a cross-platform desktop application that acts as a **human-in-the-loop security proxy** between AI agents and self-hosted Atlassian **Jira Data Center** and **Confluence Data Center**. It holds the user's Personal Access Tokens, executes typed operations on behalf of agents, requires the user's approval before any write is executed and before any read result is released, and records every read and write in an encrypted, tamper-evident audit log retained for at least three months.

---

## 1. Goals, non-goals, success criteria

### 1.1 Requirements (as stated)

| # | Requirement |
|---|---|
| R1 | Multi-platform desktop GUI app (Windows, macOS, Linux). |
| R2 | Connects to Jira and Confluence using user-provided API keys (Data Center/Server only → Personal Access Tokens). |
| R3 | Acts as a security proxy for AI access; agents never receive credentials. |
| R4 | Agents can request operations: create tickets, access spaces/pages, search, etc. |
| R5 | Write request → user is notified and must approve before execution. |
| R6 | Read request → app performs the read; user must approve the result before it is returned to the agent. |
| R7 | Best-effort preview of all data to be returned (and of writes to be executed). |
| R8 | Agents can submit scripts that use read-only commands; scripts read without confirmation; user approves only the final result (with preview). |
| R9 | The app has a CLI that agents use. |
| R10 | All reads and writes are logged and retained for at least 3 months for compliance. |

### 1.2 Decisions made during brainstorming

| Topic | Decision |
|---|---|
| Deployments | Jira DC/Server and Confluence DC/Server only (PAT, `Authorization: Bearer`). Cloud out of scope. |
| Stack | Tauri 2 (Rust core, React + TypeScript UI); Rust CLI; rquickjs sandbox. |
| CLI waiting | Block with timeout; on timeout print the request id and exit 4; `await <id>` resumes. |
| Script language | JavaScript in embedded QuickJS-NG (rquickjs), in a separate sandbox process. |
| Agent auth | None. IPC restricted to the current OS user. Agent name is self-declared and **unverified**; OS peer pid/exe captured for display and audit. |
| Auto-approve | None in v1. Every write and every read result is approved individually. Batch approve/deny of selected queue items is allowed (§5.6); each item is logged individually. |
| Audit depth | Full payloads, encrypted at rest, hash-chained, retained ≥ 92 days (covers any 3 calendar months). |
| Approval UX | Approve / deny with reason / **edit** (writes) / **redact** (reads). |
| Operations | Core + extended reads and writes for both products (§7). |
| Agent front ends | CLI **and** an MCP server (`atlas-duck mcp`, stdio) over the same IPC. |
| Spec scope | One spec covering the full v1; the implementation plan is milestone-ordered (§14). |

### 1.3 Non-goals (v1)

Atlassian Cloud; auto-approve rules/policies; per-agent authentication; auto-update; multi-user/shared/server deployments; Jira attachment upload; cross-space Confluence page moves; arbitrary HTTP passthrough; delete operations; Markdown-generated mentions (§7.6); idempotency keys (duplicates are flagged instead, §5.6).

### 1.4 Success criteria

1. An agent with only the CLI (or MCP) can search Jira, read an issue, read a Confluence page, run a multi-call read script, and create/update issues and pages — and it receives **no Atlassian-derived bytes** the user did not explicitly release (residual channels are enumerated in §10.2), and **no write** happens that the user did not explicitly approve, byte for byte (§5.1 inv. 3).
2. Every fetched, released, denied, edited, delivered and executed payload is retrievable (decrypted) from the audit log for the retention period, and the log's integrity — including truncation at either end — can be verified.
3. A reviewer can decide on a typical approval in under ~10 s thanks to the preview.
4. No PAT ever appears in IPC traffic, diagnostic logs, audit payloads, or the sandbox; in the UI it exists only transiently in the dedicated credential-entry window (§10.3) and is never displayed or returned to any webview afterwards; no Atlassian content ever appears in diagnostic logs.

---

## 2. Architecture

### 2.1 Processes

| Process | Role | Secrets |
|---|---|---|
| **`atlas-duck-app`** (Tauri 2 tray app) | Trust core: IPC server, request broker & approval state machine, Jira/Confluence HTTP clients, preview generation, audit store, UI windows. | PATs, audit KEK, checkpoint signing key, head anchor — in the OS keychain; in passphrase mode (§8.6) PATs and the signing key are in the KEK-wrapped vault, the KEK is unwrapped from `recovery`, and the head anchor is the MAC'd file `<data>/anchor`. Read only by this process. |
| **`atlas-duck`** (CLI; also hosts `atlas-duck mcp`) | Thin client used by agents. Sends typed requests over IPC, blocks for decisions, prints JSON. Launches the app if it is not running (§4.7). | None. Never touches keychain or DB. Reads only the non-secret `cli.toml`/`paths.toml` and the `endpoint` file (§7.7, §3.1). |
| **`atlas-duck-sandbox`** (one process per script run) | Executes one agent script in QuickJS. All `atlas.*` calls are forwarded to the app via its stdin/stdout. | None. No HTTP client, keychain, or DB code linked. OS resource limits + best-effort OS confinement (§9.4). |

All three binaries ship in the same installer (§12). **Data leaves the app only through IPC envelopes**: the app never inherits a client's stdio, worker stderr is captured by the app (§3.4), and diagnostic logs contain metadata only (§7.7).

### 2.2 Rust workspace layout

```
atlas-duck/
  Cargo.toml                     # workspace
  crates/
    core/          # operation registry, request lifecycle, approval queue, redaction/edit engine
    atlassian/     # Jira DC REST v2 + Agile 1.0 client, Confluence DC REST client, rate limiter
    convert/       # storage→markdown, markdown→wiki, markdown→storage, wiki→preview-html
    preview/       # preview model builders per operation
    audit/         # SQLite store, crypto (envelope), hash chain, checkpoints, retention, export
    ipc/           # protocol types (JSON-RPC), framing, per-OS transport, peer identity
    sandbox-host/  # spawns/limits/confines the worker, bridges host calls
    sandbox-worker/# the atlas-duck-sandbox binary (rquickjs)
    cli/           # atlas-duck binary: CLI + MCP server (rmcp)
  app/
    src-tauri/     # Tauri app (tray, windows, commands); [[bin]]s for cli + sandbox thin mains
    ui/            # React + TypeScript + Vite
  docs/
```

Dependency rule: `core` depends on `atlassian`, `convert`, `preview`, `audit`, `ipc` (types). `cli` depends only on `ipc`. `sandbox-worker` depends only on `ipc` (types) + `rquickjs`. Nothing but `app` depends on Tauri. `atlassian` receives credentials through an injected `CredentialProvider` (keychain / vault / test double).

### 2.3 Operation registry

Every agent-visible capability is an entry in a static registry — never an HTTP passthrough:

```rust
struct OperationSpec {
    id: &'static str,                 // "jira.issue.get", "confluence.page.update"
    product: Product,                 // Jira | Confluence
    class: OpClass,                   // Read | Write
    params_schema: JsonSchema,        // validated before anything else happens
    cli: CliBinding,                  // per-param flag names, ≤1 positional, --<name>-file variants
    target_params: &'static [&str],   // params identifying the target (read-only in the edit form)
    field_rules: Option<FieldRules>,  // allowed `fields` / `expand` values (rule-based, §7.3)
    min_version: Option<Version>,     // instance version gate
    paginated: Option<PageSpec>,      // default/hard-cap `max`, page param names
    executor: fn(..) -> ..,           // maps params → exact HTTP request list (§5.1 inv. 3)
    previewer: fn(..) -> Preview,     // builds the preview model
    stale_check: Option<fn(..)>,      // writes only; per-op rule (§5.4)
    result_projection: Projection,    // writes: static allowlist of response fields returned to the agent
    redaction_rules: RedactionRules,  // reads: where copies of a field live (§5.3)
    result_example: serde_json::Value // documented example output (ops describe)
}
```

- The CLI subcommands, MCP tools, sandbox `atlas.*` functions and `ops describe` output are all **generated from the registry**.
- `ops describe <id>` returns `{op_id, class, approval: "release"|"approve", params_schema, cli: {usage, positional, flags, file_variants}, defaults, caps, field_rules, min_version, result_example, examples: {cli, call}}`. `atlas-duck call` always accepts the schema param names.
- Scripts can only reach `class == Read` entries; enforced in the app (§9.1).
- **Validation is static**: it depends only on registry data, the params, and the instance's cached version. Nothing fetched from Atlassian content influences whether validation passes or what its error text says.

### 2.4 Trust boundary (stated plainly)

- Any process running as the same OS user can reach the IPC endpoint (per the "no agent auth" decision). OS-level restrictions only exclude other users and remote hosts.
- Agent identity is informational: self-declared name + OS-derived peer pid/exe, shown and logged as **unverified**. PID→exe lookups are racy and are not an authentication signal.
- Request ids are **not access control**: any same-user process can enumerate them (`requests list`) and `await` any of them. Ids are random only so they cannot collide or be predicted across restarts. Every delivery is logged with the recipient (§8.3 `DELIVERED`) and multi-recipient deliveries are highlighted in the Audit window.
- **The human approval step is the security control.** DC PATs cannot be scoped; the operation registry is the only least-privilege layer.
- Approval decisions are enforced in Rust. The UI submits `{request_id, decision, candidate_rev, edits?, redactions?, reason?}`; `candidate_rev` = revision counter + hash of the exact candidate, issued by Rust with each preview it delivers. Rust rejects decisions whose `candidate_rev` is not current (`DECISION_STALE`, logged, no state change), and re-validates edits/redactions. The "opened in this revision" state (§5.6) is tracked in Rust (Rust records delivery of the preview for a given rev to the approvals window), not in UI state.
- **The approvals webview is part of the trusted computing base**: code execution in it is equivalent to approval authority for every pending item. Consequently: frontend dependencies are minimal, lockfile with integrity hashes, installed with `--ignore-scripts`, no runtime remote loads; strict rendering rules (§6.4, §10.3); the Tauri isolation hook enforces a per-window command allowlist and argument schemas — it cannot establish user intent. Rust-drawn native confirmations (batch approvals §5.6, security-weakening settings §10.3) and the separate credential-entry window (§10.3) are the measures that hold against a compromised approvals webview.
- Same-user malware can also read the OS keychain; the audit encryption protects against offline theft and casual tampering, not against a compromised user session (§8.9).

### 2.5 Application lifecycle

- Tray-only app; autostart at login (`tauri-plugin-autostart`, `--background`), single instance (`tauri-plugin-single-instance` — used only to focus the existing instance, never as agent transport).
- Closing windows hides them; exit only via tray **Quit** (pending requests are cancelled and logged).
- macOS: `ActivationPolicy::Accessory` (menu-bar app). Linux: tray **menu** items (no click events on Linux trays), including "Open approvals (N)" and "Unlock…"; if no tray host is available, the approvals window opens directly on new requests.
- If the app starts **locked** (passphrase mode, §8.6), the credential-entry window (§10.3) opens for unlock immediately (also under `--background`) and again whenever a request arrives while locked.
- **Startup hardening** (however the app was launched), before any webview is created:
  - Release builds disable devtools and remote debugging.
  - Remove debug-channel and loader-injection variables from the app's own environment and log a warning: `--remote-debugging*` inside `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`, `WEBVIEW2_USER_DATA_FOLDER`, `WEBKIT_INSPECTOR_SERVER`, `WEBKIT_INSPECTOR_HTTP_SERVER`, `LD_PRELOAD`, `GTK_MODULES`, `GIO_EXTRA_MODULES`. (`WEBVIEW2_BROWSER_EXECUTABLE_FOLDER` is kept for fixed-version enterprise deployments.)
  - Windows: `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR)` early in `main`; process mandatory label with `NO_READ_UP | NO_WRITE_UP`; applicable `SetProcessMitigationPolicy` settings.
  - Linux: `prctl(PR_SET_DUMPABLE, 0)` (blocks same-uid ptrace, `process_vm_readv` and `/proc/<pid>/mem` from the worker or other processes).
  - macOS: hardened runtime without `get-task-allow`.
  - A startup self-test confirms that a child process cannot read the app's memory.
  These do not stop a same-user process from driving the UI via OS accessibility/input-injection APIs or from killing and relaunching the app — within the accepted limits (§2.4).
- First-run wizard: recovery passphrase (mandatory, §8.6) → optional data-dir override and external anchor directory (advanced) → add instance(s) → install CLI to PATH → agent onboarding snippet.

---

## 3. IPC transport

### 3.1 Endpoints

**Single instance.** The app holds an exclusive lock on `instance.lock` in the **data dir** (next to the audit DB) for its whole lifetime (`flock(LOCK_EX|LOCK_NB)` on Unix; `CreateFileW` with share mode 0 on Windows), taken before the IPC server binds and before the audit store or keychain anchor is touched. The audit store's `open()` requires the lock handle (type-enforced). A second app instance exits immediately. The data-dir path never depends on per-session environment variables (§7.7).

**Endpoint discovery.** One shared function in the `ipc` crate, used by both CLI and app, computes the endpoint location (Unix: socket path; Windows: pipe-name prefix). At bind the app writes `<data>/endpoint` (user-only ACL / 0600) containing the actual endpoint name plus its own identity record: canonical exe path, `APPIMAGE` (if set), and the exe's file identity (device/inode or file index, size, mtime) at start. On Windows the CLI must read this file; a missing file, or a pipe name that does not start with the user's SID-derived prefix, means "not running".

**Windows** — named pipe `\\.\pipe\atlas-duck-<first 16 hex of SHA-256(user SID)>-<128-bit random>`; the random suffix is regenerated on each start (and on bind failure), so the name cannot be pre-squatted:
- Every pipe instance is created with the **same** security descriptor: protected DACL granting only the current user SID read/write data rights (`FILE_GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE`-class; explicitly **not** `FILE_CREATE_PIPE_INSTANCE`; no Everyone/Anonymous ACEs). Exact mask verified against `winnt.h` (§15).
- `reject_remote_clients(true)`; first instance created with `first_pipe_instance(true)`; never retried without the flag. The accept loop always keeps one listening instance (the next instance is created before a connected one is handed off); if creating an instance fails, the IPC server stops and the UI shows an error.
- Clients connect with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` set explicitly.
- Server identifies the client's user via `ImpersonateNamedPipeClient` → `OpenThreadToken` → `TokenUser` → `RevertToSelf` (must equal the server's SID); the PID → `QueryFullProcessImageNameW` lookup is for display/audit only.

**Linux** — Unix socket in `/run/user/<geteuid()>/atlas-duck/` if `/run/user/<uid>` exists, is owned by the uid and has mode 0700; otherwise `~/.local/state/atlas-duck/run-<hostname>/` (host-qualified because homes may be NFS-shared). `$XDG_RUNTIME_DIR` is not trusted for this.
**macOS** — Unix socket in `confstr(_CS_DARWIN_USER_TEMP_DIR)/atlas-duck/` (never `$TMPDIR` or `/tmp`); length checked < 104 bytes, fallback `~/Library/Caches/atlas-duck/`.
- Directory created `0700`; before binding (app) and before connecting (CLI), `lstat` verifies owner == euid, mode == 0700, not a symlink.
- Stale-socket handling: the app holds `instance.lock`, so a socket file without a live app is unlinked before binding. No `try_overwrite`.
- On accept: `peer_cred().uid() == geteuid()` or reject. pid → exe via `/proc/<pid>/exe` (Linux; the CLI is dumpable) / `proc_pidpath` (macOS) for display/audit only.
- Socket touched periodically / sticky bit set to survive runtime-dir cleanup.

### 3.2 Anti-squatting (client side)

Before sending any byte, on every connection (including MCP reconnects), the CLI verifies:

**(a) Server owner.** Windows: the user SID of the server process token (`GetNamedPipeServerProcessId` → `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` → `OpenProcessToken` → `TokenUser`) and the pipe's owner SID (`GetSecurityInfo(OWNER_SECURITY_INFORMATION)`) must both equal the CLI's own user SID. Unix: `peer_cred().uid() == geteuid()` plus the client-side directory check (§3.1). Failure to open the server process or token counts as a mismatch.

**(b) Executable identity.** The server pid is resolved to an executable path; both that path and the expected path are **canonicalized** (realpath) before comparison:
- Expected path: the `atlas-duck-app` next to the CLI's own canonical location; if not present (e.g. CLI symlinked into `~/.local/bin`), the `app_path` from `cli.toml` (written by "Install CLI to PATH", §12.3).
- **Linux**: the app is non-dumpable (§2.5), so `/proc/<pid>/exe` and `/proc/<pid>/environ` are not readable by the CLI. The CLI instead compares the identity record in `<data>/endpoint` (written by the app, §3.1) with the expected path; the **authenticating controls on Linux are the 0700 directory check and the `SO_PEERCRED` uid** — the identity record catches stale/foreign installs, not same-user forgery. **Upgrade**: if the recorded exe file identity differs from the current file at that path, the CLI exits 5 with `unreachable`/`app_upgraded`: "atlas-duck was upgraded; restart the app" (not a security warning).
- **AppImage**: identity is the AppImage file, not the mount path: the CLI's canonical `$APPIMAGE` must equal the `APPIMAGE` in the endpoint identity record. The AppImage wrapper (§12.3) embeds the absolute AppImage path.
- **macOS**: `proc_pidpath` of the peer pid.
- **Windows**: in release builds, the server binary must carry a valid Authenticode signature from the same publisher as the CLI (skipped only in dev builds behind a compile-time feature).

On any mismatch the CLI sends nothing and exits 5 with `error.code = "server_identity"`.

**Scope of this check**: it excludes other users' endpoints and stale/foreign binaries. It does **not** protect against same-user replacement of binaries in user-writable install locations (Windows per-user, AppImage, `~/.local`), which is outside the trust boundary (§2.4); `doctor` and Settings report the install mode.

### 3.3 Framing and protocol

- `u32` big-endian length-delimited frames (`tokio_util::codec::LengthDelimitedCodec`), **max frame 24 MiB** (= 16 MiB release cap + envelope/escaping headroom; §5.2). Applies to the IPC and sandbox channels.
- Payload: JSON-RPC 2.0. Methods: `hello`, `ops.list`, `ops.describe`, `instances.list`, `request.submit`, `request.await`, `request.status`, `request.cancel`, `requests.list`, `script.submit`. Server notification: `request.progress` (§4.5).
- `request.submit` / `script.submit` carry routing fields next to the params: `{op_id, params, instance?, reason?}`. `instance` defaults to the product's default instance and is resolved to a concrete instance id before validation (so previews and audit always show a concrete instance).
- Handshake `hello`: `{protocol_version: <int>, client_kind: "cli"|"mcp", client_version, agent_name, agent_name_source: "flag"|"env"|"mcp-clientInfo"|"none"}`. `hello` must be the **first frame and arrive within 5 s**, or the connection is closed; any other method before `hello`, or a second `hello`, is rejected. All binaries ship together, so **protocol_version must match exactly**; on mismatch the server returns `protocol_mismatch {client, server}` and the CLI exits 5 with "atlas-duck app (vX) differs from CLI (vY): quit and relaunch the app, or reinstall".
- **Agent-supplied display strings** (`agent_name`, `reason`, MCP `clientInfo.name`) are normalized in Rust at `hello`/submit: C0/C1 controls (except newlines in `reason`), bidi embedding/override/isolate characters (U+202A–202E, U+2066–2069) and zero-width characters are removed, and an "unusual characters" flag is set if anything was removed; `agent_name` ≤ 64 chars, `reason` ≤ 1 000 chars. The raw originals are kept in the audit payload.
- `instances.list` returns `{alias, product, is_default, state}` only — never URLs, usernames or tokens.
- Limits (fairness, not security — the key is spoofable): max 64 concurrent connections (MCP connections are long-lived) and 16 per peer exe; max 32 pending requests per agent key (`agent_name`, falling back to `peer_exe`); max 256 pending total. When a limit is reached the server still accepts the connection and answers `busy`: envelope `status: failed`, `error: {code: "busy", retryable: true, details: {retry_after_s}}`, exit 11; nothing is queued. The approvals UI offers "Deny all pending from this agent".
- Frame-size or JSON errors, `hello` timeouts and ordering violations produce a JSON-RPC error (`protocol_error`, exit 1) where possible, never a silent drop; they are recorded in the diagnostic log (metadata only: connection id, peer pid/exe, reason).

### 3.4 Sandbox channel

**Spawning.** The worker is spawned by a dedicated platform routine in `sandbox-host` (not `std::process::Command`) with exactly three handles — stdin, stdout, stderr — each a pipe owned by the host:
- Windows: `CreateProcessW`/`CreateProcessAsUserW` with `STARTUPINFOEX`, `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` naming only the three pipe handles, `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` (AppContainer, §9.4), and `PROC_THREAD_ATTRIBUTE_JOB_LIST` (or created suspended → `AssignProcessToJobObject` → resumed), so it is in the job before its first instruction.
- Linux: fork with only async-signal-safe steps in the child: `dup2` the pipes to 0/1/2, `close_range(3, ~0U, 0)`, `PR_SET_PDEATHSIG(SIGKILL)`, `PR_SET_NO_NEW_PRIVS`, rlimits; then exec. macOS: `posix_spawn` with `POSIX_SPAWN_CLOEXEC_DEFAULT`.
- Environment cleared to a fixed allowlist (Windows: `SystemRoot` only; Unix: empty, plus `MALLOC_ARENA_MAX=1` on Linux). Working directory: an empty per-run directory (Windows) or `/` (Unix). Only the canonical sandbox binary from the install dir is executed.
- The worker exits on stdin EOF (covers app crashes; macOS has no parent-death signal).

**stderr** is read by the host, capped at 64 KiB, stored only in the run's encrypted audit record, shown in the approval view like `atlas.log`, and reaches the agent only through the release flow (§9.5). Never written to diagnostic logs.

**Channel rules (the host treats the worker as hostile).** Same framing and JSON-RPC types (`host.call`, `host.log`, `script.result`, `script.error`); the worker never connects to the IPC endpoint.
- Frame caps: worker→host frames ≤ 1 MiB, except one terminal frame (`script.result`/`script.error`) ≤ `max_result_mb` + 64 KiB; host→worker frames ≤ 24 MiB (call results are already bounded by `max_call_result_mb`).
- Backpressure: the host decodes one frame at a time and stops reading the worker's stdout while `max_concurrent_calls` host calls are in flight; it never queues more.
- Logs: `host.log` is capped per run at 1 MiB and 10 000 lines; past the cap one `[log truncated: N bytes]` marker is kept.
- Per-run state machine: request ids unique and strictly increasing; exactly one terminal message is accepted; host calls still in flight at that moment are cancelled (results discarded, never delivered; calls already committed as `SCRIPT_CALL` still count as data exposure); frames after the terminal message are ignored and the process is reaped.
- Violations (invalid UTF-8/JSON, unknown method, oversize frame, duplicate/non-increasing id, second terminal message, response to an id the host never issued) → the host kills the worker immediately (`TerminateJobObject` / `SIGKILL`) and records `SCRIPT_FAILED {reason: "protocol_violation"}`, classified per §9.5.
- Each worker process is bound to exactly one run id.

---

## 4. Agent front ends

### 4.1 CLI

Resource-style subcommands generated from the registry (per-op `CliBinding`), plus generic forms:

```
atlas-duck jira search --jql "project=ABC AND status=Open" [--fields f1,f2] [--max 50] [--start 0]
atlas-duck jira issue get ABC-123 [--comments] [--changelog] [--fields …]
atlas-duck jira issue create --project ABC --type Bug --summary "…" --description-file - [--body-format markdown|wiki]
atlas-duck confluence page get 12345 [--format markdown|storage|view]
atlas-duck confluence page update 12345 --body-file page.md [--body-format markdown|storage] [--title …]
atlas-duck script run report.js|- [--args '{"project":"ABC"}'] [--limits '{"timeout_s":60}']
atlas-duck call <op-id> --params '<json>' | --params-file f.json|-
atlas-duck ops list [--instance X] | ops describe <op-id> [--instance X]
atlas-duck instances
atlas-duck await <id> | status <id> | cancel <id>
atlas-duck requests list [--agent NAME] [--state pending|recent]   # metadata only
atlas-duck mcp [--tools full|generic] [--instance X]
atlas-duck doctor                                    # install/connectivity diagnostics (§4.7)
```

Global flags: `--agent NAME` (or `ATLAS_DUCK_AGENT`), `--reason "…"` (agent's justification, shown in the approval dialog and logged), `--timeout SECONDS` (default **100**; `0` = submit and return the pending envelope immediately), `--instance ALIAS`, `--output json|text` (default `json`).

`--format` is reserved for per-op body/representation formats (e.g. `page get --format markdown`); `--output` selects CLI output rendering.

**Stdin and input encoding.**
- Stdin is read only when an argument's value is exactly `-` (`--*-file -`, `--params-file -`, `script run -`). At most one argument may be `-`; more → exit 2. With no `-`, stdin is never read.
- Input text (stdin and files) must be UTF-8; a leading UTF-8 BOM is stripped; invalid UTF-8 → exit 2 with byte offset.
- On Windows, agents should pass file paths rather than piping through PowerShell 5.1 (which re-encodes pipeline input); documented in onboarding.
- File arguments are read **by the CLI** and sent as content; the app never reads agent-specified paths. Attachment upload sends file bytes (base64) plus filename; max 10 MiB per attachment.

**`--output text`**: stdout carries a human rendering of `data`; the envelope minus `data` goes to stderr as one JSON line; exit codes are identical. JSON is the agent contract.

**Submission notice.** Immediately after the server accepts a request, the CLI writes one line to **stderr** and flushes: `{"event":"submitted","request_id":"…","status":"pending"}`. On SIGINT/SIGTERM/SIGHUP/CTRL_CLOSE_EVENT/broken pipe it prints the pending envelope if stdout is still writable and exits 4. It **never** cancels the request (and a SIGKILL'd CLI still leaves the id on stderr).

### 4.2 Output envelope

Every invocation prints exactly one JSON envelope to stdout (in `--output json`), including usage errors and unreachable-app cases (`request_id: null` when nothing was queued):

```json
{
  "request_id": "req_…",
  "op_id": "jira.search",
  "instance": "jira-main",
  "status": "pending",
  "data": null,
  "edited": false,
  "redacted": false,
  "redaction_note": null,
  "message": null,
  "error": null,
  "meta": null
}
```

- `request_id` — opaque string; `req_` + ≥ 122 bits of CSPRNG randomness (not time-ordered, not monotonic); unique across restarts.
- `error` — `null` or `{code: string, retryable: bool, message: string, details?: object}`. Codes (stable, machine-readable) include: `usage`, `validation`, `op_unsupported_by_instance`, `internal`, `audit_failure`, `audit_storage_low`, `busy`, `unreachable`, `server_identity`, `protocol_mismatch`, `upstream_http`, `upstream_network`, `upstream_unknown_outcome`, `result_too_large`, `needs_token`, `locked`, `not_configured`, `script_syntax`, `script_limit`, `sandbox_unavailable`, `result_evicted`, `abandoned`, `unknown_request`, `protocol_error`. (Runtime errors of scripts are never an `error.code`; they reach the agent only as released `data.script_error`, §9.5.)
- `meta` — for released reads: `{fetched_at, released_at, page?: {start, returned, total|null, truncated, next_start|null}, redactions?: {items_dropped, fields_dropped: [names], spans_masked}, conversion?: {lossy, lost: {macros, images, links, layouts}}}`. Redaction metadata is counts and field names only — never positions or values.

**`data` shape.**
- **Reads**: `data = {result}`, where `result` is the Atlassian DC response **with field names and nesting unchanged**, pruned to the op's allowed fields, after redaction. Exceptions are documented per op (e.g. `confluence.page.get` with `format=markdown` replaces `body` with `{format: "markdown", value}`). Server-reported totals are passed through unchanged; `meta.page` and `meta.redactions` explain gaps.
- **Writes**: `data = {receipt, executed_params?, chunks?}`. `receipt` is the op's static `result_projection` of the server response (Jira: `id`, `key`, `self`; Confluence: `id`, `type`, `status`, `version.number`, `_links.webui`; labels: only the labels the agent supplied; 204 → `{}`). `executed_params` appears only when `edited: true` and contains **only the agent's own param keys** with the user's edits applied — never app-filled values (kept title/body, resolved ids, version numbers). The full server response is audit-only. `chunks` for batch ops (§5.4).
- **Write with unknown outcome**: `data = {target, chunks?}`.
- **Script results**: `data = {result}` (the JSON returned by the script, after redaction) or, for released error details, `data = {script_error: {class, message, stack, elapsed, logs?}}`.

### 4.3 Status ↔ exit code matrix (normative)

| Status | Exit | When | `data` |
|---|---|---|---|
| `pending` | 4 | not yet decided; `--timeout` elapsed or `--timeout 0` | null |
| `executing` | 4 | write approved, still executing when the wait ended | null |
| `succeeded` | 0 | write executed | `{receipt, executed_params?, chunks?}` |
| `released` | 0 | read / script result released (possibly redacted) | `{result}` |
| `released` | 8 | script **error details** released | `{script_error}` |
| `denied` | 3 | user denied (`message` = reason); if the user attached enrichment-error details (§5.4 step 2): `error = {code: "upstream_http", retryable: false, details: {status, error_messages}}` | null |
| `expired` | 7 | pending request expired | null |
| `cancelled` | 7 | cancelled by agent or app quit | null |
| `failed` | 1 | `internal`, `audit_failure`, `audit_storage_low`, `protocol_error` | null |
| `failed` | 2 | `usage`, `validation`, `op_unsupported_by_instance`, `unknown_request` (nothing queued) | null |
| `failed` | 5 | `unreachable` (`details.reason`: `not_running`, `launch_timeout`, `no_gui_session`, `app_upgraded`), `server_identity`, `protocol_mismatch` — nothing was queued | null |
| `pending` | 5 | `unreachable` with `details.reason = connection_lost`: the connection dropped **after** submission (e.g. app crash); the envelope carries the non-null `request_id` and the hint "use `await <id>`; the request may be `abandoned`" | null |
| `failed` | 6 | `upstream_http` (write failed after approval, or released upstream-error details — see §11.2), `upstream_network`, `result_too_large`; batch partial failure (`data.chunks`) | null / `{chunks}` |
| `failed` | 8 | `script_syntax`, `script_limit` (data-free failures only, §9.5), `sandbox_unavailable` | null |
| `failed` | 9 | `locked`, `not_configured`, `needs_token` | null |
| `outcome_unknown` | 6 | `upstream_unknown_outcome`: write sent but outcome unknown (timeout/reset after send, 5xx, crash mid-execution) — **check the target before retrying** | `{target, chunks?}` |
| `abandoned` | 7 | `abandoned`: request was pending when the app crashed/was killed | null |
| *(any terminal)* | 10 | outcome known, but result data no longer available (`error.code = result_evicted`) | null |
| `failed` | 11 | `busy` — nothing queued; retry after `retry_after_s` | null |

### 4.4 Timing semantics

- **Reads** are fetched immediately on submit; the preview is built from the fetched data; the request then waits for release.
- A pending request is **independent of the connection** that submitted it: client disconnect or kill never cancels it. It ends only by decision, expiry, `cancel`, or app quit.
- **Expiry**: pending requests expire 24 h after **submission** (configurable 1 h–7 d); a Stale return to AwaitingApproval does not reset the timer.
- **Approved writes** execute immediately on approval even if the CLI has stopped waiting.
- **Result retention for `await`**: released data / write receipts are kept in memory for 1 h after the decision and may be delivered **any number of times** within that window (each delivery logged, §8.3 `DELIVERED`). After that, `await`/`status` return the request's true terminal status (read from the audit log's plaintext columns, for the whole retention period) with `data: null`, exit 10.
- `cancel` is allowed while a request is pending (before decision); afterwards it returns the current status.
- `requests list` returns metadata only (`request_id, op_id, instance, target_display, status, submitted_at`) for pending and recently decided (≤ 24 h) requests, filterable by agent name — so an agent whose CLI was killed can recover its ids.

### 4.5 Agent-visible state (opacity rule)

Before a decision, the agent can observe only `pending`. `executing` is emitted when a write's stale check passes and execution begins; once emitted, the agent-visible status stays `executing` until a terminal state — including across a version-conflict return to AwaitingApproval (§5.4 step 6). A failed pre-execution stale check happens while the status is still `pending`. Re-approvals after staleness are therefore invisible to the agent. `status`, `await`, `request.progress` and MCP progress notifications carry only `{request_id, status}` and are emitted **only when the agent-visible status changes**, plus content-free heartbeats on a fixed timer (§4.6). Internal states (Fetching, AwaitingRelease, Running, Enriching, Stale), counts, sizes, durations, warnings, titles and staleness are never exposed. The remaining channels are enumerated in §10.2.

### 4.6 MCP server

`atlas-duck mcp` runs a stdio MCP server (official Rust SDK `rmcp`). It is another client of the app IPC — same queue, approvals, audit and semantics.

- **Tools** (`--tools full`, default): one per registry operation (name = op id with `.` → `_`, e.g. `jira_issue_get`), input schema = op params schema plus optional `reason` and `instance`; plus `script_run`, `request_await`, `request_status`, `request_cancel`, `request_list`, `ops_list`, `ops_describe`, `instances_list`.
- `--tools generic` (for clients with tool-count limits): only `call(op_id, params, reason?, instance?)`, `script_run`, `ops_list`, `ops_describe`, `instances_list`, `request_await/status/cancel/list`.
- Tool annotations: Read ops `readOnlyHint: true`; Write ops `destructiveHint` as appropriate. `outputSchema` from `result_example` where available.
- **Waiting**: tool calls block up to `ATLAS_DUCK_MCP_TIMEOUT` (default **50 s**, below common 60 s client timeouts). If the client supplied a `progressToken`, the server sends a progress notification **immediately after submit** (message contains the `request_id`), a heartbeat at least every 10 s, and one on each agent-visible status change.
- On timeout: non-error result with `structuredContent` = the §4.2 envelope (`status: pending`) and text "Approval pending. Call request_await with request_id=<id>. Do not resubmit."
- `notifications/cancelled` for a tool call stops waiting only; it never cancels the queued request (only `request_cancel` does).
- Denials, expiries and failures are returned as tool results with `isError: true` and the envelope as structured content.
- Agent name = MCP `clientInfo.name` (unverified), overridable by `--agent`. `--instance X` sets the default instance for this MCP server.

### 4.7 App launch and `doctor`

- **When to launch**: only when the endpoint does not exist (Windows: endpoint file missing, or the named pipe returns `ERROR_FILE_NOT_FOUND`; Unix `ENOENT`, or `ECONNREFUSED` on a stale socket). On `ERROR_PIPE_BUSY` the CLI uses `WaitNamedPipe` for up to 5 s, then exits 11 (`busy`) — never launches. The CLI does not launch when there is no interactive GUI session (Linux: neither `DISPLAY` nor `WAYLAND_DISPLAY`; Windows: non-interactive session/session 0; macOS: no Aqua session) and exits 5 with a hint to start the app from the desktop. Concurrent launches are serialized via a launch lock file in the data dir.
- **How to launch** (hygiene): by the canonical absolute path verified as in §3.2, passing only `--background` (agent argv never forwarded); no inherited handles; stdin/stdout/stderr on the null device (keeps MCP stdout clean); working directory = install dir (Windows) or `/`; **detached from the caller's process tree and job** so killing the agent never kills the app — Windows `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB` (falling back to `ShellExecute` if breakaway is denied), macOS LaunchServices `open -n -g -a <app> --args --background`, Linux double-fork + `setsid`. The environment is rebuilt from an explicit allowlist: `DISPLAY`, `WAYLAND_DISPLAY`, `XAUTHORITY`, `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`, `HOME`/`USERPROFILE`, `LANG`/`LC_*`, `TMP`/`TEMP`/`TMPDIR`, `SystemRoot`, a system `PATH`, and `HTTP(S)_PROXY`/`NO_PROXY` (so a CLI-launched app behaves like a login-started one).
- After launching, the CLI polls the endpoint for up to 20 s, then exits 5.
- `doctor` reports per instance alias only `{configured, reachable, needs_token, locked, tls_error, version_supported}` plus local install checks (PATH, app path, IPC endpoint). No usernames, URLs, server titles or version strings.

---

## 5. Request lifecycle and approvals

### 5.1 State machine (in `core`)

```
Received ─validate(static)─▶ Validated            (validation failure → Rejected, exit 2)
  Read:   Validated → Fetching → AwaitingRelease(result | upstream-error) → {Released | ReleasedRedacted | Denied} → Delivered*
          Fetching → Failed (READ_FAILED: result_too_large, needs_token, upstream_network)
  Write:  Validated → Enriching → AwaitingApproval(preview | enrichment-error | collision) → {Approved | ApprovedEdited} → StaleCheck
              StaleCheck → Executing → {Succeeded | Failed | OutcomeUnknown}
              StaleCheck → Stale → AwaitingApproval (candidate_rev++)
              Executing → Stale → AwaitingApproval (version conflict 409/400, §5.4 step 6; candidate_rev++)
          Enriching → Failed (REQUEST_FAILED: needs_token, upstream_network)
          AwaitingApproval → Denied
  Script: Validated → Running → AwaitingRelease(result | error-details) → {Released | ReleasedRedacted | Denied} → Delivered*
          Running → Failed (data-free failures only, §9.5; or audit_failure)
  Any pending state → Expired | Cancelled
  Infrastructure failures (audit append, internal) → Failed (REQUEST_FAILED, or the phase-specific *_FAILED event)
```

Invariants (enforced in code and property-tested):

1. **Audit-before-effect.** Each of the following side effects happens only after its audit record is durably committed: any upstream HTTP call (`REQUEST_RECEIVED` / `SCRIPT_STARTED` with full params, committed before the first call), handing a host-call response to the sandbox (`SCRIPT_CALL`), release to the agent (`READ_RELEASED`/`SCRIPT_RELEASED`), each delivery (`DELIVERED`), and execution of a write (`WRITE_APPROVED`). If the append fails, the transition fails closed (no call, no release, no execution) and the request goes to `Failed` (`audit_failure`, exit 1).
2. **No unreleased delivery.** A delivery carrying data exists only if a `READ_RELEASED`/`SCRIPT_RELEASED` record exists for that request id whose released-payload hash equals the delivered bytes' hash. Write deliveries contain only the `result_projection` of the logged `WRITE_EXECUTED` response plus the agent's own (possibly edited) params; for a failed approved write, the Atlassian `errorMessages`/`errors` of the logged `WRITE_FAILED` response (capped 2 KiB, §11.2; listed in §10.2).
3. **Approval binds the wire.** A `WRITE_APPROVED` record stores `request_set_hash` = SHA-256 over the canonical, ordered list of exact HTTP requests (method, resolved URL, body bytes — after conversion and enrichment, chunked as they will be sent), i.e. exactly what the Raw tab showed. The executor sends only requests from that list, in order, checking each against it. Only the latest approval counts, and only if no `WRITE_EDITED`/`WRITE_STALE` follows it.
   Outside approved write execution, the HTTP client permits only `GET` plus a closed, code-level allowlist of side-effect-free POSTs: **`POST /rest/api/2/search`**. Enrichment and stale checks are GET-only.
4. **Raw = released/sent.** The Raw tab shows exactly the bytes that will be released or sent. The rendered Preview may summarize, but displays a "hidden in preview: N bytes" indicator for any collapsed, truncated or placeholder region (§6.1).
5. **Decision binding.** A decision is accepted only if its `candidate_rev` equals the request's current revision. Every change to the candidate (redaction, edit, stale refresh, re-render) increments it.

### 5.2 Reads

1. Commit `REQUEST_RECEIVED` (full params), then validate (static schema + field rules + caps + instance version gate). Failure → `REQUEST_REJECTED`, exit 2, nothing queued. (Same order for writes, §5.4 step 1, and scripts, §9.1 step 2.)
2. Fetch. Paginated ops page internally up to `max` (clamped to the op's hard cap), using server-returned page sizes; total fetched bytes per read ≤ 50 MiB (exceeding it → `READ_FAILED {reason: result_too_large}`).
3. Log `READ_FETCHED` (full response, or upstream error).
4. Normalize into the release candidate (§5.3 rules), compute `meta.page`, apply the **release cap: 16 MiB** serialized JSON. Over the cap → `READ_FAILED {reason: result_too_large, size}`, exit 6 with a hint to narrow `fields`/`max`/`expand`. The agent-visible error carries no size and no content (the size is in the audit record and the UI only); the fact that a cap was exceeded is a listed residual channel (§10.2).
5. Build preview; enqueue → `AwaitingRelease`.
6. **Upstream errors** (any HTTP status ≥ 400 except 401) are release candidates too: the preview shows status + capped error body; the user may release (redaction allowed) or deny. Until then the agent sees `pending`. A released upstream error is delivered as `status: failed`, exit 6, `error = {code: "upstream_http", details: {status, error_messages}}` (after redaction). Directly returned without release: 401 (→ `needs_token`, exit 9) and network/TLS errors without a response body (exit 6, `upstream_network`).
7. User: **Release**, **Release with redactions**, or **Deny (reason)** → `READ_RELEASED` (released bytes + redaction operations) or `READ_DENIED`.

### 5.3 Redaction

Operates on the structured release candidate:
- **Drop items** (issues in a result set, comments, child pages, …).
- **Drop fields** (per item or across all items).
- **Mask text** → replaced with `[REDACTED]`. By default masking replaces **every occurrence** of the selected string across all string values of the candidate (HTML-escaped variants included); an option restricts it to the selected occurrence.

Per-op `redaction_rules` ensure copies go too. For Jira: dropping field X also drops `renderedFields.X`, `names.X`, `schema.X`, `editmeta.fields.X`, and changelog items whose `field`/`fieldId` is X. After item drops, `total`/`maxResults` and nested `comment.total`/`worklog.total` are set to the released counts. Before release, the preview lists "also appears in: …" for selected values. **Release is blocked if a string masked in every-occurrence mode still occurs anywhere** in the candidate (substring check, including HTML-escaped variants). For single-occurrence masks, the preview shows "N other occurrences remain" and release requires an explicit confirmation.

The agent receives `redacted: true`, `meta.redactions` (counts + dropped field names), and the optional note. The audit record stores the original fetch (`READ_FETCHED`), the redaction operations, and the released bytes.

### 5.4 Writes

1. Commit `REQUEST_RECEIVED`, then **validate** (static). Body formats converted to the native format here (Markdown → wiki markup / storage XHTML, §7.6).
2. **Enrich** (GET only; logged as `PREVIEW_FETCH {purpose}`; never released to the agent): resolve names (project, issue type, transition, user, parent page), createmeta required fields, current state for diffs (fields / current storage body), current version numbers, Confluence duplicate-title check, attachment filename collision, sprint state, and lossy-conversion detection (§7.6). Enrichment results also form the **stale-check baseline**.
   An enrichment fetch that returns an upstream error puts the request in `AwaitingApproval` with an "enrichment failed" preview: Approve is disabled; the user may deny (reason), optionally attaching the (redactable) error details, which the agent then receives as `denied`, exit 3, `error.details`.
3. **Enqueue** → `AwaitingApproval`.
4. User: **Approve**, **Edit & approve**, or **Deny (reason)**.
   - The edit form is generated from the op's params schema; raw-JSON editor as fallback. **Target-identifying params (`target_params`: instance, issue key, page id, project, space, parent) are read-only** — to retarget, deny with a reason. Edits are re-validated, bodies re-converted, the request list and preview re-rendered (`candidate_rev++`); approval is only enabled on a valid, freshly rendered preview.
   - Logged: `WRITE_EDITED` (original + edited params), `WRITE_APPROVED` (`request_set_hash`, `candidate_rev`).
5. **Stale check** immediately before execution — per-op rule:

   | Op(s) | Stale rule |
   |---|---|
   | `jira.issue.edit` | current values of exactly the edited fields equal the "before" values shown in the diff |
   | `jira.issue.assign` | current assignee equals the previewed one |
   | `jira.issue.transition` | current `status.id` equals the previewed from-status **and** the transition is still listed |
   | `jira.sprint.move_issues` | target sprint `state` still `future` or `active` |
   | `confluence.page.update`, `confluence.page.move` | `version.number` unchanged |
   | `confluence.attachment.upload` with `replace` | attachment `version.number` unchanged |
   | additive / idempotent ops (`jira.comment.add`, `jira.worklog.add`, `jira.issuelink.create`, `jira.issue.create`, `jira.backlog.move_issues`, `confluence.comment.add`, `confluence.label.add`, `confluence.label.remove`, `confluence.page.create`, plain attachment upload) | none — a vanished target surfaces as the write's own error |

   Stale-check and refresh fetches are logged as `PREVIEW_FETCH {purpose: stale_check|refresh}`. If stale → `WRITE_STALE`, back to `AwaitingApproval` flagged **"Changed since you reviewed"** with refreshed enrichment and diff (`candidate_rev++`, "opened" flag cleared). Never auto-retried.
6. **Execute** the approved request list:
   - Success → `WRITE_EXECUTED` (full response; audit only).
   - Server error response (4xx) → `WRITE_FAILED`. A Confluence `409`, or a `400` signalling a version conflict, is recorded as `WRITE_STALE` instead and returns to `AwaitingApproval`.
   - Timeout or connection reset **after** the request was sent, or any 5xx → `WRITE_OUTCOME_UNKNOWN`; status `outcome_unknown`; never retried. Non-GET requests are retried only on 429 (`Retry-After`) and on connection errors that occur before any byte was sent.
   - **Batches** (sprint/backlog moves > 50 issues): approved once, executed as chunks in previewed order; each chunk logs its own `WRITE_EXECUTED`/`WRITE_FAILED`/`WRITE_OUTCOME_UNKNOWN` with `{chunk_index, chunk_count}`. Execution stops at the first chunk that does not succeed; remaining chunks are not sent. The envelope reports `failed` (exit 6) or `outcome_unknown`, with `data.chunks = [{index, items, outcome: succeeded|failed|unknown|not_attempted}]`. Continuing requires a new request.

### 5.5 Scripts

See §9. Internal reads are executed without prompts and logged individually; only the final outcome (result or error details) goes through the release flow.

### 5.6 Approvals UI

- **Queue list**: agent name (text badge "unverified"), op id, **instance alias**, target, age, class (Read/Write/Script), stale flag, **"possible duplicate"** flag (another pending item with the same agent + op + params hash). Grouping by agent with "select all from agent" for batch deny.
- **Detail pane** tabs:
  - *Preview* — rendered, sanitized (§6).
  - *Structured* — item/field tree with redaction controls (reads) or the edit form (writes).
  - *Raw* — exact bytes to be released, or the exact HTTP request list to be sent.
  - *Request* — params, agent `--reason`, instance, connection info (client kind, agent name + source, peer pid, peer exe), timestamps.
- **"Opened"** = Rust has delivered the preview of the item's current revision to the Approvals window in response to a `preview fetch` command. The UI issues that command only on explicit user navigation (click or next/prev keys while the window has focus); auto-display on a new request renders the queue list only and never fetches a preview. Any candidate change (new revision) clears the flag. This guards against blind or accidental approvals, not against a compromised webview (§2.4).
- **Keyboard**: approve/deny/next are modifier chords (e.g. Ctrl/Cmd+Enter), never single keys. Approve/release controls and shortcuts are inert for 1 s after the window gains focus or the displayed candidate changes.
- **Batch**: batch deny is always available. **Batch approve/release is enabled only when every selected item has been opened** in its current revision (checked in Rust); items flagged "possible duplicate" must be selected individually; the request carries each item's `candidate_rev`; mismatches are skipped and reported. Rust shows a **native confirmation dialog** (count, op ids, targets, instance) before applying a batch approval. Each item is logged individually with `batch: true`.
- New request → OS toast (attention only; not actionable), approvals window shown + focused (setting: "focus" | "badge only"), tray badge/tooltip with pending count. **Toast and tray text is app-generated only** (class, op id, pending count) and never interpolates agent-supplied strings.
- Agent-supplied strings (name, reason) are rendered as quoted plain text in a bidi-isolated element (`unicode-bidi: isolate`), after a fixed-width, non-truncatable "unverified" badge; the "unusual characters" flag (§3.3) is shown when set. Op class and target are always displayed from the registry and validated params.
- All badges, warnings and flags are text-labelled with accessible names; colour is never the only signal.
- Approver identity recorded: OS username + the Atlassian username **and user key** bound to the instance PAT.

### 5.7 Other windows

**Settings** (instances, limits, retention/legal hold, focus behaviour, CLI install, recovery/backup, external anchor, confinement status), **Audit** (§8.10), **Running scripts** (§9.6), **Agent onboarding** (§12.4), **Credential entry** (PATs, passphrases, unlock; §10.3).

---

## 6. Previews

### 6.1 Principles

1. The preview is built from the **exact release candidate** (reads) or the **exact request list to be sent** (writes); the Raw tab shows those bytes verbatim (inv. 4).
2. Best effort: unknown structures fall back to a JSON tree; unknown macros to placeholders.
3. Every preview header shows: instance alias, item count ("N of total", or "N shown, more available" when the server reports no total), byte size, fields included, "hidden in preview: N bytes", and **warnings**.
4. All views, including Raw, visibly mark zero-width, bidi-control, other invisible/confusable characters and trailing whitespace, and the header counts them.

### 6.2 Warnings (non-exhaustive)

"contains N custom fields", "all fields requested (`*all`)", "includes restricted-visibility comments", "issue has a security level", "includes summary/status of N linked/parent/sub-task issues", "CQL may enumerate many results", "server-rendered view: macros may include content from other pages", "result truncated by cap (N of M)", "body contains unknown macros", "this update will remove N macros / M images / K links" (§7.6), "N changes not visible in rendered diff", "mention could not be resolved", "invisible characters present (N)", "possible duplicate of req_…".

### 6.3 Per-type previews

| Type | Preview |
|---|---|
| Jira issue | Card: key, summary, type, status, priority, assignee, reporter; table of **every** released field (custom field names resolved via `/rest/api/2/field`); description/comments rendered from wiki markup (local best-effort renderer); restricted comments highlighted. |
| Jira search | Table (key + requested fields), expandable rows, "N of total". |
| Confluence page | Rendered Markdown (from the local storage→Markdown conversion that is also the released text) + Raw tab. |
| Confluence comments | Threaded list with author, date, inline/footer badge. |
| Confluence search | Table: title, space, type, last modified, excerpt (if requested). |
| Lists (projects, spaces, boards, sprints, labels, …) | Table. |
| Create issue/page | Form-like card with resolved names, required-field check, rendered body; duplicate-title warning (Confluence). |
| Edit/update | **Two diffs**: rendered (Markdown-normalized) diff and **raw native diff** (storage XHTML / wiki markup / JSON fields) against the current state. If the raw diff contains changes the rendered diff does not, warning "N changes not visible in rendered diff" linking to the raw diff. |
| Transition | From → to status, plus fields set during transition. |
| Assign / link / labels / worklog / sprint move | Concise summary sentence + affected items table (chunk boundaries shown for batches). |
| Page move | Old ancestor path → new ancestor path. |
| Attachment upload | File name, size, MIME type, SHA-256, image thumbnail (local bytes only); "replaces existing attachment vN" when `replace`. |
| Script result | JSON tree / table auto-detection, plus script source, provenance list, `atlas.log` output and captured stderr. |
| Script error details | Error class, message, stack, elapsed time, provenance, logs. |
| Upstream error (read) / enrichment error (write) | HTTP status, Atlassian `errorMessages`/`errors` (capped 2 KiB). |
| Fallback | JSON tree with sizes. |

### 6.4 Rendering safety

- **Preview iframe**: preview HTML is generated in Rust, sanitized with an allowlist sanitizer (`ammonia`) that **never keeps `style`/`class` attributes or `<style>` elements** (no source-derived colour, size, visibility or position survives; the wiki renderer ignores `{color}` and similar), and displayed in an iframe with `sandbox` (no scripts, no same-origin) whose CSP is `default-src 'none'; style-src 'nonce-<rust-generated>'; img-src data:`; the only stylesheet is the app-owned one carrying that nonce. No remote resource is ever loaded (prevents exfiltration/tracking via image URLs). Server-rendered HTML (`--format view`) goes through the same sanitizer and is labelled as a secondary view.
- Links are shown as text (URL visible), not clickable — **everywhere**, not only in the iframe.
- Invisible and bidi characters (Unicode category Cf, Zl/Zp, U+00AD, U+202A–202E, U+2066–2069) are rendered as visible escapes such as `⟨U+202E⟩` in Preview, Raw and diff views; every rendered field/URL/mention is bidi-isolated (`<bdi>` / `dir=auto`). Warnings: "contains N invisible/zero-width characters", "contains N bidirectional control characters", "source formatting removed (hidden/colour styling present)".
- **Outside the preview iframe**, all request-, agent-, Atlassian- and audit-derived content (Structured, Raw and Request tabs, diffs, script source and logs, error bodies, queue list, Audit window) is rendered as **text nodes only**. `dangerouslySetInnerHTML`, `innerHTML`, `insertAdjacentHTML`, `document.write` and HTML-emitting Markdown/linkify components are banned in `ui/`, enforced in CI by ESLint (`react/no-danger`, `no-unsanitized/*`) plus a grep gate. JSON-tree, diff and code-editor components must render text nodes and must not need `eval` or blob workers.
- **Main-window CSP** (in `tauri.conf.json`, with Tauri's build-time hash/nonce injection): `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src ipc: http://ipc.localhost; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'`. No `'unsafe-inline'`, no `'unsafe-eval'`; runtime CSS-in-JS style injection is not used.

---

## 7. Atlassian adapters

### 7.1 Instances and setup

- Multiple instances per product, each with an alias; one default per product. Instance config (non-secret) in `config.toml` (§7.7); PAT in the keychain under `atlas-duck/<instance-id>` (Windows persistence = Local) or in the vault (§8.6).
- Base URL includes the context path (e.g. `https://wiki.corp/confluence`). Each stored PAT is bound to a hash of its normalized base URL (stored beside the secret). Changing an instance's scheme, host, port or context path — in the UI or by editing `config.toml` — deletes/invalidates the PAT, sets the instance to `needs_token`, and requires re-entry plus a passing connection test (logged `CONFIG_CHANGED` + `CREDENTIAL_CHANGED`); the loader refuses to use a PAT whose URL hash does not match. The per-instance custom CA (stored as a fingerprint) and proxy settings are authoritative in the audit DB like the audit policy (§8.8): a differing value in `config.toml` is logged as `CONFIG_CHANGED {source: file}` and not applied until confirmed in the UI (Rust-drawn confirmation, §10.3).
- Connection test:
  - Jira: `GET /rest/api/2/myself` (identity: `name`, `key`) + `GET /rest/api/2/serverInfo` (version).
  - Confluence: `GET /rest/api/user/current` must be 200 **and** `type == "known"` (anonymous access also returns 200); version from `GET /rest/applinks/1.0/manifest` (`version`, `buildNumber`; present on all DC versions), cross-checked with `GET /rest/api/server-information` on 10.x. A working PAT implies ≥ 7.9.
- Version policy: refuse below PAT support (Jira < 8.14, Confluence < 7.9); warn below Jira 9.12 / Confluence 8.5. If the version stays unknown: warn once and use the most conservative behaviour for version-gated features.
- Ops may declare `min_version`; `ops list/describe --instance X` marks unavailable ops; calling one → exit 2, `op_unsupported_by_instance` `{min_version, instance_version}`, nothing queued.
- PAT expiry / 401 → instance state `needs_token` (logged `INSTANCE_STATE_CHANGED`); requests to it fail with exit 9; UI prompts to re-enter.

### 7.2 HTTP client

- `reqwest` with rustls; trust store = OS roots + optional per-instance custom CA bundle (PEM); honours system/`HTTPS_PROXY` proxy settings, per-instance override.
- Headers: `Authorization: Bearer <PAT>`, `Accept: application/json`, `X-Atlassian-Token: no-check` on every non-GET.
- Method guard: enforces §5.1 inv. 3 (GET + allowlisted POSTs outside approved write execution).
- Per-instance limiter: max 4 concurrent requests (shared by direct reads, enrichment and scripts); token-bucket pacing using `X-RateLimit-*` when present.
- Retries: `429` → honour `Retry-After` (each wait ≤ 30 s), max 3 retries. Non-GET: see §5.4 step 6.
- Time budgets: connect 10 s; 30 s per HTTP call; **120 s total per read request** (all pages and retries); 60 s per write chunk. Exceeded → exit 6 (`upstream_network`) for reads, `outcome_unknown` for sent writes.
- Pagination: offset-based; always use server-returned `maxResults`/`limit`/`total`/`size`; follow `_links.next` only after resolving against the configured base URL and verifying scheme/host/port match.
- Caps: 32 MiB per HTTP response; 50 MiB total fetched per paginated read.

### 7.3 Jira DC operation catalog (REST v2 + Agile 1.0)

**Field rules** (`jira.issue.get`, `jira.search`): accepted `fields` values are system field ids from a fixed list, any `customfield_\d+`, `-<field>` exclusions, and `*all` (preview warns "all fields requested"). `*navigable` is accepted. Unknown custom ids are flagged in the preview (via the cached `/rest/api/2/field`), not rejected (Jira ignores them). `expand` values are allowlisted per op.

| Op id | Class | Endpoint(s) | Notes |
|---|---|---|---|
| `jira.myself` | R | `GET /rest/api/2/myself` | |
| `jira.project.list` | R | `GET /rest/api/2/project` | |
| `jira.project.get` | R | `GET /rest/api/2/project/{key}` | |
| `jira.issue.get` | R | `GET /rest/api/2/issue/{key}` | default `fields=summary,status,issuetype,priority,assignee,reporter,created,updated,labels,components,fixVersions,parent,description,issuelinks,security`; `comments` → same executor as `jira.comment.list` (cap 100, configurable); `changelog` → `expand=changelog`; `rendered` → `expand=renderedFields` (opt-in) |
| `jira.search` | R | `POST /rest/api/2/search` | default fields `summary,status,assignee,priority,issuetype,updated`; `start`, `max` (default 50, hard cap configurable, default 500) |
| `jira.comment.list` | R | `GET /rest/api/2/issue/{key}/comment?orderBy=created` | paged |
| `jira.worklog.list` | R | `GET /rest/api/2/issue/{key}/worklog` | |
| `jira.transition.list` | R | `GET /rest/api/2/issue/{key}/transitions?expand=transitions.fields` | |
| `jira.issue.editmeta` | R | `GET /rest/api/2/issue/{key}/editmeta` | |
| `jira.createmeta.issuetypes` | R | `GET /rest/api/2/issue/createmeta/{project}/issuetypes` | available ≥ 8.4; legacy `/issue/createmeta` never used |
| `jira.createmeta.fields` | R | `GET /rest/api/2/issue/createmeta/{project}/issuetypes/{typeId}` | as above |
| `jira.field.list` | R | `GET /rest/api/2/field` | |
| `jira.issuelinktype.list` | R | `GET /rest/api/2/issueLinkType` | |
| `jira.attachment.meta` | R | `GET /rest/api/2/attachment/{id}` | metadata only |
| `jira.user.assignable` | R | `GET /rest/api/2/user/assignable/search` | |
| `jira.board.list` | R | `GET /rest/agile/1.0/board` | paged |
| `jira.sprint.list` | R | `GET /rest/agile/1.0/board/{id}/sprint` | paged |
| `jira.sprint.issues` | R | `GET /rest/agile/1.0/sprint/{id}/issue` | paged |
| `jira.backlog.issues` | R | `GET /rest/agile/1.0/board/{id}/backlog` | paged |
| `jira.issue.create` | W | `POST /rest/api/2/issue` | body markdown→wiki; enrichment: createmeta required fields |
| `jira.issue.edit` | W | `PUT /rest/api/2/issue/{key}` | `fields` and `update` (labels add/remove via `update`) |
| `jira.comment.add` | W | `POST /rest/api/2/issue/{key}/comment` | optional visibility |
| `jira.issue.transition` | W | `POST /rest/api/2/issue/{key}/transitions` | |
| `jira.issue.assign` | W | `PUT /rest/api/2/issue/{key}/assignee` | `{"name": …}` |
| `jira.worklog.add` | W | `POST /rest/api/2/issue/{key}/worklog` | |
| `jira.issuelink.create` | W | `POST /rest/api/2/issueLink` | |
| `jira.sprint.move_issues` | W | `POST /rest/agile/1.0/sprint/{id}/issue` | chunks of 50; enrichment checks sprint state |
| `jira.backlog.move_issues` | W | `POST /rest/agile/1.0/backlog/issue` | chunks of 50 |

Users: write payloads use `name`; previews and audit record both `name` and `key`. Bodies are wiki markup.

### 7.4 Confluence DC operation catalog (REST `/rest/api`)

| Op id | Class | Endpoint(s) | Notes |
|---|---|---|---|
| `confluence.user.current` | R | `GET /rest/api/user/current` | |
| `confluence.space.list` | R | `GET /rest/api/space` | paged |
| `confluence.space.get` | R | `GET /rest/api/space/{key}` | |
| `confluence.page.get` | R | `GET /rest/api/content/{id}?expand=body.storage,version,space,ancestors` | `format`: `markdown` (default; local conversion; `meta.conversion`), `storage`, `view` (opt-in; `expand=body.view`; warning) |
| `confluence.page.find` | R | `GET /rest/api/content?spaceKey=&title=&type=page` | |
| `confluence.search` | R | `GET /rest/api/search?cql=…&start=&limit=&excerpt=none\|indexed` | app appends ` AND type in (page,blogpost,comment,attachment)` to the agent's CQL; default `excerpt=none` (`highlight` never used); releases `totalSize` and per result `content.id`, `content.type`, `title`, `resultGlobalContainer.title`, `url`, `lastModified`, `excerpt?`; `max` default 25, hard cap configurable (default 200) |
| `confluence.page.children` | R | `GET /rest/api/content/{id}/child/page` | paged |
| `confluence.comment.list` | R | `GET /rest/api/content/{id}/child/comment?expand=body.storage,history,ancestors,version&depth=all` | paged, cap 200; footer + inline |
| `confluence.label.list` | R | `GET /rest/api/content/{id}/label` | |
| `confluence.attachment.list` | R | `GET /rest/api/content/{id}/child/attachment` | metadata only |
| `confluence.page.history` | R | without `version`: `GET /rest/api/content/{id}/history?expand=lastUpdated,previousVersion,contributors.publishers`; with `version=n`: `GET /rest/api/content/{id}?version=n&status=historical&expand=body.storage,version` | exactly one call; DC has no version-list endpoint — agents walk back from the current version (scripts recommended); `format` as `page.get` |
| `confluence.page.create` | W | `POST /rest/api/content` | storage format; enrichment: duplicate-title check, parent resolution |
| `confluence.page.update` | W | `PUT /rest/api/content/{id}` | `version.number + 1`; title kept unless given; lossy-conversion check (§7.6) |
| `confluence.page.move` | W | `PUT /rest/api/content/{id}` with new `ancestors` | same space only; keeps title/body |
| `confluence.comment.add` | W | `POST /rest/api/content` `{type:"comment", container:{id, type:<page\|blogpost from enrichment>}, ancestors?:[{id: reply_to}], body:{storage:{value, representation:"storage"}}}` | params `{content_id, body, body_format, reply_to?}` |
| `confluence.label.add` | W | `POST /rest/api/content/{id}/label` | |
| `confluence.label.remove` | W | `DELETE /rest/api/content/{id}/label/{label}` | |
| `confluence.attachment.upload` | W | new: `POST /rest/api/content/{id}/child/attachment` (multipart `file`, `allowDuplicated=false`); `replace=true`: `POST /rest/api/content/{id}/child/attachment/{attachmentId}/data` | enrichment: filename collision check — a collision without `replace` puts the request in `AwaitingApproval` with an "attachment already exists" preview and Approve disabled (handled like an enrichment failure, §5.4 step 2); max 10 MiB |

### 7.5 Pagination for agents

Paginated read ops accept `start` (default 0) and `max` (op default; clamped to the hard cap). They page internally up to `max`, so server clamping never reaches the agent. The released `meta.page = {start, returned, total|null, truncated, next_start|null}` mirrors the preview's "N of M". Each further page is a separate request with its own release; **for large multi-page reads agents should use a script** (`atlas.all(...)`, §9.2), which needs one release.

### 7.6 Format conversion (`convert` crate)

- **Storage XHTML → Markdown**: wrap fragment in a root declaring `ac:`/`ri:` namespaces; parse with `quick-xml` with an HTML named-entity resolver; map `ac:structured-macro` → `[macro: name {params}]` (rich-text bodies inlined, `ac:plain-text-body` CDATA → fenced code), `ac:link`/`ri:page` → `[title](confluence:SPACE/title)`, `ac:image` → `![filename]`, `ri:user` (`ri:userkey` or legacy `ri:username`) → `@username` resolved via `GET /rest/api/user?key=` during the fetch (cached per instance; unresolved → `@user:<key>`), `ac:task` → `- [ ]`/`- [x]`; remaining HTML → Markdown via `htmd`. Fallback on XML parse failure: extract CDATA bodies first, then html5ever-based conversion. The conversion reports `lossy` + counts of constructs reduced to placeholders. Golden-file tested.
- **Markdown → Jira wiki markup** and **Markdown → storage XHTML**: `pulldown-cmark` event stream with custom renderers (headings, emphasis, lists, code blocks → `{code}` / code macro, tables, links, blockquotes). **All raw HTML and wiki-special sequences (`{`, `[`, `|`, `[~`, `!`, `\`) are escaped**, so Markdown input can never produce macros, mentions or includes. To produce macros/mentions, agents use `--body-format wiki|storage` explicitly. The preview lists every macro, mention, include and link target present in an outgoing payload.
- **Lossy updates**: for `confluence.page.update` with `body_format=markdown`, enrichment compares the current storage body with the outgoing storage; if constructs (`ac:structured-macro`, `ac:image`, `ac:link`, `ri:*`, `ac:layout`) would be lost, the preview shows a prominent warning "this update will remove N macros / M images / K links". `ops describe confluence.page.update` advises `body_format=storage` for pages where `get` reported `meta.conversion.lossy = true`.
- **Wiki markup → preview HTML**: local best-effort renderer (headings, emphasis, lists, tables, `{code}`/`{noformat}`, `{quote}`, links as text, `{panel}` etc. as labelled blocks; unknown macros as placeholders).

### 7.7 Configuration, paths, diagnostics

- **Config** `config.toml` (with `schema_version`) in the per-OS config dir (Windows `%APPDATA%\atlas-duck`, macOS `~/Library/Application Support/atlas-duck`, Linux `$XDG_CONFIG_HOME/atlas-duck`). Holds instances (alias, product, base URL, CA bundle path, proxy), UI preferences, limits. **Audit policy (retention, legal hold, external anchor dir) is authoritative in the audit DB**, not in the config file (§8.8).
- **Data dir** default: `%LOCALAPPDATA%\atlas-duck`, `~/Library/Application Support/atlas-duck`, `$XDG_DATA_HOME/atlas-duck`; overridable only in the first-run wizard (advanced step). Local disk only.
- **Path stability**: base folders are resolved from OS known-folder APIs / the passwd home directory, not per-session environment. XDG overrides and the data-dir override are honoured only at first run and then pinned in `paths.toml` (at the home-derived default config location), which both the app and the CLI read — so differently-configured sessions (SSH, `systemd --user`, IDE sandboxes) always find the same data dir, lock and endpoint file.
- **`cli.toml`** (non-secret) in the config dir: `app_path`, written by "Install CLI to PATH".
- **Diagnostic log** (`tracing`, rolling files under `<data>/logs`, 10 MiB × 5, ≤ 7 days): metadata only — op id, request id, instance alias, HTTP method, path template, status code, duration, error class. **Never** headers, query strings, JQL/CQL, params, request/response bodies, titles, keys or Atlassian error text, at any log level; no setting enables body logging.

---

## 8. Audit log

### 8.1 Storage

- SQLite via `rusqlite` (bundled). Single writer thread in the app; CLI and sandbox never open the DB.
- Pragmas: `journal_mode=WAL`, `synchronous=FULL`, `secure_delete=ON`, `page_size=8192`, `auto_vacuum=INCREMENTAL`. After each prune: `PRAGMA incremental_vacuum` then `wal_checkpoint(TRUNCATE)`.
- **Low-space admission**: before accepting a request, free space on the DB volume must exceed a threshold (default `max(2 GiB, 4 × 24 MiB)`). Below it, new agent requests are refused (`audit_storage_low`, exit 1) with a UI/tray warning; system events and pruning continue within the headroom.

### 8.2 Schema (main table `events`)

| Column | Encrypted? | Content |
|---|---|---|
| `seq` INTEGER PK | no | monotonic |
| `format_version` | no | canonical encoding version (§8.4) |
| `chain_id` | no | random per installation segment (§8.11) |
| `ts_utc` | no | wall clock, RFC 3339 ms |
| `epoch` | no | UTC date, **non-decreasing**: `max(previous epoch, today_utc)` |
| `request_id`, `event_type` | no | |
| `op_id`, `op_class`, `instance_id` | no | |
| `target` | no | issue key / page id / space key / `jql:<sha256>` / `cql:<sha256>` |
| `agent_name`, `agent_name_source`, `client_kind`, `connection_id`, `peer_pid`, `peer_exe` | no | unverified identity |
| `os_user`, `atlassian_user`, `atlassian_user_key` | no | approver/actor (script releases: null; instances listed in payload) |
| `decision` | no | `approve`, `approve_edited`, `release`, `release_redacted`, `deny`, `expire`, `cancel`, `reject`, or null |
| `flags` | no | `edited`, `redacted`, `batch`, `stale`, `partial`, `clock_backwards`, `integrity_incident` |
| `payload_len`, `payload_sha256` | no | of the plaintext payload |
| `key_id`, `nonce`, `payload_ct` | ciphertext | zstd(level 3) → AES-256-GCM |
| `prev_hash`, `record_hash` | no | chain |

Query texts (JQL/CQL), titles and bodies live only in the encrypted payload. Payloads are stored **in full**; sizes are bounded upstream (§5.2, §7.2, §9.4).

### 8.3 Event types

- **Lifecycle**: `REQUEST_RECEIVED`, `REQUEST_REJECTED` (terminal), `REQUEST_FAILED {code}` (terminal; enrichment-phase failures such as `needs_token`/`upstream_network`, and `internal` errors), `PREVIEW_FETCH {purpose: enrich|stale_check|refresh|resolve}` (every app-initiated GET that is not released: enrichment, stale checks, name/user/field resolution), `DECISION_STALE {submitted_rev, current_rev, decision, batch}` (non-terminal; a rejected decision or a skipped batch item), `DELIVERED` `{connection_id, client_kind, agent_name(+source), peer_pid, peer_exe, payload_sha256}` (on every hand-off: submit-wait, `await`, MCP).
- **Reads**: `READ_FETCHED`, `READ_RELEASED`, `READ_DENIED`, `READ_FAILED` (terminal; e.g. `result_too_large`, network).
- **Writes**: `WRITE_EDITED`, `WRITE_APPROVED`, `WRITE_DENIED`, `WRITE_STALE`, `WRITE_EXECUTED`, `WRITE_FAILED`, `WRITE_OUTCOME_UNKNOWN` (chunk events carry `{chunk_index, chunk_count}`).
- **Scripts**: `SCRIPT_STARTED` (source + args + limits), `SCRIPT_CALL` (each internal read: op, params, instance, full response), `SCRIPT_FINISHED`, `SCRIPT_FAILED {reason, data_free: bool}` (reasons incl. `killed_by_user`, `protocol_violation`, `audit_failure`, limit names), `SCRIPT_RELEASED`, `SCRIPT_DENIED`.
- **Terminal**: `EXPIRED`, `CANCELLED`, `ABANDONED`.
- **System**: `GENESIS`, `APP_START` (incl. sandbox confinement status), `APP_STOP`, `CONFIG_CHANGED` (`source: app|file`), `INSTANCE_STATE_CHANGED`, `CREDENTIAL_CHANGED` (PAT or recovery-passphrase change; never the secret), `CHECKPOINT`, `PRUNE`, `EXPORT`, `BACKUP`, `RESTORE`, `KEY_ROTATED`, `VERIFY`, `INTEGRITY_ACK`, `LEGAL_HOLD_CHANGED`, `CLOCK_ANOMALY`.

A request is **terminal** after any of: `REQUEST_REJECTED`, `REQUEST_FAILED`, `READ_RELEASED`, `READ_DENIED`, `READ_FAILED`, `WRITE_EXECUTED` (final chunk), `WRITE_FAILED`, `WRITE_OUTCOME_UNKNOWN`, `WRITE_DENIED`, `SCRIPT_RELEASED`, `SCRIPT_DENIED`, `SCRIPT_FAILED` (where `data_free = true` or `reason = audit_failure`), `EXPIRED`, `CANCELLED`, `ABANDONED`.

### 8.4 Canonical encoding and hash chain

- `canonical_bytes` (versioned by `format_version`): a fixed, ordered field list per version — every column except `record_hash`. Each field: presence byte (0 = NULL, 1 = present), u32-BE length, bytes. Integers fixed-width big-endian; strings UTF-8 (lossless WTF-8 for OS paths). Adding hashed columns bumps `format_version`; old rows verify under their own version. Exact layout fixed by golden test vectors in the `audit` crate.
- `record_hash = SHA-256("atlas-duck/audit/v<format_version>" ‖ prev_hash ‖ canonical_bytes)`. The first record is **`GENESIS`** (`prev_hash` = 32 zero bytes) containing `{chain_id, install_id, created_at, signing_pubkey}`.
- The chain is verifiable **without decryption**: `payload_sha256` (plaintext) is inside the hashed bytes, so hashing a decrypted export payload and comparing binds it to the chain.
- **AAD** for AES-GCM = same encoding over `[format_version, chain_id, seq, ts_utc, epoch, event_type, request_id, op_id, target, key_id, payload_sha256]`, domain `atlas-duck/aad/v1` — prevents moving ciphertexts between rows.
- **Checkpoint signature** input = same encoding over the checkpoint fields, domain `atlas-duck/checkpoint/v1`, Ed25519.

### 8.5 Anchors and checkpoints

- **Head anchor**: `(seq, record_hash)` mirrored into the keychain after commits (batched ≤ 1 s, flushed on `APP_STOP`). Keychain also holds `{chain_id, genesis_hash, first_retained_seq, first_retained_prev_hash}`, updated only by prune/restore.
- **Daily checkpoints**: each checkpoint covers a seq range `(previous checkpoint last_seq, own last_seq]` and records `{epoch, first_seq, last_seq, last_record_hash, count, prev_checkpoint_hash}`, signed with the Ed25519 key. Before appending the first record of a new epoch (or at startup), the writer appends one `CHECKPOINT` per not-yet-checkpointed epoch (count 0 for empty days). Checkpoints form an unbroken chain from `GENESIS`; checkpoint rows are kept for the life of the installation (also mirrored in table `checkpoints`).
- **External anchor** (optional; strongly recommended, and required-with-confirmation in passphrase mode): each signed checkpoint and the signing-key fingerprint are written as JSON files to a user-chosen directory (e.g. a network share), named by `chain_id`.
- **Signing key fingerprint** (SHA-256 of the public key, hex) is shown in Settings and the first-run wizard, and written to the external anchor directory.

### 8.6 Keys and recovery

- **KEK** (32 B random) in the OS keychain (Windows persistence = Local, not roaming). **DEKs**: at least one per UTC month of `epoch`; random 32 B; wrapped by the KEK (AES-256-GCM); stored in table `keys(key_id, month, wrapped_dek, created_at, destroyed_at)`. A restore or rotation adds a new DEK for the current month; each record references its `key_id`.
- **Recovery passphrase** (mandatory at first run; min 12 chars, strength meter): a second copy of the KEK is wrapped with Argon2id (m = 64 MiB, t = 3, p = 4, 16-byte salt) in table `recovery`. Changing it re-wraps (logged `CREDENTIAL_CHANGED`).
- Random 96-bit nonces only; keys in `Zeroizing<[u8; 32]>`.
- Startup self-test: write/read/delete a keychain canary entry. Never a silent fallback to an insecure store.
- **Passphrase mode** (Linux without a usable Secret Service default collection): the app starts **locked** (exit 9 for requests; unlock via the credential-entry window, §2.5). The KEK is unwrapped from `recovery` with the passphrase. PATs and the Ed25519 private key are stored AES-GCM-wrapped under the KEK in table `vault`. The head anchor is a file `<data>/anchor` (0600, fsync + atomic rename) MAC'd with an HKDF-derived key from the KEK; a missing anchor file after first run is a verification failure. **Limitation (stated in Settings and §8.9):** a local anchor detects truncation of the DB alone but not a coordinated rollback of DB + anchor file; only external anchoring protects against that, so passphrase mode without an external anchor directory requires explicit confirmation and shows a persistent warning.

### 8.7 Verification

- **Startup**: keychain canary; decrypt newest record; verify chain from the latest checkpoint to the head; anchor rule:
  - pass if the record at `anchor_seq` exists with `record_hash == anchor_hash` and `db_head_seq ≥ anchor_seq`;
  - `db_head_seq > anchor_seq` (crash within the batching window): verify those tail records, log "N unanchored tail records" in `VERIFY` (informational), advance the anchor;
  - fail if `anchor_seq > db_head_seq` or the hash differs, or if the first retained record does not match `first_retained_seq`/`first_retained_prev_hash`.
  Also reconciles unfinished requests (§11.3) and compares with the external anchor directory when configured.
- **Full verification** (daily background + on demand): the checkpoint chain from `GENESIS` without gaps and with valid signatures; one checkpoint per epoch from install date to yesterday; every retained record; the first retained record's `prev_hash` equals the `last_record_hash` of the checkpoint just before it; no checkpoint with `count > 0` and `epoch ≥ today − retention_days` (or under legal hold) lacks its events; a decrypt pass checking `payload_sha256`; external anchor files match.
- **Integrity incidents** persist: on any failure, a `VERIFY` event with `result` and `{expected_seq, expected_hash, observed_seq, observed_hash, detected_at}` and flag `integrity_incident` is appended **before** any further anchor update; if an external anchor dir is configured, an incident JSON is written there. The red banner (UI + tray) is derived from the log: shown while any integrity-incident `VERIFY` has no later `INTEGRITY_ACK` referencing it. `INTEGRITY_ACK` is created by an explicit "Acknowledge integrity incident" action (OS user + note). The proxy keeps working (so the incident itself stays logged) unless the DB is unwritable.

### 8.8 Retention and policy

- `retention_days`: default 100, **minimum 92** (covers any three calendar months). Stored authoritatively in the audit DB; changed only via the UI (logged `CONFIG_CHANGED`). Legal hold likewise (`LEGAL_HOLD_CHANGED`). On startup, if `config.toml` requests different values, the difference is logged as `CONFIG_CHANGED {source: file, old, new}` before any prune; values below 92 are raised to 92; lifting legal hold or lowering retention never takes effect from a file edit — it needs UI confirmation.
- **Prune** deletes only a contiguous seq prefix ending exactly at the `last_seq` of the newest checkpoint whose epoch is older than the cutoff (`min(today_utc, head epoch) − retention_days`). Never partial checkpoints. Writes `PRUNE {range, count, anchor_checkpoint, cutoff}`, updates `first_retained_*` in the keychain/anchor, and the next `CHECKPOINT` records `{pruned_through_seq, cutoff_epoch}`.
- **Clock guards**: prune is skipped (and `CLOCK_ANOMALY` logged) when `now < ts_utc` of the head record or `now <` the last `PRUNE` time; a run may advance the cutoff by at most 2 epochs beyond the previous `PRUNE` cutoff without explicit UI confirmation — so a forward clock jump can never mass-delete records. A record whose `ts_utc` is > 5 s earlier than its predecessor's gets the `clock_backwards` flag.
- **Crypto-shredding**: once every day of a month is pruned, all DEKs of that month are destroyed (wrapped key overwritten, `destroyed_at` set, noted in `PRUNE`) — never while legal hold is on.
- **Legal hold** pauses pruning and shredding.
- **Storage estimate**: ≈ retention_days × (events/day × ~2 KiB + bytes fetched/released per day ÷ zstd ratio). Example: 500 events/day of typical reads ≈ 1–1.5 GB per 100 days; 20 heavy script runs/day at 50 MiB each ≈ 10–20 GB. Settings shows a gauge, 7-day growth and projected days-to-threshold.

### 8.9 Threat model limits (documented to users)

Protects against: offline theft of the DB; casual/accidental modification; silent truncation of the tail (keychain anchor) or head (genesis/first-retained anchors + checkpoint chain); and — only with external anchoring — rewriting history after a checkpoint was exported. Does **not** protect against malware running as the same OS user while the session is unlocked (it can call the keychain and re-sign), nor — under degraded sandbox confinement (§9.4) — against a sandbox escape, which then equals same-user code execution. A compliance export is trustworthy only against a public key or anchor obtained out of band. Passphrase mode: see §8.6. Backups and exports are outside retention and crypto-shredding (§8.10).

### 8.10 Audit UI, export, backup

- **Audit window**: filter by time range, agent, op, class, instance, target, decision, flags; view decrypted payloads; follow a request's full event trail (incl. deliveries); highlight requests delivered more than once or to a peer different from the submitter; "Verify now"; integrity incidents and acknowledgement.
- **Compliance export**: a time range, widened to whole checkpoint ranges, → directory with `events.jsonl` (every canonical column incl. `key_id`, `nonce`, `payload_ct` base64, **plus** the decrypted payload), `checkpoints.jsonl`, `manifest.json` (boundary `prev_hash`, chain_id(s), public key(s) per segment, restore records). Events after the last signed checkpoint are marked `unanchored`. `atlas-duck-app --verify-export <dir> --pubkey <fingerprint|file> [--anchor-dir <dir>]` recomputes every `record_hash`, the chain, `payload_sha256` of the decrypted payloads, checkpoint signatures, and compares checkpoints with the external anchor. Without `--pubkey`/`--anchor-dir` it reports "internally consistent; trust root NOT verified" and exits non-zero. The export dialog warns that files are decrypted and readable by any same-user process. Logged (`EXPORT`).
- **Full backup**: `VACUUM INTO` snapshot + recovery blob + latest signed checkpoint. Logged (`BACKUP`). The UI states that backups and exports are outside retention/crypto-shredding; their lifecycle is the operator's responsibility.

### 8.11 Restore

1. Verify the snapshot chain up to the bundled signed checkpoint.
2. Unwrap the KEK with the recovery passphrase.
3. Generate a **new `chain_id`**, a new Ed25519 signing key and a new DEK.
4. If the keychain anchor on this machine is ahead of the snapshot head (same-machine rollback), require explicit confirmation showing how many records will be lost.
5. Append `RESTORE {source_chain_id, source_head_seq, source_head_hash, source_pubkey, new_pubkey, backup_created_at, prior_keychain_anchor|null, records_lost}`, then reset the anchors.

The verifier treats `RESTORE` as a segment boundary: records before it verify against `source_pubkey`, after it against `new_pubkey`. `--verify-export` reports two exports sharing a prefix with different `chain_id`s as a **fork**, not tampering; the docs state the old installation must be decommissioned.

### 8.12 Data protection note

The audit log contains personal data of Atlassian users (names, comments, worklogs) and of approvers for the retention period. Plaintext index columns: `target`, `agent_name`, `peer_exe`, `os_user`, `atlassian_user(_key)`, timestamps. Erasure is possible only by whole month after retention (crypto-shredding). Operators should reflect this in their records of processing.

---

## 9. Script sandbox

### 9.1 Flow

1. `atlas-duck script run file.js|- [--args JSON] [--limits JSON]` — the CLI sends **source + args**, never a path.
2. App commits `REQUEST_RECEIVED`, validates (source ≤ 256 KiB, args ≤ 1 MiB JSON, limits keys/values §9.4; failure → `REQUEST_REJECTED`, exit 2), then commits `SCRIPT_STARTED`.
3. App spawns `atlas-duck-sandbox` with OS limits and confinement (§9.4) and sends `{source, args, limits}` over stdin.
4. Each `atlas.*` call → `host.call` → the app validates (**Read class only**, schema, field rules, caps, instance), executes via the shared client/limiter, commits `SCRIPT_CALL` (full response), **then** returns the result to the worker. If the append fails, the script is killed (`SCRIPT_FAILED {audit_failure}`), nothing is released.
5. Worker returns `script.result` (JSON) or `script.error`; the app also observes limits and process exit.
6. Outcome classification and release per §9.5.

### 9.2 Script API

The source is wrapped as the body of `async function main(args, atlas) { … }`; its return value (JSON-serializable) is the result.

```js
const res = await atlas.jira.search({ jql: `project = ${args.project} AND resolution = Unresolved`,
                                      fields: ["summary","status","assignee"], max: 500 });
const byAssignee = {};
for (const i of res.issues) (byAssignee[i.fields.assignee?.name ?? "unassigned"] ??= []).push(i.key);
atlas.log(`processed ${res.issues.length} issues`);
return byAssignee;
```

- `atlas.<product>.<…>(params, {instance}?)` — async functions mirroring every **Read** op (generated from the registry), returning the same `result` shape as the CLI's `data.result` (unredacted — redaction applies only at release).
- `atlas.call(opId, params, {instance}?)`, `atlas.all(opId, params, {instance}?)` (pages through any paginated read up to the per-run caps), `atlas.ops()`, `atlas.instances()`, `atlas.log(...strings)`.
- `atlas` and `args` are deep-frozen.

### 9.3 Engine configuration

- `rquickjs` pinned exact version; features `futures`, `macro` only (no `loader`, `dyn-load`, `parallel`).
- Context with minimal intrinsics: base objects, Eval (required to load source; harmless inside the sandbox), JSON, Promise, RegExp, MapSet, Date. **Excluded**: TypedArrays/ArrayBuffer, Proxy, WeakRef, Atomics/SharedArrayBuffer, Performance. No module loader (any `import` fails).
- One fresh Runtime per run, confined to a single thread with an 8 MiB native stack; `set_max_stack_size(1 MiB)`; `set_memory_limit(heap limit)`; `set_gc_threshold`.
- Interrupt handler checks deadline, cancel flag, and op budget (catches CPU-bound loops).
- Only JS source is accepted — never bytecode.

### 9.4 Limits and confinement

| `--limits` key | Default | Enforcement |
|---|---|---|
| `timeout_s` (wall clock incl. awaits) | 120 | interrupt handler + host-side kill of the process |
| `heap_mb` | 64 | `set_memory_limit`; OOM is terminal (host-decided) |
| `process_mb` | 256 | Windows job object / Linux `setrlimit(RLIMIT_AS)` / macOS host-side watchdog (polls `proc_pid_rusage` `ri_phys_footprint` every 100 ms, SIGKILL above the limit; `RLIMIT_AS` is not enforced on Darwin) |
| `max_calls` | 200 | host |
| `max_fetch_mb` (bytes fetched per run) | 50 | host |
| `max_call_result_mb` (per host-call response after normalization) | 16 | host; over → the call rejects inside the script with `result_too_large` |
| `max_result_mb` (final result) | 16 | host |
| `max_concurrent_calls` | 4 | host |
| — concurrent scripts | 2 (queued beyond) | host |

Defaults configurable in Settings. Agents may request **lower** values via `--limits`; unknown keys or values above the configured default → exit 2, nothing queued.

**OS confinement of the worker** (best effort beyond a mandatory floor):
- **Linux** — applied by the worker to itself after its single JS thread exists and before it reads stdin: `PR_SET_NO_NEW_PRIVS`; Landlock handling all filesystem rights the kernel's ABI supports with no rules (plus ABI ≥ 4 network rules and ABI ≥ 6 scopes when available); **seccomp-bpf in default-kill mode with an enumerated allowlist** kept in one reviewed file (read on fd 0, write on fds 1/2, memory management, futex, clocks, `getrandom`, signal return/mask, exit). After setup `clone3` returns `ENOSYS` and `clone` is denied; excluded among others: `execve(at)`, `socket(pair)`, `open*`, `io_uring_*`, `ptrace`, `process_vm_*`, `bpf`, keyring calls, `unshare`/`setns`. The parent sets `PR_SET_PDEATHSIG(SIGKILL)` and rlimits (`AS`, `NOFILE`, `CORE=0`) before exec. Network blocking relies on seccomp, not Landlock.
- **macOS** — the worker calls `sandbox_init` with an embedded deny-by-default SBPL profile: no network, no file access after startup, no fork/exec, no `mach-lookup` (blocks securityd/keychain and pasteboard). This calling mode is deprecated and undocumented, so it is verified by probes (below) and listed in §15. Memory via the host-side watchdog.
- **Windows** — the worker runs in an **AppContainer** with zero capabilities (Less-Privileged AppContainer where all needed ACEs exist), so it has no network access and only explicitly granted file access; the installer grants (L)PAC read+execute on the worker binary and every DLL it loads. Job object: `ACTIVE_PROCESS=1`, `KILL_ON_JOB_CLOSE`, `DIE_ON_UNHANDLED_EXCEPTION`, process memory limit, `JOB_OBJECT_UILIMIT_ALL`. If AppContainer creation fails (e.g. per-user install without the ACEs), the only available configuration is a lockdown token (restricting SID = NULL SID, untrusted integrity, applied after startup) + job object, in which file reads and network may not be blocked — this is **below the floor** (degraded).

**Mandatory floor and probes.** Per OS floor: Linux `no_new_privs` + seccomp; macOS seatbelt profile + watchdog; Windows AppContainer + job object. On each app start, and before the first script, the host runs a **probe worker** that attempts: opening a file in the user profile, `socket()`/`connect()` to 127.0.0.1 and a public IP, spawning a process (incl. raw `clone`/`clone3` on Linux), reading the app's memory, and (Windows) `CredReadW`/`OpenClipboard`, (macOS) a securityd `mach-lookup`. Results are recorded in `APP_START` and shown in Settings. **If the floor cannot be applied and verified, scripts are disabled** (`failed`, exit 8, `error.code = sandbox_unavailable`). An explicit Settings toggle "Allow scripts with degraded confinement" re-enables them with a persistent warning and is audit-logged (`CONFIG_CHANGED`). Missing extra layers (e.g. Landlock on older kernels) are reported but do not disable scripts. Under degraded confinement, a worker compromise is equivalent to same-user code execution (§8.9).

### 9.5 Outcome classification and leak prevention

Classification is by **data exposure**, not by error type, and is decided **only by the host from its own state**: `script_syntax` only for a compile-phase failure before the host delivered any host-call result; `script_limit` only for limits the host itself measured (its timer and counters, the job-object/rlimit/watchdog kill reason, host-decided OOM); everything else is a runtime outcome. The worker's self-reported class and message are untrusted payload, stored only for the release preview.

- A run is **data-free** if no `SCRIPT_CALL` was committed for it (every host call that reached Atlassian — successful, upstream-error rejection, or `result_too_large` rejection — commits a `SCRIPT_CALL` before anything is returned to the worker). Data-free failures — compile/syntax errors raised before `main` runs, and limits hit before the first host-call result — are returned directly: `failed`, exit 8, `error.code = script_syntax | script_limit` (syntax errors include line/column/message).
- **Every other termination** — success, runtime error (including a `SyntaxError` from `JSON.parse`/`eval` of fetched text), any limit (timeout, OOM, budgets, size), user kill, worker crash, protocol violation — becomes a single `AwaitingRelease` item. **Exception**: an audit append failure always ends the run as `failed`, `audit_failure`, exit 1 (§5.1 inv. 1), with nothing released. The candidate is the result, or the error details `{class, message, stack, elapsed, logs}`. Until the decision, the agent sees only `pending` (§4.5): no error class, no timing, no Running/AwaitingRelease distinction.
- On release of a result: `released`, exit 0. On release of error details: `released`, exit 8, `data.script_error`. On deny: `denied`, exit 3.
- `atlas.log` output and captured stderr never reach the agent unless the user includes them in a release.

### 9.6 Running-scripts UI

Live list: agent, instance(s), started, elapsed, host calls, bytes fetched; per-script kill button (→ the run becomes an AwaitingRelease item per §9.5, with reason `killed_by_user`).

---

## 10. Security summary

### 10.1 Defense in depth

| Layer | Control |
|---|---|
| Credentials | PATs only in OS keychain (or KEK-wrapped vault), used only by the app's HTTP client; never in IPC, UI, logs, sandbox. |
| Local access | User-restricted pipe/socket; peer uid/SID checks; anti-squatting on both sides; detached app launch. |
| Capability | Fixed operation registry; field/expand rules; caps; method guard (GET + allowlisted POST outside approved writes); no passthrough. |
| Human control | Every write approved byte-for-byte (request-set hash); every read released; edits/redactions re-validated in Rust; decision bound to `candidate_rev`; stale check before writes; no blind approvals (opened-flag, modifier chords, focus delay). |
| Opacity | Agent sees only agent-visible status changes (§4.5); upstream errors and script outcomes after data exposure are release-gated. |
| Script isolation | Separate process, no credentials, minimal JS intrinsics, resource limits, OS confinement, Read-only enforced host side. |
| Data exfil via UI | Sanitized previews, no remote loads, links as text, invisible-character marking, raw diffs. |
| Frontend | In the TCB (§2.4). Per-window capabilities and navigation lockdown (§10.3), explicit CSP and text-only rendering outside the sandboxed preview iframe (§6.4), `freezePrototype`, isolation hook with command allowlist + argument schemas, decision binding and opened-state in Rust, native Rust confirmation for batch approvals and security-weakening settings, devtools disabled, debug env vars scrubbed (§2.5). |
| Process hardening | App non-dumpable / memory-read protected (§2.5); CLI launches the app detached with a sanitized environment (§4.7); worker spawned with an explicit handle list and empty environment (§3.4). |
| Logs | Diagnostic logs metadata-only; Atlassian content persisted only in the encrypted audit. |
| Audit | Encrypted payloads, AAD binding, hash chain from genesis, head/first-retained anchors, signed checkpoints, optional external anchor, persistent integrity incidents, retention ≥ 92 days with clock guards. |
| Supply chain | `cargo-deny`, `cargo-audit`, `npm audit` in CI; pinned rquickjs; QuickJS-NG security advisories applied within 7 days. |

### 10.2 Residual channels (accepted, documented)

- **Decision timing**: when the agent's call returns reveals when the human decided (and that a decision was approve/deny). This is chosen by the user, not by data.
- **Data-free failures**: validation errors (static), 401/needs-token state, network/TLS errors without a body, and data-free script failures reveal no Atlassian content.
- **Busy/queue signals**: reveal only queue load.
- **Content-size outcomes**: `result_too_large` (release cap or 50 MiB fetch cap) and read time-budget expiry are returned without release and reveal that a result exceeded a cap or took too long (no size, no content).
- **Write error text**: after an approved write fails with 4xx, the Atlassian `errorMessages`/`errors` (≤ 2 KiB) are returned without a separate release; they describe the approved payload but may quote server state.
- **Same-user processes** can list and `await` any request (including released data within the 1 h window); every delivery is logged with the recipient and highlighted in the Audit window.

### 10.3 Frontend lockdown

- **Per-window capabilities** (Tauri capability files, `app.security.capabilities` set explicitly; all custom commands declared in the app manifest; tested in §13 that commands outside a window's grant are rejected):

  | Window | Granted commands |
  |---|---|
  | Approvals | queue list/get, preview fetch for a rev, approve/deny/edit/redact, batch request (Rust confirms natively) |
  | Audit | read-only queries and payload view; export/backup/verify **triggers** (no path arguments) |
  | Settings | settings, instance setup, **credential-entry trigger** (opens the credential window), CLI install, retention/legal hold, confinement toggle |
  | Credential entry | `submit_secret` only (PAT, recovery passphrase, unlock passphrase) |
  | Running scripts | list, kill |
  | Onboarding | read-only registry/onboarding text |

  No window gets shell, fs, http, opener, clipboard-read or remote-URL capabilities. Decision commands exist only in the Approvals window; credential commands only in Settings. The Audit window is a separate webview whose capability file grants no decision commands; it renders decrypted payloads through the same sanitized, sandboxed-iframe path as §6.4.
- **Navigation**: every webview registers an `on_navigation` handler that allows only the app's own origin (`tauri://localhost` / `http://tauri.localhost`); `window.open`/new-window requests are denied. No external-link opener in v1 — URLs are copyable text. No clipboard-read; copy is write-only on a user gesture.
- **Secrets** (PATs, recovery passphrase, unlock passphrase) are entered only in a dedicated, Rust-opened **credential-entry window**: a separate webview with a static bundled page, no untrusted content, and a single write-only `submit_secret` command (it is also used for first-run and unlock). Secrets are never sent to, displayed in, or returned to any webview after entry; other windows can only trigger the credential window.
- **Paths and certificates** for export, backup, restore, external anchor directory and custom-CA import are chosen in a **native dialog opened by Rust**; no command accepts a filesystem path or certificate bytes from the webview. A custom CA shows its fingerprint and subject in the Rust-drawn dialog.
- **Security-weakening settings** (restore backup, add custom CA, lift legal hold, lower retention, raise limits, enable degraded script confinement, switch focus to "badge only", passphrase mode without external anchor) require a Rust-drawn native confirmation and are logged as `CONFIG_CHANGED` with old and new values.

---

## 11. Error handling

### 11.1 Fail-closed rules

- Audit append failure → no upstream call / release / execution; request `Failed`, `audit_failure`, exit 1; UI banner.
- Low audit storage → new requests refused (`audit_storage_low`, exit 1).
- Keychain unavailable / passphrase mode locked → all requests rejected, exit 9.
- Validation failure → exit 2, nothing queued, logged `REQUEST_RECEIVED` (committed before validation) + `REQUEST_REJECTED`.

### 11.2 Upstream errors

- **Reads / script calls / enrichment**: HTTP status ≥ 400 (except 401) is content — release-gated (§5.2 step 6, §5.4 step 2, §9.5). For scripts, an upstream error is returned to the script as a rejected promise (it is fetched data; the run is no longer data-free).
- **401** → instance `needs_token` (logged `INSTANCE_STATE_CHANGED`). Direct reads (`READ_FAILED`) and enrichment (`REQUEST_FAILED`): `failed`, exit 9, directly. Script host calls: the call rejects inside the script with `needs_token` (run outcome per §9.5). Write execution: `WRITE_FAILED`, `failed`, exit 9 `needs_token`.
- **429** → bounded retry (§7.2), then the same as other upstream errors.
- **Network/TLS errors without a response**, and read time-budget expiry (§7.2) → direct reads and enrichment: exit 6 `upstream_network` with a clear message (e.g. "certificate not trusted — add a custom CA in Settings"); script host calls: the call rejects inside the script; sent writes: `outcome_unknown` (§5.4 step 6).
- **Writes after approval**: 4xx (other than 401) → `WRITE_FAILED`, the Atlassian `errorMessages`/`errors` (capped 2 KiB) returned with exit 6 (the user approved this write; the error describes the agent's own payload — a listed residual channel, §10.2). Version conflicts → `WRITE_STALE` (§5.4). Timeout/reset after send/5xx → `outcome_unknown`.

### 11.3 Crash / restart reconciliation

- Pending requests are in memory; on crash, CLI connections drop (exit 5 for waiting CLIs; the request id was already printed to stderr).
- On startup, the app scans for request ids whose last event is non-terminal and appends `ABANDONED`; writes whose last event is `WRITE_APPROVED` or a non-final chunk get `WRITE_OUTCOME_UNKNOWN` (listing completed chunks), and the user sees a notice listing targets to check.
- `await`/`status` on such ids return `abandoned` (exit 7) or `outcome_unknown` (exit 6), read from the audit log. An unknown id → exit 2 (`unknown_request`).

### 11.4 UI resilience

The Rust core is the single source of truth; reloading the webview loses no state.

---

## 12. Packaging, distribution, onboarding

### 12.1 Binaries

`atlas-duck-app` (main), `atlas-duck` (CLI + MCP), `atlas-duck-sandbox` are all `[[bin]]` targets of the Tauri package (thin `main`s calling into their crates), so the Tauri bundler ships them next to the app on every platform without target-triple renaming. `default-run = "atlas-duck-app"`.

### 12.2 Per OS

- **Windows**: NSIS installer, `installMode: both`; per-machine (Program Files) recommended for tamper resistance. Authenticode signing. WebView2 bootstrapper.
- **macOS**: `.dmg`, signed + notarized, hardened runtime; every binary in `Contents/MacOS` signed. Separate arm64 and x86_64 builds in v1 (universal builds need custom `lipo` for extra bins).
- **Linux**: `.deb` and `.rpm` (binaries in `/usr/bin`, CLI on PATH; depends on WebKitGTK 4.1 and libayatana-appindicator3), AppImage (CLI via in-app install).

### 12.3 Install CLI to PATH (in-app, all OSes)

Writes `cli.toml` (`app_path`). Windows: append install dir to `HKCU\Environment\Path` (REG_EXPAND_SZ) + broadcast `WM_SETTINGCHANGE`. macOS: symlink `~/.local/bin/atlas-duck` (or `/usr/local/bin` with admin prompt). Linux AppImage: wrapper script in `~/.local/bin` that exports the absolute AppImage path as `APPIMAGE` and invokes it in CLI mode. deb/rpm: already on PATH.

### 12.4 Agent onboarding

A Settings page generates copy-paste instructions (for CLAUDE.md / AGENTS.md / MCP client config) from the registry:
- commands, the envelope, the status/exit matrix;
- "approvals take human time: set `--timeout` at least 10 s below your tool's kill timeout (e.g. `--timeout 100` under a 120 s tool), or use `--timeout 0` and `await`; the request id is printed to stderr on submit; **never resubmit a pending request — use `requests list` / `await`**";
- "results may be redacted or edited — check `redacted`, `edited`, `meta`";
- "batch many reads into one script instead of many parallel calls; on exit 11 back off";
- "on `outcome_unknown`, check the target before retrying";
- "Confluence pages with macros: edit with `body_format=storage`";
- pass file paths rather than piping through Windows PowerShell 5.1;
- the script API reference with examples, and the MCP server config snippet (including `ATLAS_DUCK_MCP_TIMEOUT` and `--tools generic` for tool-limited clients).

---

## 13. Testing strategy

| Level | What |
|---|---|
| Unit | State machine property tests (proptest): invariants §5.1 under random event sequences, including candidate_rev races, stale loops, chunk failures. Method guard: no Read/enrichment/script path can emit a non-GET outside the allowlist; Write execution sends exactly the approved request set. Audit: tamper tests (modify/delete/reorder/truncate tail/truncate head/ciphertext-swap/checkpoint deletion → verify fails), canonical-encoding golden vectors, crypto round-trips, prune keeps verifiability, clock jumps (forward/backward) never over-prune, restore segments and fork detection, anchor rules after crash, integrity incident persistence. Converters: golden files (storage→md incl. CDATA, macros, entities, user mentions; md→wiki and md→storage incl. escaping of raw HTML/wiki specials; wiki→html). Redaction engine incl. copies and mask-everywhere. Params validation, field rules, CLI flag binding. |
| Integration | Mock Jira/Confluence DC (`wiremock`) with fixtures modelled on Jira 9.12/10.x and Confluence 8.5/9.x; full CLI → IPC → core → mock → audit flows using a headless **scripted approver** in place of the UI; MCP front end via an MCP test client (heartbeats, timeout result, cancel semantics). Opacity tests: agent-visible status/progress streams are identical for released vs denied-later vs upstream-error vs script-limit-after-data cases until the decision. CLI killed mid-wait → request survives, id on stderr, `requests list` finds it. |
| Security | IPC: other-user connection rejected (Linux CI with a second user); a second Windows account that creates a pipe with the name written in the endpoint file (simulated) → CLI exits 5 without sending; Windows pipe DACL and client SQOS level inspected; `hello` deadline/ordering; busy handling never triggers a launch; AppImage and deb-upgrade anti-squatting cases; two app instances with different environments cannot both open the audit store. Launch: the app survives killing the launching CLI/MCP process tree and job; `atlas-duck mcp` stdout carries only JSON-RPC when it auto-launches the app; no debug port opens when WebView2/WebKit inspector variables are set. Process hardening: a child cannot read the app's memory. Frontend: injection payloads (`<script>`, `onerror`, `javascript:`) in every field of every tab and the Audit window do not execute; commands outside a window's capability grant are rejected; navigation to foreign origins is blocked. Sandbox channel fuzzing: malformed, oversize and out-of-order frames, log floods and host-call floods stay within caps and end in `protocol_violation`; the worker sees no descriptors/handles other than its three pipes and an empty environment. Sandbox: scripts attempting fs/net/`import`/infinite loops/memory bombs/deep recursion/write ops/error-message leaks/data-dependent limit errors → contained, and data-dependent failures yield `pending`; OS confinement probes per OS. Preview: HTML with remote images/scripts neutralized; invisible characters marked; raw-only diff changes flagged. Diagnostic logs contain no content (grep test over a full integration run). |
| UI | Vitest + Testing Library component tests (opened-flag, focus delay, batch rules, read-only target fields); `tauri-driver` WebDriver smoke tests on Windows and Linux. |
| Live (opt-in) | Env-gated tests against real DC instances (e.g. Atlassian trial Docker images), covering the §15 verification items. |
| CI | Matrix: Windows (MSVC), macOS (arm64), Ubuntu 22.04; `cargo test`, `clippy -D warnings`, `cargo-deny`, `cargo-audit`, UI tests, bundle build. |

---

## 14. Implementation milestones (for the plan)

1. **Workspace & skeleton**: crates, Tauri tray app shell, CI matrix, three bins bundled, config/paths, diagnostic logging.
2. **Audit store**: schema, canonical encoding, crypto, chain + genesis, anchors, checkpoints, recovery, passphrase-mode vault, retention + clock guards, verification + incidents, restore — fully tested in isolation.
3. **IPC + CLI skeleton**: transports per OS with peer checks and anti-squatting, handshake, envelope + status/exit matrix, submission notice, `ops list/describe`, `await/status/cancel/requests list`, app auto-launch, `doctor`.
4. **Core lifecycle**: registry, state machine + invariants, method guard, queue + limits, opacity rule, headless scripted approver, redaction/edit engine, credential provider + keychain storage, headless instance setup for tests.
5. **Jira adapter + previews** (core then extended ops), wiki/markdown converters, stale rules, chunked batches.
6. **Approvals UI**: queue, previews, raw diffs, redaction/edit, opened-flag/focus/batch rules, notifications/tray badge, settings, instance setup, first-run wizard, credential-entry window (incl. unlock).
7. **Confluence adapter + previews** (core then extended ops), storage converters, lossy-update detection, user resolution.
8. **Script sandbox**: worker, host bridge, limits, OS confinement, outcome classification, running-scripts UI.
9. **MCP front end** (full/generic tools, heartbeats).
10. **Audit UI, export/verify-export, backup/restore, onboarding page, packaging & PATH install**, hardening and docs.

---

## 15. Items to verify during implementation

- Exact Windows pipe access mask (no `FILE_CREATE_PIPE_INSTANCE`).
- Whether rquickjs `Context::custom` without some intrinsics still supports host-side `eval` of source (Eval intrinsic expected to be required).
- rquickjs on `x86_64-pc-windows-msvc` (README marks MSVC experimental) — CI early.
- Confluence: comment creation payload (container type, reply `ancestors`), `child/comment` `depth=all`/location behaviour, `?version=N&status=historical` on 8.5/9.x; `/rest/applinks/1.0/manifest` availability with PAT; `/rest/api/search` `excerpt=indexed` and `totalSize` on 8.5/9.x; PUT version-conflict status (409 vs 400).
- Jira DC `maxResults` clamping defaults on 10.x/11.x; labels `update` syntax; assignee unassign sentinel.
- macOS `LOCAL_PEEREPID` semantics vs `LOCAL_PEERPID` for peer exe display.
- `keyring` 4.x / `keyring-core` store crates per OS and exact versions; Windows persistence setting.
- Windows AppContainer/LPAC worker: `CredReadW`, `CreateFileW` on `%USERPROFILE%`, `connect()` and `OpenClipboard` all fail (CI probe); the exact set of DLLs needing (L)PAC ACEs; stdio pipe handles via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` work inside the AppContainer.
- macOS `sandbox_init` with a custom SBPL profile (deprecated, undocumented): re-verify on each new macOS major via the probe worker; confirm `RLIMIT_AS` is a no-op on the CI macOS image.
- Linux seccomp allowlist completeness on each supported glibc/musl target (worker runs its full test suite under the filter).
- Inherited-handle behaviour of the chosen spawn APIs per OS.

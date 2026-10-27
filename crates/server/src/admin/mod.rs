//! The admin CLI's server side (SM-3.5, SM-8.1, M13 PD-M13-1): `atlas-duck-server admin …` talks
//! to the running server over a Unix socket, so the server stays the only process that opens the
//! stores (ADR 0003). One request per connection: one JSON line in, one JSON line out, unknown
//! fields refused. The socket lives in [`socket`] (Unix only); the request handling here is
//! platform-independent and tested over in-memory streams.

pub mod anchor;
pub mod backup;
pub mod backups;
pub mod client;
pub mod instances;
pub mod maintenance;
pub mod restore;
pub mod retention;
pub mod rotate;
#[cfg(unix)]
pub mod socket;
pub mod stream;
pub mod tarball;
pub mod users;

#[cfg(test)]
#[path = "../tests/admin_backup.rs"]
mod backup_tests;
#[cfg(test)]
#[path = "../tests/admin_retention.rs"]
mod retention_tests;
#[cfg(test)]
#[path = "../tests/admin_rotate.rs"]
mod rotate_tests;
#[cfg(test)]
#[path = "../tests/admin.rs"]
mod tests;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::anchor::AnchorWriter;
use crate::api_keys::ApiKeys;
use crate::clock::Clock;
use crate::runtime::Registry;
use crate::session::SessionTable;
use crate::store::ServerStore;

/// A request line is at most this long (`admin/request_too_large`).
pub const MAX_LINE: usize = 64 * 1024;

/// How long a connection may take to send its request line.
pub const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// SM-6.5 default retention period of a deactivated user's chain.
pub const DEFAULT_RETENTION_DAYS: u32 = 365;

/// What the admin operations act on: the serving process's own store, runtimes, sessions and keys.
pub struct AdminCtx {
    pub store: Arc<dyn ServerStore>,
    pub registry: Arc<Registry>,
    pub sessions: Arc<SessionTable>,
    pub api_keys: Arc<ApiKeys>,
    pub writer: Arc<AnchorWriter>,
    pub clock: Arc<dyn Clock>,
    pub retention_days: u32,
    /// Final review M4: the most file data a streamed restore accepts.
    pub max_stream_bytes: u64,
    /// ADR 0004: where the scheduler keeps daily backups (`ATLAS_DUCK_BACKUP_DIR`), and how many.
    pub backup_dir: Option<std::path::PathBuf>,
    pub backup_keep: u32,
    /// Admin operations run one at a time.
    ops: tokio::sync::Mutex<()>,
}

impl AdminCtx {
    pub fn new(
        store: Arc<dyn ServerStore>,
        registry: Arc<Registry>,
        sessions: Arc<SessionTable>,
        api_keys: Arc<ApiKeys>,
        writer: Arc<AnchorWriter>,
        clock: Arc<dyn Clock>,
        retention_days: u32,
    ) -> AdminCtx {
        AdminCtx {
            store,
            registry,
            sessions,
            api_keys,
            writer,
            clock,
            retention_days,
            max_stream_bytes: stream::DEFAULT_MAX_STREAM_BYTES,
            backup_dir: None,
            backup_keep: crate::config::DEFAULT_BACKUP_KEEP,
            ops: tokio::sync::Mutex::new(()),
        }
    }
}

impl AdminCtx {
    /// Sets the streamed-restore bound (`ATLAS_DUCK_MAX_RESTORE_BYTES`).
    pub fn with_max_stream_bytes(mut self, n: u64) -> AdminCtx {
        self.max_stream_bytes = n;
        self
    }

    /// Sets the scheduled backups' directory and how many bundles it keeps (ADR 0004).
    pub fn with_scheduled_backups(
        mut self,
        dir: Option<std::path::PathBuf>,
        keep: u32,
    ) -> AdminCtx {
        self.backup_dir = dir;
        self.backup_keep = keep;
        self
    }

    /// The admin operation lock: the scheduler's jobs take it too, so they never overlap a command.
    pub async fn lock_ops(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.ops.lock().await
    }
}

/// No arguments; any field is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceArgs {
    pub alias: String,
    pub product: String,
    pub url: String,
    #[serde(default)]
    pub default: bool,
    #[serde(default)]
    pub ca_org: bool,
    #[serde(default)]
    pub proxy: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasArg {
    pub alias: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsernameArg {
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchArg {
    pub on: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirArg {
    pub dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyFileArg {
    pub new_key_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DryRunArg {
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameArg {
    pub name: String,
}

/// One admin request (`{"op": "...", ...}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    InstancesList(NoArgs),
    InstancesAdd(InstanceArgs),
    InstancesRemove(AliasArg),
    UsersList(NoArgs),
    UsersDeactivate(UsernameArg),
    Maintenance(SwitchArg),
    Backup(DirArg),
    Restore(DirArg),
    RestoreResume(NoArgs),
    RotateMasterKey(KeyFileArg),
    MasterKeyStatus(NoArgs),
    /// `backup --stdout`: the answer line, then the bundle as a tar stream.
    BackupStream(NoArgs),
    /// `restore --stdin`: the request line, then the bundle as a tar stream.
    RestoreStream(NoArgs),
    BackupsList(NoArgs),
    BackupsRemove(NameArg),
    /// `backups export <name> --stdout`: like `BackupStream` for a kept bundle.
    BackupsExport(NameArg),
    RetentionRun(DryRunArg),
    AnchorVerify(NoArgs),
}

impl Request {
    /// The op name for logs (never an argument).
    pub fn op(&self) -> &'static str {
        match self {
            Request::InstancesList(_) => "instances_list",
            Request::InstancesAdd(_) => "instances_add",
            Request::InstancesRemove(_) => "instances_remove",
            Request::UsersList(_) => "users_list",
            Request::UsersDeactivate(_) => "users_deactivate",
            Request::Maintenance(_) => "maintenance",
            Request::Backup(_) => "backup",
            Request::Restore(_) => "restore",
            Request::RestoreResume(_) => "restore_resume",
            Request::RotateMasterKey(_) => "rotate_master_key",
            Request::MasterKeyStatus(_) => "master_key_status",
            Request::BackupStream(_) => "backup_stream",
            Request::RestoreStream(_) => "restore_stream",
            Request::BackupsList(_) => "backups_list",
            Request::BackupsRemove(_) => "backups_remove",
            Request::BackupsExport(_) => "backups_export",
            Request::RetentionRun(_) => "retention_run",
            Request::AnchorVerify(_) => "anchor_verify",
        }
    }
}

/// One admin answer: `{"ok": true, "data": ...}` or `{"ok": false, "error": "<code>"}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn ok(data: Value) -> Response {
        Response {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    /// A failure that carries a report (`anchor verify`'s findings).
    pub fn err_with(code: &str, data: Value) -> Response {
        Response {
            ok: false,
            data: Some(data),
            error: Some(code.to_owned()),
        }
    }

    pub fn err(code: &str) -> Response {
        Response {
            ok: false,
            data: None,
            error: Some(code.to_owned()),
        }
    }
}

/// Runs one request.
pub async fn handle(ctx: &AdminCtx, req: Request) -> Response {
    let op = req.op();
    let _one = ctx.ops.lock().await;
    let out = match req {
        Request::InstancesList(_) => instances::list(ctx),
        Request::InstancesAdd(a) => instances::add(ctx, a).await,
        Request::InstancesRemove(a) => instances::remove(ctx, &a.alias).await,
        Request::UsersList(_) => users::list(ctx),
        Request::UsersDeactivate(u) => users::deactivate_by_name(ctx, &u.username).await,
        Request::Maintenance(m) => maintenance::set(ctx, m.on),
        Request::Backup(d) => backup::run(ctx, &d.dir).await,
        Request::Restore(d) => restore::run(ctx, &d.dir).await,
        Request::RestoreResume(_) => restore::resume(ctx).await,
        Request::RotateMasterKey(k) => rotate::run(ctx, &k.new_key_file).await,
        Request::MasterKeyStatus(_) => rotate::status(ctx),
        // Streams exist only on a connection (`serve_conn`).
        Request::BackupStream(_) | Request::RestoreStream(_) | Request::BackupsExport(_) => {
            Err("admin/stream_only")
        }
        Request::BackupsList(_) => backups::list(ctx),
        Request::BackupsRemove(n) => backups::remove(ctx, &n.name),
        Request::RetentionRun(d) => retention::admin(ctx, d.dry_run).await,
        Request::AnchorVerify(_) => {
            let resp = anchor::admin(ctx);
            tracing::info!(
                event = "admin_op",
                op,
                outcome = resp.error.as_deref().unwrap_or("ok")
            );
            return resp;
        }
    };
    match out {
        Ok(v) => {
            tracing::info!(event = "admin_op", op, outcome = "ok");
            Response::ok(v)
        }
        Err(code) => {
            tracing::warn!(event = "admin_op", op, outcome = code);
            Response::err(code)
        }
    }
}

/// Parses one request line; anything but a known request is `admin/bad_request`.
pub fn parse_line(line: &[u8]) -> Result<Request, &'static str> {
    serde_json::from_slice(line).map_err(|_| "admin/bad_request")
}

/// Serves one connection: reads one line (at most [`MAX_LINE`]), answers one line.
pub async fn serve_conn<S>(ctx: &AdminCtx, stream: S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (r, mut w) = tokio::io::split(stream);
    let mut reader = BufReader::new(r);
    let mut line = Vec::new();
    // Batch-1 review M-2: an idle peer cannot hold a task forever.
    tokio::time::timeout(
        READ_TIMEOUT,
        (&mut reader)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut line),
    )
    .await
    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    let resp = if line.len() > MAX_LINE {
        Response::err("admin/request_too_large")
    } else {
        match parse_line(&line) {
            Ok(Request::BackupStream(_)) => {
                let _one = ctx.ops.lock().await;
                return stream::backup_out(ctx, &mut w).await;
            }
            Ok(Request::BackupsExport(n)) => {
                let _one = ctx.ops.lock().await;
                return stream::export_out(ctx, &n.name, &mut w).await;
            }
            Ok(Request::RestoreStream(_)) => {
                let _one = ctx.ops.lock().await;
                stream::restore_in(ctx, &mut reader).await
            }
            Ok(req) => handle(ctx, req).await,
            Err(code) => Response::err(code),
        }
    };
    write_line(&mut w, &resp).await?;
    w.shutdown().await
}

/// One JSON answer line.
pub(crate) async fn write_line<W: AsyncWrite + Unpin>(
    w: &mut W,
    resp: &Response,
) -> std::io::Result<()> {
    let mut out = serde_json::to_vec(resp).map_err(std::io::Error::other)?;
    out.push(b'\n');
    w.write_all(&out).await
}

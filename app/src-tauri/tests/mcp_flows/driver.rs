//! The in-house stdio MCP driver of `mcp_flows` (M9 Task 13): newline-delimited JSON-RPC 2.0 to a
//! child's stdin, stdout read line by line.
//!
//! - Every stdout line is kept verbatim (`raw_stdout_lines`, the transcript the M10 canary sweep
//!   reads); a line that is not a JSON-RPC 2.0 message (§4.6: stdout carries only JSON-RPC) fails
//!   the test at once.
//! - Every wait has an explicit timeout, so a test fails by assertion or timeout and never hangs.
//! - Responses are matched by id: a response that arrives while another one is awaited is kept.
//! - The transcript (both directions, stderr of the child) is printed when the test panics.

#![allow(dead_code)]

use std::collections::HashMap;
use std::error::Error;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Child;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// The protocol revision the driver announces in `initialize`.
pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// How long a call, a list or the handshake may take before the driver gives up.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(90);
/// How long a write to the child's stdin or its exit after EOF may take.
const IO_TIMEOUT: Duration = Duration::from_secs(20);

type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

/// What a finished tool call produced.
#[derive(Debug, Clone)]
pub struct CallOutcome {
    /// The `result` object of the `tools/call` response (`content`, `structuredContent`,
    /// `isError`).
    pub result: Value,
    /// Every notification (progress, cancelled, ...) that arrived while this call was awaited.
    pub notifications: Vec<Value>,
}

impl CallOutcome {
    pub fn is_error(&self) -> bool {
        self.result["isError"].as_bool().unwrap_or(false)
    }

    pub fn structured(&self) -> &Value {
        &self.result["structuredContent"]
    }
}

/// The kind of one stdout line, once it is known to be JSON-RPC 2.0.
#[derive(Debug, PartialEq)]
enum Kind {
    Request,
    Notification,
    Response,
}

fn classify(v: &Value) -> std::result::Result<Kind, String> {
    let obj = v.as_object().ok_or("not a JSON object")?;
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err("no \"jsonrpc\": \"2.0\"".into());
    }
    if let Some(method) = obj.get("method") {
        if !method.is_string() {
            return Err("\"method\" is not a string".into());
        }
        return Ok(if obj.contains_key("id") {
            Kind::Request
        } else {
            Kind::Notification
        });
    }
    match (
        obj.get("id"),
        obj.contains_key("result"),
        obj.contains_key("error"),
    ) {
        (Some(_), true, false) | (Some(_), false, true) => Ok(Kind::Response),
        _ => Err("neither a request, a notification nor a response".into()),
    }
}

/// The transport-independent half of the driver: a writer, a line reader, the transcript and the
/// response bookkeeping. Tested over `tokio::io::duplex`; the real child plugs its pipes in.
pub struct Wire {
    writer: Option<BoxWrite>,
    reader: BufReader<BoxRead>,
    /// Bytes of a line read so far (`read_until` keeps them across a timeout).
    partial: Vec<u8>,
    /// Every stdout line, verbatim, in arrival order.
    lines: Vec<String>,
    /// Both directions, in order, for the failure printout.
    log: Vec<String>,
    next_id: u64,
    /// Responses read while another id was awaited.
    stash: HashMap<u64, Value>,
    /// Notifications read since they were last taken.
    notifications: Vec<Value>,
    eof: bool,
}

impl Wire {
    pub fn new(writer: BoxWrite, reader: BoxRead) -> Wire {
        Wire {
            writer: Some(writer),
            reader: BufReader::new(reader),
            partial: Vec::new(),
            lines: Vec::new(),
            log: Vec::new(),
            next_id: 1,
            stash: HashMap::new(),
            notifications: Vec::new(),
            eof: false,
        }
    }

    pub fn raw_stdout_lines(&self) -> Vec<String> {
        self.lines.clone()
    }

    pub fn transcript(&self) -> String {
        self.log.join("\n")
    }

    /// Writes one JSON-RPC message as a line and flushes.
    async fn send(&mut self, msg: &Value) -> Result<()> {
        let mut line = serde_json::to_string(msg)?;
        self.log.push(format!("-> {line}"));
        line.push('\n');
        let writer = self.writer.as_mut().ok_or("stdin is already closed")?;
        tokio::time::timeout(IO_TIMEOUT, async {
            writer.write_all(line.as_bytes()).await?;
            writer.flush().await
        })
        .await
        .map_err(|_| "writing to stdin did not finish in time")??;
        Ok(())
    }

    /// Sends a request and returns its id without waiting.
    pub async fn send_request(&mut self, method: &str, params: Value) -> Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await?;
        Ok(id)
    }

    pub async fn send_notification(&mut self, method: &str, params: Value) -> Result<()> {
        self.send(&json!({"jsonrpc": "2.0", "method": method, "params": params}))
            .await
    }

    /// Reads one stdout line (at most until `deadline`), keeps it, checks it is JSON-RPC 2.0 and
    /// files it: responses into the stash, notifications into the list; a request of the server
    /// is answered (`ping` with `{}`, anything else `-32601`).
    async fn pump_one(&mut self, deadline: Instant) -> Result<()> {
        if self.eof {
            return Err(format!("stdout is closed\n{}", self.transcript()).into());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        let n = tokio::time::timeout(left, self.reader.read_until(b'\n', &mut self.partial))
            .await
            .map_err(|_| "timed out waiting for a stdout line")??;
        if n == 0 && self.partial.is_empty() {
            self.eof = true;
            return Err(format!("stdout closed\n{}", self.transcript()).into());
        }
        if self.partial.last() != Some(&b'\n') {
            // EOF inside a line: the next read reports the close; this line is still checked.
            self.eof = true;
        }
        let bytes = std::mem::take(&mut self.partial);
        let text = String::from_utf8_lossy(&bytes);
        let line = text.trim_end_matches(['\n', '\r']).to_owned();
        self.lines.push(line.clone());
        self.log.push(format!("<- {line}"));
        let value: Value = serde_json::from_str(&line).map_err(|e| {
            format!(
                "stdout line is not JSON ({e}): {line:?}\n{}",
                self.transcript()
            )
        })?;
        let kind = classify(&value).map_err(|why| {
            format!(
                "stdout line is not a JSON-RPC 2.0 message ({why}): {line:?}\n{}",
                self.transcript()
            )
        })?;
        match kind {
            Kind::Notification => self.notifications.push(value),
            Kind::Request => {
                let id = value["id"].clone();
                let reply = if value["method"] == "ping" {
                    json!({"jsonrpc": "2.0", "id": id, "result": {}})
                } else {
                    json!({"jsonrpc": "2.0", "id": id,
                           "error": {"code": -32601, "message": "method not found"}})
                };
                self.send(&reply).await?;
            }
            Kind::Response => {
                let id = value["id"].as_u64().ok_or_else(|| {
                    format!("a response carries an id the driver never sent: {line:?}")
                })?;
                if self.stash.insert(id, value).is_some() {
                    return Err(format!("two responses for id {id}\n{}", self.transcript()).into());
                }
            }
        }
        Ok(())
    }

    /// Waits for the response of `id` (the whole message, `result` or `error`).
    pub async fn wait_response(&mut self, id: u64, timeout: Duration) -> Result<Value> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(v) = self.stash.remove(&id) {
                return Ok(v);
            }
            self.pump_one(deadline).await.map_err(|e| {
                format!(
                    "waiting for the response of id {id} ({timeout:?}): {e}\n{}",
                    self.transcript()
                )
            })?;
        }
    }

    /// Reads for `period` and returns an error if the response of `id` arrives meanwhile (a
    /// request that must stay unanswered, e.g. after `notifications/cancelled`).
    pub async fn expect_no_response(&mut self, id: u64, period: Duration) -> Result<()> {
        let deadline = Instant::now() + period;
        loop {
            if self.stash.contains_key(&id) {
                return Err(format!("id {id} was answered\n{}", self.transcript()).into());
            }
            match self.pump_one(deadline).await {
                Ok(()) => {}
                Err(_) if Instant::now() >= deadline => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    /// Takes the notifications read so far.
    pub fn take_notifications(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.notifications)
    }

    /// A request/response round trip; a JSON-RPC `error` is an `Err`.
    pub async fn request(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value> {
        let id = self.send_request(method, params).await?;
        let response = self.wait_response(id, timeout).await?;
        match response.get("error") {
            Some(e) => Err(format!("{method} failed: {e}").into()),
            None => Ok(response["result"].clone()),
        }
    }

    /// Closes stdin (the end-of-input signal of a stdio server).
    pub fn close_stdin(&mut self) {
        self.writer = None;
    }
}

/// A running `atlas-duck mcp`.
pub struct McpChild {
    wire: Wire,
    child: Child,
    stderr: Arc<Mutex<Vec<u8>>>,
    timeout: Duration,
}

impl McpChild {
    /// Takes the pipes of a child spawned with piped stdin, stdout and stderr (`World::mcp_spawn`).
    pub fn new(mut child: Child) -> Result<McpChild> {
        let stdin = child.stdin.take().ok_or("the child has no piped stdin")?;
        let stdout = child.stdout.take().ok_or("the child has no piped stdout")?;
        let stderr_pipe = child.stderr.take().ok_or("the child has no piped stderr")?;
        // Drain stderr so the child never blocks on a full pipe.
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let sink = stderr.clone();
        tokio::spawn(async move {
            let mut pipe = stderr_pipe;
            let mut buf = [0u8; 4096];
            while let Ok(n) = pipe.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                if let (Ok(mut all), Some(chunk)) = (sink.lock(), buf.get(..n)) {
                    all.extend_from_slice(chunk);
                }
            }
        });
        Ok(McpChild {
            wire: Wire::new(Box::new(stdin), Box::new(stdout)),
            child,
            stderr,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Replaces the default wait of `initialize`, `list_tools` and `call`.
    pub fn with_timeout(mut self, timeout: Duration) -> McpChild {
        self.timeout = timeout;
        self
    }

    /// `initialize` with `clientInfo.name = client_name`, then `notifications/initialized`.
    /// Returns the `initialize` result.
    pub async fn initialize(&mut self, client_name: &str) -> Result<Value> {
        let result = self
            .wire
            .request(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": client_name, "version": "0.0.0"},
                }),
                self.timeout,
            )
            .await?;
        self.wire
            .send_notification("notifications/initialized", json!({}))
            .await?;
        Ok(result)
    }

    /// Every tool of `tools/list` (follows `nextCursor`).
    pub async fn list_tools(&mut self) -> Result<Vec<Value>> {
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..20 {
            let params = match &cursor {
                Some(c) => json!({"cursor": c}),
                None => json!({}),
            };
            let result = self
                .wire
                .request("tools/list", params, self.timeout)
                .await?;
            if let Some(page) = result["tools"].as_array() {
                tools.extend(page.iter().cloned());
            }
            match result["nextCursor"].as_str() {
                Some(next) => cursor = Some(next.to_owned()),
                None => return Ok(tools),
            }
        }
        Err("tools/list did not end after 20 pages".into())
    }

    /// Sends `tools/call` and returns the JSON-RPC id without waiting (`wait_call`, `cancel`).
    /// With a progress token the request carries `_meta.progressToken`.
    pub async fn send_call(
        &mut self,
        name: &str,
        args: Value,
        progress_token: Option<&str>,
    ) -> Result<u64> {
        let mut params = json!({"name": name, "arguments": args});
        if let Some(token) = progress_token {
            params["_meta"] = json!({"progressToken": token});
        }
        self.wire.send_request("tools/call", params).await
    }

    /// Waits for the response of a call sent with `send_call` (at most `timeout`).
    pub async fn wait_call(&mut self, id: u64, timeout: Duration) -> Result<CallOutcome> {
        let response = self.wire.wait_response(id, timeout).await?;
        if let Some(e) = response.get("error") {
            return Err(format!("tools/call answered a JSON-RPC error: {e}").into());
        }
        Ok(CallOutcome {
            result: response["result"].clone(),
            notifications: self.wire.take_notifications(),
        })
    }

    /// `tools/call` and its result, with the notifications that arrived meanwhile.
    pub async fn call(
        &mut self,
        name: &str,
        args: Value,
        progress_token: Option<&str>,
    ) -> Result<CallOutcome> {
        let id = self.send_call(name, args, progress_token).await?;
        self.wait_call(id, self.timeout).await
    }

    /// `notifications/cancelled` for the call `id` (no response is expected).
    pub async fn cancel(&mut self, id: u64) -> Result<()> {
        self.wire
            .send_notification(
                "notifications/cancelled",
                json!({"requestId": id, "reason": "mcp_flows"}),
            )
            .await
    }

    /// Reads for `period` and fails if the call `id` is answered meanwhile.
    pub async fn expect_no_response(&mut self, id: u64, period: Duration) -> Result<()> {
        self.wire.expect_no_response(id, period).await
    }

    /// Takes the notifications read so far (those not handed to a `CallOutcome`).
    pub fn take_notifications(&mut self) -> Vec<Value> {
        self.wire.take_notifications()
    }

    /// Every stdout line of the child, verbatim.
    pub fn raw_stdout_lines(&self) -> Vec<String> {
        self.wire.raw_stdout_lines()
    }

    pub fn stderr_text(&self) -> String {
        match self.stderr.lock() {
            Ok(all) => String::from_utf8_lossy(&all).into_owned(),
            Err(_) => String::new(),
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Closes the child's stdin (end of input: the server ends).
    pub fn close_stdin(&mut self) {
        self.wire.close_stdin();
    }

    /// Waits (at most 20 s) for the child to end, e.g. after `close_stdin`.
    pub async fn wait_exit(&mut self) -> Result<ExitStatus> {
        tokio::time::timeout(IO_TIMEOUT, self.child.wait())
            .await
            .map_err(|_| format!("atlas-duck mcp did not end within {IO_TIMEOUT:?}"))?
            .map_err(Into::into)
    }

    /// The failure printout: both directions of the wire and the child's stderr.
    pub fn transcript(&self) -> String {
        format!(
            "--- MCP transcript ---\n{}\n--- stderr ---\n{}",
            self.wire.transcript(),
            self.stderr_text()
        )
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("{}", self.transcript());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, split};

    type TestResult = std::result::Result<(), Box<dyn Error>>;

    /// A `Wire` over an in-memory pipe plus the fake server's two ends.
    fn rig() -> (
        Wire,
        BufReader<impl AsyncRead + Unpin>,
        impl AsyncWrite + Unpin,
    ) {
        let (client, server) = duplex(64 * 1024);
        let (client_read, client_write) = split(client);
        let (server_read, server_write) = split(server);
        (
            Wire::new(Box::new(client_write), Box::new(client_read)),
            BufReader::new(server_read),
            server_write,
        )
    }

    async fn read_request(server: &mut BufReader<impl AsyncRead + Unpin>) -> Result<Value> {
        let mut line = String::new();
        server.read_line(&mut line).await?;
        Ok(serde_json::from_str(&line)?)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn driver_rejects_non_jsonrpc_line() -> TestResult {
        let (mut wire, mut server_in, mut server_out) = rig();
        let id = wire.send_request("tools/list", json!({})).await?;
        read_request(&mut server_in).await?;
        // A log line on stdout, as a buggy server would print it.
        server_out.write_all(b"starting up...\n").await?;
        let err = wire
            .wait_response(id, Duration::from_secs(5))
            .await
            .err()
            .ok_or("a log line was accepted")?
            .to_string();
        assert!(err.contains("starting up..."), "{err}");
        assert_eq!(wire.raw_stdout_lines(), vec!["starting up...".to_owned()]);

        // JSON that is not JSON-RPC 2.0 is just as wrong.
        for bad in [
            r#"{"id":1,"result":{}}"#,
            r#"{"jsonrpc":"1.0","id":1,"result":{}}"#,
            r#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#,
            r#"{"jsonrpc":"2.0","id":1}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{}}"#,
        ] {
            let (mut wire, mut server_in, mut server_out) = rig();
            let id = wire.send_request("tools/list", json!({})).await?;
            read_request(&mut server_in).await?;
            server_out.write_all(format!("{bad}\n").as_bytes()).await?;
            let err = wire.wait_response(id, Duration::from_secs(5)).await;
            assert!(err.is_err(), "{bad} was accepted");
            assert_eq!(wire.raw_stdout_lines(), vec![bad.to_owned()]);
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn driver_matches_responses_by_id() -> TestResult {
        let (mut wire, mut server_in, mut server_out) = rig();
        let first = wire.send_request("tools/call", json!({"n": 1})).await?;
        let second = wire.send_request("tools/call", json!({"n": 2})).await?;
        assert_eq!(read_request(&mut server_in).await?["id"], first);
        assert_eq!(read_request(&mut server_in).await?["id"], second);

        // The second answer comes first, with a progress notification between the two.
        let lines = [
            json!({"jsonrpc": "2.0", "id": second, "result": {"n": 2}}),
            json!({"jsonrpc": "2.0", "method": "notifications/progress",
                   "params": {"progressToken": "t", "progress": 1}}),
            json!({"jsonrpc": "2.0", "id": first, "result": {"n": 1}}),
        ];
        for line in &lines {
            server_out.write_all(format!("{line}\n").as_bytes()).await?;
        }
        let a = wire.wait_response(first, Duration::from_secs(5)).await?;
        assert_eq!(a["result"]["n"], 1);
        let b = wire.wait_response(second, Duration::from_secs(5)).await?;
        assert_eq!(b["result"]["n"], 2);
        let notes = wire.take_notifications();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0]["method"], "notifications/progress");
        assert_eq!(wire.raw_stdout_lines().len(), 3);

        // An unanswered id times out instead of hanging, and a server request is answered.
        let third = wire.send_request("tools/call", json!({})).await?;
        read_request(&mut server_in).await?;
        server_out
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"p\",\"method\":\"ping\"}\n")
            .await?;
        let timed_out = wire.wait_response(third, Duration::from_millis(300)).await;
        assert!(timed_out.is_err());
        let pong = read_request(&mut server_in).await?;
        assert_eq!(pong["id"], "p");
        assert!(pong["result"].is_object(), "{pong}");
        Ok(())
    }
}

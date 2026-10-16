//! The `e2e` target's WebDriver client (M6 T32): the W3C endpoints the flows need, over `reqwest`
//! to `tauri-driver` on 127.0.0.1.
//!
//! - The WebDriver "execute script" endpoint is **not** used and has no method here: no script is
//!   ever injected into a webview of the app, even in tests (the webviews are TCB). Everything a
//!   flow observes it reads through element, attribute, CSS value, title and window endpoints.
//! - Every request and response body is built or read by a pure function of this file
//!   ([`session_request`], [`parse_element`], [`wd_error`], ...), unit-tested against the examples
//!   of the W3C WebDriver specification. The I/O methods are thin and are only reached by flows
//!   that passed `harness::opted_in(..)`: nothing in `cfg(test)` code here opens a socket or spawns
//!   a process.
//! - [`DriverProc`] spawns `tauri-driver` (path in `ATLAS_DUCK_TAURI_DRIVER`, default
//!   `tauri-driver` from `PATH`), with the world's environment plus the E2E opt-in
//!   `ATLAS_DUCK_E2E_ALLOW_DRIVER=1` (the app `tauri-driver` starts inherits it, and the startup
//!   hardening of the `scripted-approver` build then leaves the driver variables alone). On Windows
//!   the native driver comes from `ATLAS_DUCK_E2E_NATIVE_DRIVER` (`msedgedriver.exe`).

#![allow(dead_code)]

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::future::Future;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use base64::Engine as _;
use reqwest::Method;
use serde_json::{Value, json};

use crate::harness::Result;

// ---- constants ---------------------------------------------------------------------------------

/// The key of a web element reference in every W3C answer.
pub const ELEMENT_KEY: &str = "element-6066-11e4-a52e-4f735466cecf";

/// Special key codes of the W3C "Keys" table (private use code points).
pub mod keys {
    pub const TAB: &str = "\u{E004}";
    pub const ENTER: &str = "\u{E007}";
    pub const SHIFT: &str = "\u{E008}";
    pub const CONTROL: &str = "\u{E009}";
    pub const ESCAPE: &str = "\u{E00C}";
    pub const SPACE: &str = "\u{E00D}";
    pub const ARROW_UP: &str = "\u{E013}";
    pub const ARROW_DOWN: &str = "\u{E015}";
}

/// The variable naming the `tauri-driver` executable (default: `tauri-driver` from `PATH`).
pub const ENV_TAURI_DRIVER: &str = "ATLAS_DUCK_TAURI_DRIVER";
/// The variable naming the native driver (`msedgedriver.exe` on Windows; on Linux `WebKitWebDriver`
/// is found on `PATH` when it is unset).
pub const ENV_NATIVE_DRIVER: &str = "ATLAS_DUCK_E2E_NATIVE_DRIVER";
/// The E2E opt-in of the app's startup hardening (`startup::hardening::ENV_E2E_ALLOW_DRIVER`).
pub const ENV_ALLOW_DRIVER: &str = "ATLAS_DUCK_E2E_ALLOW_DRIVER";
/// Where failure screenshots go (default: `<target tmp>/e2e-artifacts`).
pub const ENV_ARTIFACTS: &str = "ATLAS_DUCK_E2E_ARTIFACTS";

/// How long `tauri-driver` may take to answer `GET /status` after the spawn.
const DRIVER_START_WAIT: Duration = Duration::from_secs(30);
/// One WebDriver command (a new session starts the app: the longest one).
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
/// "Delete Session" at the end of a flow: the app is gone already, a blocked driver must not hold
/// the teardown for the full command timeout.
const QUIT_TIMEOUT: Duration = Duration::from_secs(10);
/// "Navigate To" a foreign URL: the app is expected to refuse it, and a driver may wait for a load
/// that never comes.
const NAVIGATE_TIMEOUT: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(100);

// ---- pure: request bodies ----------------------------------------------------------------------

/// The `POST /session` body for `tauri-driver`: the app under test in `tauri:options`.
pub fn session_request(application: &str, args: &[&str]) -> Value {
    json!({
        "capabilities": {
            "alwaysMatch": {
                "browserName": "wry",
                "tauri:options": {
                    "application": application,
                    "args": args,
                }
            }
        }
    })
}

/// A locator strategy of the "Find Element" commands (W3C names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Using {
    Css,
    XPath,
}

impl Using {
    pub fn name(self) -> &'static str {
        match self {
            Using::Css => "css selector",
            Using::XPath => "xpath",
        }
    }
}

/// The body of "Find Element(s)".
pub fn find_request(using: Using, value: &str) -> Value {
    json!({ "using": using.name(), "value": value })
}

/// The body of "Element Send Keys".
pub fn keys_request(text: &str) -> Value {
    json!({ "text": text })
}

/// The body of "Navigate To".
pub fn navigate_request(url: &str) -> Value {
    json!({ "url": url })
}

/// The body of "Switch To Window".
pub fn window_request(handle: &str) -> Value {
    json!({ "handle": handle })
}

/// The body of "Switch To Frame": a frame element, or `null` for the top-level context.
pub fn frame_request(frame: Option<&Element>) -> Value {
    match frame {
        Some(e) => json!({ "id": { ELEMENT_KEY: e.0 } }),
        None => json!({ "id": null }),
    }
}

/// The body of "Perform Actions" for a chord: the modifiers down, the key pressed and released,
/// the modifiers up in reverse order, on one key source.
pub fn chord_request(modifiers: &[&str], key: &str) -> Value {
    let mut actions: Vec<Value> = Vec::new();
    for m in modifiers {
        actions.push(json!({ "type": "keyDown", "value": m }));
    }
    actions.push(json!({ "type": "keyDown", "value": key }));
    actions.push(json!({ "type": "keyUp", "value": key }));
    for m in modifiers.iter().rev() {
        actions.push(json!({ "type": "keyUp", "value": m }));
    }
    json!({ "actions": [{ "type": "key", "id": "keyboard", "actions": actions }] })
}

/// The body of "Perform Actions" for one key held down and not released (the held-Enter check): the
/// matching [`release_request`] ends it.
pub fn key_down_request(key: &str) -> Value {
    json!({ "actions": [{
        "type": "key", "id": "keyboard",
        "actions": [{ "type": "keyDown", "value": key }]
    }] })
}

/// The empty `{}` body of the commands that take none ("Click", "Refresh", "Switch To Parent
/// Frame").
pub fn empty_request() -> Value {
    json!({})
}

// ---- pure: answers -----------------------------------------------------------------------------

/// A web element reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element(pub String);

/// An error answer of the driver (`value.error`, W3C "Errors").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WdError {
    pub status: u16,
    pub error: String,
    pub message: String,
}

impl fmt::Display for WdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "webdriver {} ({}): {}",
            self.error, self.status, self.message
        )
    }
}

impl std::error::Error for WdError {}

/// The error of an answer: any answer whose `value` has a string `error`, or a 4xx/5xx status.
pub fn wd_error(status: u16, body: &Value) -> Option<WdError> {
    let err = body["value"]["error"].as_str();
    if err.is_none() && status < 400 {
        return None;
    }
    Some(WdError {
        status,
        error: err.unwrap_or("unknown error").to_owned(),
        message: body["value"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    })
}

/// The `value` of an answer, or its error.
pub fn answer_value(status: u16, body: &Value) -> std::result::Result<Value, WdError> {
    match wd_error(status, body) {
        Some(e) => Err(e),
        None => Ok(body["value"].clone()),
    }
}

/// The session id of a "New Session" answer.
pub fn parse_session_id(value: &Value) -> Result<String> {
    value["sessionId"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("no sessionId in the new session answer: {value}").into())
}

/// One element reference.
pub fn parse_element(value: &Value) -> Result<Element> {
    value[ELEMENT_KEY]
        .as_str()
        .map(|id| Element(id.to_owned()))
        .ok_or_else(|| format!("no element reference in {value}").into())
}

/// A list of element references.
pub fn parse_elements(value: &Value) -> Result<Vec<Element>> {
    value
        .as_array()
        .ok_or_else(|| format!("no element list in {value}"))?
        .iter()
        .map(parse_element)
        .collect()
}

/// A list of window handles.
pub fn parse_strings(value: &Value) -> Result<Vec<String>> {
    value
        .as_array()
        .ok_or_else(|| format!("no string list in {value}"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("not a string: {v}").into())
        })
        .collect()
}

/// An attribute answer: `null` when the attribute is absent.
pub fn parse_nullable_string(value: &Value) -> Result<Option<String>> {
    match value {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        other => Err(format!("not a string or null: {other}").into()),
    }
}

/// The `tauri-driver` command line: its own port and the native driver's.
pub fn driver_args(port: u16, native_port: u16, native_driver: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "--port".to_owned(),
        port.to_string(),
        "--native-port".to_owned(),
        native_port.to_string(),
    ];
    if let Some(path) = native_driver {
        args.push("--native-driver".to_owned());
        args.push(path.to_owned());
    }
    args
}

// ---- the driver process --------------------------------------------------------------------------

/// A `tauri-driver` of one test: spawned with the world's environment plus the E2E opt-in, killed
/// on drop together with everything it started. The app is started by the driver (the first "New
/// Session"), so the app's environment is this one.
///
/// The whole tree ends with the driver: on Windows `tauri-driver` is put in a kill-on-close job
/// object right after the spawn (its `msedgedriver`, the app and the app's WebView2 processes are
/// created inside it), on Unix it leads its own process group that is killed. The app of a world
/// that has no store yet (the Setup window) records no pid and holds no `instance.lock`, so the
/// world cannot stop it; this is what does.
pub struct DriverProc {
    child: Option<Child>,
    base: String,
    #[cfg(windows)]
    job: Option<job::Job>,
}

impl DriverProc {
    /// `env` is `World::env()` (the test home, the keystore dir, the pass-through names). The
    /// driver's log goes to `log`.
    pub async fn start(env: Vec<(OsString, OsString)>, log: &Path) -> Result<DriverProc> {
        let exe = std::env::var_os(ENV_TAURI_DRIVER).unwrap_or_else(|| "tauri-driver".into());
        let native = std::env::var(ENV_NATIVE_DRIVER).ok();
        let (port, native_port) = free_ports()?;
        let out = fs::File::create(log)?;
        let err = out.try_clone()?;
        let mut cmd = Command::new(exe);
        cmd.args(driver_args(port, native_port, native.as_deref()))
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err));
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.env(ENV_ALLOW_DRIVER, "1");
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let child = cmd.spawn()?;
        // Assigned at once: the driver starts its native driver (and, on a session, the app) as
        // its children, which join the job only when it is already in it.
        #[cfg(windows)]
        let job = {
            use std::os::windows::io::AsRawHandle;
            let assigned = job::Job::kill_on_close().and_then(|j| {
                j.assign(child.as_raw_handle())?;
                Ok(j)
            });
            match assigned {
                Ok(j) => Some(j),
                Err(e) => {
                    let mut child = child;
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(
                        format!("tauri-driver could not be put in a job object: {e}").into(),
                    );
                }
            }
        };
        let mut proc = DriverProc {
            child: Some(child),
            base: format!("http://127.0.0.1:{port}"),
            #[cfg(windows)]
            job,
        };
        let http = client()?;
        let start = Instant::now();
        loop {
            let ended = match proc.child.as_mut() {
                Some(c) => c.try_wait()?,
                None => None,
            };
            if let Some(status) = ended {
                return Err(format!("tauri-driver ended at start: {status}; log {log:?}").into());
            }
            if let Ok(resp) = http.get(format!("{}/status", proc.base)).send().await
                && resp.status().is_success()
            {
                break;
            }
            if start.elapsed() > DRIVER_START_WAIT {
                proc.kill_tree();
                return Err(
                    format!("tauri-driver answered no /status in 30 s; log {log:?}").into(),
                );
            }
            tokio::time::sleep(POLL).await;
        }
        Ok(proc)
    }

    /// `http://127.0.0.1:<port>`.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Ends the driver and every process it started (the native driver, the app, the app's
    /// webview processes). Idempotent; also what the drop does.
    pub fn kill_tree(&mut self) {
        // Closing the last handle of the kill-on-close job ends every process in it.
        #[cfg(windows)]
        drop(self.job.take());
        #[cfg(unix)]
        if let Some(child) = &self.child {
            let _ = Command::new("kill")
                .args(["-KILL", "--", &format!("-{}", child.id())])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for DriverProc {
    fn drop(&mut self) {
        self.kill_tree();
    }
}

/// Two distinct free ports: both listeners are held until both are known (two separate
/// bind-and-drop calls can answer the same port).
fn free_ports() -> Result<(u16, u16)> {
    let a = TcpListener::bind("127.0.0.1:0")?;
    let b = TcpListener::bind("127.0.0.1:0")?;
    Ok((a.local_addr()?.port(), b.local_addr()?.port()))
}

#[cfg(windows)]
mod job {
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };

    /// A job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and no breakaway flag: dropping it
    /// closes the last handle, which ends every process in it.
    pub struct Job(OwnedHandle);

    impl Job {
        pub fn kill_on_close() -> io::Result<Job> {
            // SAFETY: plain call; null on failure.
            let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if h.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: a fresh job handle nothing else owns.
            let job = Job(unsafe { OwnedHandle::from_raw_handle(h) });
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            // Deliberately no JOB_OBJECT_LIMIT_BREAKAWAY_OK / SILENT_BREAKAWAY_OK.
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let size = u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .map_err(io::Error::other)?;
            // SAFETY: `info` is a local of the stated size and class.
            let set = unsafe {
                SetInformationJobObject(
                    job.0.as_raw_handle(),
                    JobObjectExtendedLimitInformation,
                    (&raw const info).cast(),
                    size,
                )
            };
            if set == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }

        pub fn assign(&self, process: RawHandle) -> io::Result<()> {
            // SAFETY: both handles are live (the process handle belongs to the caller's child).
            if unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), process) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

/// `reqwest`'s `rustls-no-provider` build panics in `ClientBuilder::build` without a process-wide
/// provider; the client talks plain http only, but the build still needs one.
fn client() -> Result<reqwest::Client> {
    static PROVIDER: OnceLock<()> = OnceLock::new();
    PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    Ok(reqwest::Client::builder()
        .no_proxy()
        .timeout(COMMAND_TIMEOUT)
        .build()?)
}

// ---- the client ----------------------------------------------------------------------------------

/// Polls `probe` every 100 ms until it answers `Some`, at most `within`; `what` names the wait in the
/// failure text.
pub async fn wait_for<T, F, Fut>(what: &str, within: Duration, mut probe: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>>>,
{
    let start = Instant::now();
    loop {
        if let Some(v) = probe().await? {
            return Ok(v);
        }
        if start.elapsed() > within {
            return Err(format!("timed out after {within:?} waiting for {what}").into());
        }
        tokio::time::sleep(POLL).await;
    }
}

/// One WebDriver session.
pub struct WebDriver {
    http: reqwest::Client,
    base: String,
    session: String,
    artifacts: PathBuf,
}

impl WebDriver {
    /// "New Session": starts the app (`application`, with `args`) through `tauri-driver`.
    pub async fn new_session(base: &str, application: &str, args: &[&str]) -> Result<WebDriver> {
        let http = client()?;
        let resp = http
            .post(format!("{base}/session"))
            .header("content-type", "application/json; charset=utf-8")
            .body(session_request(application, args).to_string())
            .send()
            .await?;
        let status = resp.status().as_u16();
        let body: Value = serde_json::from_str(&resp.text().await?)?;
        let value = answer_value(status, &body)?;
        Ok(WebDriver {
            http,
            base: base.to_owned(),
            session: parse_session_id(&value)?,
            artifacts: artifacts_dir(),
        })
    }

    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        self.call_within(method, path, body, None).await
    }

    /// [`WebDriver::call`] with its own timeout instead of the client's.
    async fn call_within(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        timeout: Option<Duration>,
    ) -> Result<Value> {
        let url = format!("{}/session/{}{path}", self.base, self.session);
        let mut req = self.http.request(method, url);
        if let Some(t) = timeout {
            req = req.timeout(t);
        }
        if let Some(b) = body {
            req = req
                .header("content-type", "application/json; charset=utf-8")
                .body(b.to_string());
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let text = resp.text().await?;
        let body: Value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text)?
        };
        Ok(answer_value(status, &body)?)
    }

    async fn get(&self, path: &str) -> Result<Value> {
        self.call(Method::GET, path, None).await
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value> {
        self.call(Method::POST, path, Some(body)).await
    }

    /// "Delete Session": the driver closes the app's webviews.
    pub async fn quit(&self) -> Result<()> {
        self.call_within(Method::DELETE, "", None, Some(QUIT_TIMEOUT))
            .await
            .map(|_| ())
    }

    // ---- elements ------------------------------------------------------------------------------

    pub async fn find_by(&self, using: Using, value: &str) -> Result<Element> {
        let v = self.post("/element", find_request(using, value)).await?;
        parse_element(&v)
    }

    pub async fn find_all_by(&self, using: Using, value: &str) -> Result<Vec<Element>> {
        let v = self.post("/elements", find_request(using, value)).await?;
        parse_elements(&v)
    }

    /// The first element matching the CSS selector; an error when there is none.
    pub async fn find(&self, css: &str) -> Result<Element> {
        self.find_by(Using::Css, css).await
    }

    pub async fn find_all(&self, css: &str) -> Result<Vec<Element>> {
        self.find_all_by(Using::Css, css).await
    }

    pub async fn find_xpath(&self, xpath: &str) -> Result<Element> {
        self.find_by(Using::XPath, xpath).await
    }

    /// "Find Elements From Element" (CSS): the matches under `e`.
    pub async fn find_all_in(&self, e: &Element, css: &str) -> Result<Vec<Element>> {
        let v = self
            .post(
                &format!("/element/{}/elements", e.0),
                find_request(Using::Css, css),
            )
            .await?;
        parse_elements(&v)
    }

    /// "Get Active Element": the focused element of the current browsing context's document (for
    /// failure texts: where a key would go).
    pub async fn active_element(&self) -> Result<Element> {
        let v = self.get("/element/active").await?;
        parse_element(&v)
    }

    /// Waits until some element matches (CSS), at most `within`.
    pub async fn wait_find(&self, css: &str, within: Duration) -> Result<Element> {
        wait_for(css, within, || async {
            Ok(self.find_all(css).await?.into_iter().next())
        })
        .await
    }

    pub async fn wait_find_xpath(&self, xpath: &str, within: Duration) -> Result<Element> {
        wait_for(xpath, within, || async {
            Ok(self
                .find_all_by(Using::XPath, xpath)
                .await?
                .into_iter()
                .next())
        })
        .await
    }

    pub async fn click(&self, e: &Element) -> Result<()> {
        self.post(&format!("/element/{}/click", e.0), empty_request())
            .await
            .map(|_| ())
    }

    pub async fn send_keys(&self, e: &Element, text: &str) -> Result<()> {
        self.post(&format!("/element/{}/value", e.0), keys_request(text))
            .await
            .map(|_| ())
    }

    /// "Get Element Text": the rendered text.
    pub async fn text(&self, e: &Element) -> Result<String> {
        let v = self.get(&format!("/element/{}/text", e.0)).await?;
        Ok(v.as_str().unwrap_or_default().to_owned())
    }

    /// "Get Element Attribute".
    pub async fn attribute(&self, e: &Element, name: &str) -> Result<Option<String>> {
        let v = self
            .get(&format!("/element/{}/attribute/{name}", e.0))
            .await?;
        parse_nullable_string(&v)
    }

    /// "Get Element Property": the live JavaScript property (an input's typed `value`), which the
    /// attribute endpoint does not give on a spec-strict driver. `None` for `null`/absent.
    pub async fn property(&self, e: &Element, name: &str) -> Result<Option<String>> {
        let v = self
            .get(&format!("/element/{}/property/{name}", e.0))
            .await?;
        Ok(match v {
            Value::Null => None,
            Value::String(s) => Some(s),
            other => Some(other.to_string()),
        })
    }

    /// "Get Element CSS Value": the computed value of one property.
    pub async fn css_value(&self, e: &Element, property: &str) -> Result<String> {
        let v = self
            .get(&format!("/element/{}/css/{property}", e.0))
            .await?;
        Ok(v.as_str().unwrap_or_default().to_owned())
    }

    pub async fn is_enabled(&self, e: &Element) -> Result<bool> {
        let v = self.get(&format!("/element/{}/enabled", e.0)).await?;
        Ok(v.as_bool().unwrap_or(false))
    }

    // ---- documents and windows -----------------------------------------------------------------

    /// "Get Title": the title of the current top-level browsing context's document.
    pub async fn title(&self) -> Result<String> {
        let v = self.get("/title").await?;
        Ok(v.as_str().unwrap_or_default().to_owned())
    }

    /// "Get Current URL" of the current top-level browsing context.
    pub async fn current_url(&self) -> Result<String> {
        let v = self.get("/url").await?;
        Ok(v.as_str().unwrap_or_default().to_owned())
    }

    /// "Navigate To" (not script injection: the W3C endpoint a user's address bar equals). The
    /// result is the driver's: a refused navigation may answer ok, an error or nothing within
    /// [`NAVIGATE_TIMEOUT`]; callers assert on the document afterwards, never on this.
    pub async fn navigate(&self, url: &str) -> Result<()> {
        self.call_within(
            Method::POST,
            "/url",
            Some(navigate_request(url)),
            Some(NAVIGATE_TIMEOUT),
        )
        .await
        .map(|_| ())
    }

    pub async fn refresh(&self) -> Result<()> {
        self.post("/refresh", empty_request()).await.map(|_| ())
    }

    pub async fn window_handles(&self) -> Result<Vec<String>> {
        parse_strings(&self.get("/window/handles").await?)
    }

    pub async fn current_window(&self) -> Result<String> {
        let v = self.get("/window").await?;
        Ok(v.as_str().unwrap_or_default().to_owned())
    }

    pub async fn switch_to_window(&self, handle: &str) -> Result<()> {
        self.post("/window", window_request(handle))
            .await
            .map(|_| ())
    }

    /// Switches to the window whose document title is `title` (the window labels have no WebDriver
    /// name: each window's page has its own `<title>`); waits for it to exist, at most `within`.
    pub async fn switch_to_title(&self, title: &str, within: Duration) -> Result<String> {
        wait_for(&format!("a window titled {title:?}"), within, || async {
            for handle in self.window_handles().await? {
                // A window that closes between the listing and the switch is not an error.
                if self.switch_to_window(&handle).await.is_err() {
                    continue;
                }
                if self.title().await.ok().as_deref() == Some(title) {
                    return Ok(Some(handle));
                }
            }
            Ok(None)
        })
        .await
    }

    pub async fn switch_to_frame(&self, frame: &Element) -> Result<()> {
        self.post("/frame", frame_request(Some(frame)))
            .await
            .map(|_| ())
    }

    pub async fn switch_to_top(&self) -> Result<()> {
        self.post("/frame", frame_request(None)).await.map(|_| ())
    }

    pub async fn switch_to_parent(&self) -> Result<()> {
        self.post("/frame/parent", empty_request())
            .await
            .map(|_| ())
    }

    // ---- keys ----------------------------------------------------------------------------------

    /// A chord (`modifiers` held, `key` pressed) at the focused element.
    pub async fn chord(&self, modifiers: &[&str], key: &str) -> Result<()> {
        self.post("/actions", chord_request(modifiers, key))
            .await
            .map(|_| ())
    }

    /// Holds `key` down (no release): the platform's auto-repeat is up to the driver.
    pub async fn key_down(&self, key: &str) -> Result<()> {
        self.post("/actions", key_down_request(key))
            .await
            .map(|_| ())
    }

    /// "Release Actions": ends what [`WebDriver::key_down`] started.
    pub async fn release_keys(&self) -> Result<()> {
        self.call(Method::DELETE, "/actions", None)
            .await
            .map(|_| ())
    }

    // ---- failures ------------------------------------------------------------------------------

    /// Best effort: a PNG of the current window as `<artifacts>/<name>.png`; the path, or `None`.
    pub async fn screenshot_on_failure(&self, name: &str) -> Option<PathBuf> {
        let v = self.get("/screenshot").await.ok()?;
        let png = base64::engine::general_purpose::STANDARD
            .decode(v.as_str()?)
            .ok()?;
        fs::create_dir_all(&self.artifacts).ok()?;
        let path = self.artifacts.join(format!("{name}.png"));
        fs::write(&path, png).ok()?;
        Some(path)
    }
}

/// `ATLAS_DUCK_E2E_ARTIFACTS`, else `<cargo target tmp>/e2e-artifacts` (never `%TEMP%`).
fn artifacts_dir() -> PathBuf {
    std::env::var_os(ENV_ARTIFACTS)
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_TARGET_TMPDIR")).join("e2e-artifacts"))
}

// ---- pure tests: the recorded W3C examples -------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// W3C WebDriver §8.1 "New Session" example answer (browser fields shortened).
    const NEW_SESSION: &str = r#"{"value":{"sessionId":"1234567890","capabilities":{"browserName":"firefox","browserVersion":"68.0a1","platformName":"linux","acceptInsecureCerts":false,"pageLoadStrategy":"normal","setWindowRect":true,"timeouts":{"implicit":0,"pageLoad":300000,"script":30000}}}}"#;
    /// §12.3.2 "Find Element" example answer.
    const FIND_ELEMENT: &str = r#"{"value":{"element-6066-11e4-a52e-4f735466cecf":"d9dc5c75-ed5f-4e7e-a09a-8d2f26a47f68"}}"#;
    /// §12.3.3 "Find Elements" example answer.
    const FIND_ELEMENTS: &str = r#"{"value":[{"element-6066-11e4-a52e-4f735466cecf":"a"},{"element-6066-11e4-a52e-4f735466cecf":"b"}]}"#;
    /// §6.6 "Error" answer for a missing element.
    const NO_SUCH_ELEMENT: &str = r#"{"value":{"error":"no such element","message":"Unable to locate element: #x","stacktrace":"WebDriverError@chrome://remote"}}"#;
    /// §11.7 "Get Window Handles" example answer.
    const HANDLES: &str = r#"{"value":["CDwindow-1","CDwindow-2"]}"#;
    /// "Get Element Attribute" of an absent attribute.
    const NULL_ATTRIBUTE: &str = r#"{"value":null}"#;

    fn parse(text: &str) -> Value {
        serde_json::from_str(text).unwrap_or(Value::Null)
    }

    #[test]
    fn new_session_request_names_the_app_in_tauri_options() {
        let body = session_request("C:\\x\\atlas-duck-app.exe", &["--background"]);
        assert_eq!(
            body,
            json!({"capabilities":{"alwaysMatch":{
                "browserName":"wry",
                "tauri:options":{"application":"C:\\x\\atlas-duck-app.exe","args":["--background"]}
            }}})
        );
        // No firstMatch, no desired/required capabilities (legacy keys).
        assert!(body["capabilities"]["firstMatch"].is_null());
        assert!(body["desiredCapabilities"].is_null());
    }

    #[test]
    fn new_session_answer_yields_the_session_id() {
        let body = parse(NEW_SESSION);
        let value = answer_value(200, &body).unwrap();
        assert_eq!(parse_session_id(&value).unwrap(), "1234567890");
        assert!(parse_session_id(&json!({"capabilities":{}})).is_err());
    }

    #[test]
    fn element_answers_parse() {
        let value = answer_value(200, &parse(FIND_ELEMENT)).unwrap();
        assert_eq!(
            parse_element(&value).unwrap(),
            Element("d9dc5c75-ed5f-4e7e-a09a-8d2f26a47f68".into())
        );
        let value = answer_value(200, &parse(FIND_ELEMENTS)).unwrap();
        assert_eq!(
            parse_elements(&value).unwrap(),
            [Element("a".into()), Element("b".into())]
        );
        assert!(parse_elements(&json!([])).unwrap().is_empty());
        // A legacy `ELEMENT` key is not a W3C reference.
        assert!(parse_element(&json!({"ELEMENT":"x"})).is_err());
        assert!(parse_elements(&json!({"not":"a list"})).is_err());
    }

    #[test]
    fn error_answers_carry_the_w3c_error_code() {
        let body = parse(NO_SUCH_ELEMENT);
        let e = wd_error(404, &body).unwrap();
        assert_eq!(e.error, "no such element");
        assert_eq!(e.status, 404);
        assert!(e.message.contains("Unable to locate"));
        assert_eq!(
            e.to_string(),
            "webdriver no such element (404): Unable to locate element: #x"
        );
        // An error body is an error whatever the status; a 4xx without a body is an error too.
        assert!(wd_error(200, &body).is_some());
        assert_eq!(wd_error(500, &Value::Null).unwrap().error, "unknown error");
        assert!(wd_error(200, &parse(FIND_ELEMENT)).is_none());
        assert!(answer_value(404, &body).is_err());
    }

    #[test]
    fn handles_and_nullable_answers_parse() {
        let value = answer_value(200, &parse(HANDLES)).unwrap();
        assert_eq!(parse_strings(&value).unwrap(), ["CDwindow-1", "CDwindow-2"]);
        assert!(parse_strings(&json!([1])).is_err());
        let null = answer_value(200, &parse(NULL_ATTRIBUTE)).unwrap();
        assert_eq!(parse_nullable_string(&null).unwrap(), None);
        assert_eq!(
            parse_nullable_string(&json!("1")).unwrap(),
            Some("1".to_owned())
        );
        assert!(parse_nullable_string(&json!(true)).is_err());
    }

    #[test]
    fn command_bodies_have_the_w3c_shapes() {
        assert_eq!(
            find_request(Using::Css, "button[data-positive-decision]"),
            json!({"using":"css selector","value":"button[data-positive-decision]"})
        );
        assert_eq!(
            find_request(Using::XPath, "//h1"),
            json!({"using":"xpath","value":"//h1"})
        );
        assert_eq!(keys_request("ab"), json!({"text":"ab"}));
        assert_eq!(
            navigate_request("http://127.0.0.1:9/x"),
            json!({"url":"http://127.0.0.1:9/x"})
        );
        assert_eq!(keys::ARROW_UP, "\u{E013}");
        assert_eq!(window_request("h1"), json!({"handle":"h1"}));
        assert_eq!(
            frame_request(Some(&Element("e1".into()))),
            json!({"id":{"element-6066-11e4-a52e-4f735466cecf":"e1"}})
        );
        assert_eq!(frame_request(None), json!({"id":null}));
        assert_eq!(empty_request(), json!({}));
    }

    #[test]
    fn a_chord_presses_modifiers_around_the_key_and_releases_in_reverse() {
        let body = chord_request(&[keys::CONTROL, keys::SHIFT], keys::ENTER);
        let actions = &body["actions"][0]["actions"];
        let seq: Vec<(String, String)> = actions
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                (
                    a["type"].as_str().unwrap().to_owned(),
                    a["value"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        let want = [
            ("keyDown", keys::CONTROL),
            ("keyDown", keys::SHIFT),
            ("keyDown", keys::ENTER),
            ("keyUp", keys::ENTER),
            ("keyUp", keys::SHIFT),
            ("keyUp", keys::CONTROL),
        ];
        assert_eq!(
            seq,
            want.map(|(t, v)| (t.to_owned(), v.to_owned())).to_vec()
        );
        assert_eq!(body["actions"][0]["type"], "key");
        assert_eq!(body["actions"][0]["id"], "keyboard");
        // A chord with no modifier is a plain key press.
        let plain = chord_request(&[], keys::TAB);
        assert_eq!(plain["actions"][0]["actions"].as_array().unwrap().len(), 2);
        // A held key has a keyDown and nothing else.
        let held = key_down_request(keys::ENTER);
        assert_eq!(held["actions"][0]["actions"].as_array().unwrap().len(), 1);
        assert_eq!(held["actions"][0]["actions"][0]["type"], "keyDown");
    }

    #[test]
    fn key_codes_are_the_w3c_private_use_points() {
        assert_eq!(keys::ENTER, "\u{E007}");
        assert_eq!(keys::CONTROL, "\u{E009}");
        assert_eq!(keys::SHIFT, "\u{E008}");
        assert_eq!(keys::ESCAPE, "\u{E00C}");
        assert_eq!(keys::ARROW_DOWN, "\u{E015}");
    }

    #[test]
    fn the_driver_command_line_names_both_ports_and_the_native_driver() {
        assert_eq!(
            driver_args(4444, 4445, None),
            ["--port", "4444", "--native-port", "4445"]
        );
        assert_eq!(
            driver_args(1, 2, Some("C:\\drv\\msedgedriver.exe")),
            [
                "--port",
                "1",
                "--native-port",
                "2",
                "--native-driver",
                "C:\\drv\\msedgedriver.exe"
            ]
        );
    }

    /// The client has no "execute script" endpoint: not in a path, not in a method name.
    #[test]
    fn the_client_never_names_the_execute_script_endpoint() {
        // The needle is built so that this file does not contain it itself; `/exec` covers the
        // sync and async spellings and any path built around them.
        let needles = [["/exec", "ute"].concat()];
        for (name, source) in [
            ("webdriver.rs", include_str!("webdriver.rs")),
            ("flows.rs", include_str!("flows.rs")),
        ] {
            for needle in &needles {
                assert!(!source.contains(needle.as_str()), "{name} reaches {needle}");
            }
        }
    }
}

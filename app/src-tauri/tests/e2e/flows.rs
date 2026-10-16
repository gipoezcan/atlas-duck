//! The end-to-end flows (M6 T32): the real `atlas-duck-app` (debug, `scripted-approver`) driven
//! through `tauri-driver`, and the real `atlas-duck` CLI against it, over the `cli_flows` harness.
//!
//! - Every flow starts with `harness::opted_in(..)`: without `ATLAS_DUCK_CLI_FLOWS=1` (CI only,
//!   never set on a developer machine) it prints a `skipped:` line and returns before it builds a
//!   `World`, spawns `tauri-driver` or opens a socket.
//! - The scripted approver holds every request whose reason does not start with `atlas-test:`, so
//!   these flows decide through the real window.
//! - No script runs in a webview (the client has no execute-script call): the flows read the DOM
//!   through element, attribute, property, CSS value, URL and title commands, and press keys
//!   through the actions endpoint. What that cannot observe is listed in the T32 fix report
//!   (`window.__pwned`, `window.open`, the native dialogs, the order of an emit and a `show()`).
//! - The default `Rig` quits the app through the test control file first (the shutdown path runs),
//!   then ends the WebDriver session; the driver's drop ends whatever is left of its process tree.
//! - A failed check is an `Err` (the `ensure!` macros), never a panic, so `Rig::finish` always
//!   runs: screenshot, the world's diagnostics, the app's quit.
//! - The credential window has its own data directory and so its own browser context (S-07). The
//!   flows that need it through the driver may fail on a first CI run for that automation-context
//!   reason alone (see [`CREDENTIAL_UNREACHABLE`]); no test-only shared context is ever added.

use std::time::{Duration, Instant};

use atlas_duck_atlassian::testing::fixtures;
use atlas_duck_atlassian::testing::{MockDc, TEST_USER, TEST_USER_KEY, XAuser};
use atlas_duck_ipc::paths::ENDPOINT_FILE;
use atlas_duck_registry::Product;
use serde_json::{Value, json};

use crate::harness::{APP_EXE, PAT_CANARY, Result, World, WorldOpts, opted_in, parse_envelope};
use crate::webdriver::{DriverProc, Element, WebDriver, keys, wait_for};

/// `return Err(..)` when the condition does not hold (the flows' `assert!`).
macro_rules! ensure {
    ($cond:expr, $($msg:tt)+) => {
        if !$cond {
            return Err(format!($($msg)+).into());
        }
    };
    ($cond:expr) => {
        if !$cond {
            return Err(concat!("check failed: ", stringify!($cond)).into());
        }
    };
}

/// `return Err(..)` with both values when they differ (the flows' `assert_eq!`).
macro_rules! ensure_eq {
    ($left:expr, $right:expr $(,)?) => {
        ensure_eq!($left, $right, "values differ")
    };
    ($left:expr, $right:expr, $($msg:tt)+) => {
        // A `match`, so the operands' temporaries live through the comparison.
        match (&$left, &$right) {
            (left, right) => {
                if left != right {
                    return Err(format!(
                        "{}\n left: {left:?}\nright: {right:?}",
                        format!($($msg)+)
                    )
                    .into());
                }
            }
        }
    };
}

// ---- constants -----------------------------------------------------------------------------------

/// One element, one window, one change in the page.
const WAIT: Duration = Duration::from_secs(30);
/// A cold start of the app, through the driver.
const START_WAIT: Duration = Duration::from_secs(90);
/// The inert period of the decision buttons (PD-70) plus the margin of a slow runner.
const INERT_WAIT: Duration = Duration::from_secs(20);
/// How long a held request may wait for the flow to decide it.
const HOLD: &str = "120";
/// P-01 (spec 13 Performance): the first screen of the preview within this long.
const P01_BUDGET: Duration = Duration::from_millis(1000);
/// S-08's summary: a newline and a run of spaces, so the renderer wraps the value in a `pre`.
const S08_SUMMARY: &str = "S-08 first line\nsecond  line";
/// The reason of the requests the flows decide by hand (no `atlas-test:` prefix: the scripted
/// approver holds them).
const BY_HAND: &str = "e2e: decided by hand";
/// The Â§10.3 credential-page policy, from the shipped page (the placeholder is substituted by Rust).
const CREDENTIAL_HTML: &str = include_str!("../../../ui/credential.html");
const ISOLATION_PLACEHOLDER: &str = "<isolation-origin>";
/// A URL no app window may navigate to (nothing listens on the discard port).
const FOREIGN_URL: &str = "http://127.0.0.1:9/atlas-duck-e2e-foreign";
/// The origin every window's page is served from.
const APP_ORIGIN: &str = if cfg!(windows) {
    "http://tauri.localhost"
} else {
    "tauri://localhost"
};
/// Appended to every failure to reach the credential window through the driver. The credential
/// window has its own data directory (T6, S-07), hence its own browser context, and a driver may
/// not be able to automate it: Linux (`tauri-runtime-wry` allows WebKit automation for the first
/// web context only) and Windows (a data directory of its own is a browser process of its own, and
/// only one owns the debugging port of the driver). A failure of this kind is no product finding:
/// the T6 unit test and a manual check cover the window, and a test-only shared context is never
/// the answer (it would defeat S-07).
const CREDENTIAL_UNREACHABLE: &str = "the credential window could not be reached through the driver. \
     This may be the automation context, not the product: it has its own data directory and so its \
     own browser context (Linux: tauri-runtime-wry allows WebKit automation for the first web \
     context only; Windows: a data directory of its own is a browser process of its own that does \
     not own the debugging port). Do not add a shared context for tests (S-07)";

/// Strings an agent or a server could put into any text field: markup, handlers, URL schemes, a
/// style block, a bidi override. Every one would change the page, the title or the `data-alive`
/// marker if it ran.
const PAYLOADS: [&str; 7] = [
    "<script>window.__pwned=1;document.title='pwned'</script>",
    "<img src=x onerror=\"document.title='pwned'\">",
    "<svg onload=\"document.title='pwned'\"></svg>",
    "javascript:document.title='pwned'",
    "<iframe src=\"http://127.0.0.1:9/frame\"></iframe>",
    "\"><a href=\"http://127.0.0.1:9/link\">x</a>",
    "\u{202e}gnp.exe",
];

fn window_title(name: &str) -> String {
    format!("atlas-duck: {name}")
}

// ---- worlds, mocks ---------------------------------------------------------------------------------

async fn jira_world() -> Result<World> {
    let mut world = World::new(WorldOpts::default())?;
    world
        .provision_store(&[("jira-main", Product::Jira)])
        .await?;
    Ok(world)
}

fn jira(world: &World) -> Result<&MockDc> {
    world
        .mock("jira-main")
        .ok_or_else(|| "no mock for jira-main".into())
}

/// The three enrichment answers of a `jira.issue.create` in `ABC` with issue type `Bug`, and the
/// approved POST's `201`.
async fn mount_create(mock: &MockDc) {
    mock.json("/rest/api/2/project", 200, fixtures::JIRA_PROJECTS)
        .await;
    mock.json(
        "/rest/api/2/issue/createmeta/ABC/issuetypes",
        200,
        fixtures::JIRA_CREATEMETA_ISSUETYPES,
    )
    .await;
    mock.json(
        "/rest/api/2/issue/createmeta/ABC/issuetypes/10002",
        200,
        fixtures::JIRA_CREATEMETA_FIELDS,
    )
    .await;
    mock.json("/rest/api/2/issue", 201, fixtures::JIRA_ISSUE_CREATED)
        .await;
}

/// The default issue with a new key, summary and description.
fn issue_json(key: &str, summary: &str, description: &str) -> Result<String> {
    let mut v: Value = serde_json::from_str(fixtures::JIRA_ISSUE)?;
    v["key"] = json!(key);
    v["fields"]["summary"] = json!(summary);
    v["fields"]["description"] = json!(description);
    Ok(v.to_string())
}

/// A held `jira issue get` of the default fixture issue.
fn hold_read(world: &World) -> Result<tokio::process::Child> {
    world.cli_spawn(&[
        "jira",
        "issue",
        "get",
        "ABC-1",
        "--reason",
        BY_HAND,
        "--timeout",
        HOLD,
    ])
}

// ---- the rig -----------------------------------------------------------------------------------------

/// One test: the world, the `tauri-driver` that owns the app, the WebDriver session. Dropped in this
/// order: the session handle, the driver (its whole process tree is killed: the app included, also
/// an app of a world with no store, which has no lock or pid for the world to find), then the world
/// (its drop stops an app that is still running, from its own records).
struct Rig {
    wd: WebDriver,
    driver: DriverProc,
    world: World,
    /// The handle of the first window (Approvals for a provisioned world).
    first: String,
}

impl Rig {
    /// Starts `tauri-driver`, a session (which starts the app, no arguments: a cold GUI start), and
    /// switches to the window titled `window`. `endpoint`: waits for the app's endpoint file first
    /// (a provisioned world; a world without a store has none).
    async fn start(world: World, window: &str, endpoint: bool) -> Result<Rig> {
        let driver = DriverProc::start(world.env(), &world.root().join("tauri-driver.log")).await?;
        let wd = WebDriver::new_session(driver.base(), APP_EXE, &[]).await?;
        if endpoint {
            let file = world.data_dir().join(ENDPOINT_FILE);
            wait_for("the app's endpoint file", START_WAIT, || async {
                Ok(file.try_exists()?.then_some(()))
            })
            .await?;
        }
        let first = wd.switch_to_title(window, START_WAIT).await?;
        Ok(Rig {
            wd,
            driver,
            world,
            first,
        })
    }

    async fn approvals(world: World) -> Result<Rig> {
        Rig::start(world, &window_title("Approvals"), true).await
    }

    /// Ends the flow: on an error a screenshot and the world's diagnostics join the message; then the
    /// app quits through the test control file and the session ends.
    async fn finish(self, name: &str, outcome: Result<()>) -> Result<()> {
        let outcome = self.annotate(name, outcome).await;
        let quit = self.world.quit_app().await;
        let _ = self.wd.quit().await;
        outcome.and(quit)
    }

    /// [`Rig::finish`] for a world with no store: before the wizard has finished the app serves
    /// nothing, so it has no control dir to quit through, no pid record and no `instance.lock`.
    /// The session ends and then the driver's whole process tree (the app too) is killed here,
    /// before the world goes: nothing is left running for the next flow.
    async fn finish_setup(mut self, name: &str, outcome: Result<()>) -> Result<()> {
        let outcome = self.annotate(name, outcome).await;
        let _ = self.wd.quit().await;
        self.driver.kill_tree();
        outcome
    }

    /// On an error: the message gains a screenshot and the world's diagnostics.
    async fn annotate(&self, name: &str, outcome: Result<()>) -> Result<()> {
        match outcome {
            Ok(()) => Ok(()),
            Err(e) => {
                let shot = self.wd.screenshot_on_failure(name).await;
                Err(format!("{e}\nscreenshot: {shot:?}\n{}", self.world.diagnostics()).into())
            }
        }
    }

    async fn to_approvals(&self) -> Result<()> {
        self.wd.switch_to_window(&self.first).await
    }

    /// Opens a window from the Approvals header and switches to it.
    async fn open_window(&self, button: &str, title: &str) -> Result<()> {
        self.to_approvals().await?;
        let b = self
            .wd
            .wait_find_xpath(
                &format!("//header//nav//button[normalize-space()='{button}']"),
                WAIT,
            )
            .await?;
        self.wd.click(&b).await?;
        self.wd.switch_to_title(&window_title(title), WAIT).await?;
        Ok(())
    }

    /// Approvals -> Settings -> the instance's token button -> the credential window, once its
    /// `credential_context` call succeeded: the token form is there and the failed-load page (an
    /// `h1.title` too, with a `p.error` and no form) is not.
    async fn open_credential(&self) -> Result<()> {
        self.open_window("Settings", "Settings").await?;
        let token = self
            .wd
            .wait_find_xpath(
                "//button[normalize-space()='Replace token' or normalize-space()='Add token']",
                WAIT,
            )
            .await?;
        self.wd.click(&token).await?;
        self.switch_to_credential().await
    }

    /// Switches to the open credential window and waits for its loaded page.
    async fn switch_to_credential(&self) -> Result<()> {
        let unreachable = |e: Box<dyn std::error::Error>| -> Box<dyn std::error::Error> {
            format!("{e}\n{CREDENTIAL_UNREACHABLE}").into()
        };
        self.wd
            .switch_to_title(&window_title("Credential"), WAIT)
            .await
            .map_err(unreachable)?;
        if let Err(e) = self.wd.wait_find("main#credential form.entry", WAIT).await {
            // The window answers, but its call was refused: a product finding, not the driver.
            if !self.wd.find_all("main#credential .error").await?.is_empty() {
                return Err(
                    "the credential window shows its failed-load error (credential_context refused)"
                        .into(),
                );
            }
            return Err(unreachable(e));
        }
        Ok(())
    }
}

// ---- page helpers ------------------------------------------------------------------------------------

async fn body_text(wd: &WebDriver) -> Result<String> {
    let body = wd.find("body").await?;
    wd.text(&body).await
}

/// Waits until the page text satisfies `accept`.
async fn wait_text(
    wd: &WebDriver,
    what: &str,
    within: Duration,
    accept: impl Fn(&str) -> bool,
) -> Result<String> {
    wait_for(what, within, || async {
        let text = body_text(wd).await?;
        Ok(accept(&text).then_some(text))
    })
    .await
}

async fn wait_enabled(wd: &WebDriver, e: &Element, within: Duration) -> Result<()> {
    wait_for("an enabled control", within, || async {
        Ok(wd.is_enabled(e).await?.then_some(()))
    })
    .await
}

/// The Open button of the pending row of `op_id`.
fn row_open_xpath(op_id: &str) -> String {
    format!(
        "//div[contains(@class,'queue-item')][.//span[contains(@class,'op-id')][normalize-space()='{op_id}']]\
         //button[starts-with(@aria-label,'Open ')]"
    )
}

/// Clicks Open on the row of `op_id` (waits for the row: the request needs its fetch and enrichment).
async fn open_row(wd: &WebDriver, op_id: &str) -> Result<()> {
    let open = wd
        .wait_find_xpath(&row_open_xpath(op_id), START_WAIT)
        .await?;
    wd.click(&open).await
}

/// Waits for the preview iframe to hold a table row, pressing "Open preview" when the detail pane
/// offers it. The wait ends in the Approvals document (not the frame).
async fn first_preview_row(wd: &WebDriver, within: Duration) -> Result<()> {
    first_preview_text(wd, within, None).await.map(|_| ())
}

/// [`first_preview_row`] that also returns the frame's text, and (with `not`) does not accept a
/// frame whose text is `not`: a previous request's frame that is still mounted cannot satisfy it.
async fn first_preview_text(wd: &WebDriver, within: Duration, not: Option<&str>) -> Result<String> {
    let pressed = std::cell::Cell::new(false);
    wait_for("a table row in the preview frame", within, || async {
        let frames = wd.find_all("iframe[title='Preview']").await?;
        let Some(frame) = frames.first() else {
            if !pressed.get()
                && let Ok(b) = wd
                    .find_xpath("//article//button[normalize-space()='Open preview']")
                    .await
            {
                pressed.set(true);
                wd.click(&b).await?;
            }
            return Ok(None);
        };
        // A frame that is reloading (new srcdoc) answers "no such frame": look again.
        if wd.switch_to_frame(frame).await.is_err() {
            return Ok(None);
        }
        let rows = wd.find_all("tr").await;
        let text = match &rows {
            Ok(r) if !r.is_empty() => Some(body_text(wd).await),
            _ => None,
        };
        wd.switch_to_parent().await?;
        Ok(match text {
            Some(Ok(t)) if not != Some(t.as_str()) => Some(t),
            _ => None,
        })
    })
    .await
}

/// The decision button of the opened card (Approve, Release, ...), once its inert period is over.
async fn decision_button(wd: &WebDriver) -> Result<Element> {
    // The window must be focused for the page to leave its all-inert state: a click on the heading.
    if let Ok(h) = wd.find("h1").await {
        let _ = wd.click(&h).await;
    }
    let b = wd.wait_find("button[data-positive-decision]", WAIT).await?;
    if let Err(e) = wait_enabled(wd, &b, INERT_WAIT).await {
        return Err(format!("{e} (the decision button): {}", detail_state(wd).await).into());
    }
    Ok(b)
}

/// What the opened card says, for a failure text: its status and alert lines and its own buttons
/// (an "Open" button means the shown revision went stale), never the preview frame.
async fn detail_state(wd: &WebDriver) -> String {
    let lines = match wd
        .find_all(
            "article.detail [role=status], article.detail [role=alert], article.detail > button",
        )
        .await
    {
        Ok(found) => found,
        Err(e) => return format!("the detail pane is unreadable ({e})"),
    };
    let mut texts = Vec::new();
    for e in &lines {
        texts.push(
            wd.text(e)
                .await
                .unwrap_or_else(|e| format!("unreadable ({e})")),
        );
    }
    if texts.is_empty() {
        "the detail pane shows no status, alert or button of its own".to_owned()
    } else {
        format!("the detail pane shows {texts:?}")
    }
}

/// How many clicks on the enabled positive button UI-06 makes before it gives up.
const APPROVE_CLICKS: u32 = 3;
/// A click that changed nothing on the page within this long was not taken.
const NOT_TAKEN_AFTER: Duration = Duration::from_secs(3);

/// Clicks the positive button `b` until the page records the decision. The page drops a click that
/// falls into an inert period without a trace (spec 5.6: `send` re-reads the clock), and a driver
/// may start such a period itself (its input can focus the window: a window focus restarts it). A
/// click that was not taken leaves the page as it was: no decision, no alert, the button enabled
/// (a call in flight disables it). Only such a click is repeated, after the inert period, at most
/// [`APPROVE_CLICKS`] times; an alert, a stale revision or a decision ends the loop, and every
/// failure names what the card shows.
async fn click_until_decided(wd: &WebDriver, b: &Element) -> Result<()> {
    for click in 1..=APPROVE_CLICKS {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        if let Err(e) = wait_enabled(wd, b, INERT_WAIT).await {
            return Err(format!("{e} (before click {click}): {}", detail_state(wd).await).into());
        }
        wd.click(b).await?;
        let clicked = Instant::now();
        loop {
            if body_text(wd).await?.contains("Decision recorded") {
                return Ok(());
            }
            // A decided card shows its Open button too (nothing is opened any more): the decision
            // is read again after the check, so one landing in between is no refusal.
            let refused = !wd.find_all("article.detail [role=alert]").await?.is_empty()
                || !wd.find_all("article.detail > button").await?.is_empty();
            if refused && body_text(wd).await?.contains("Decision recorded") {
                return Ok(());
            }
            if refused {
                return Err(format!(
                    "click {click} on the enabled button was answered without a decision: {}",
                    detail_state(wd).await
                )
                .into());
            }
            if clicked.elapsed() > WAIT {
                return Err(format!(
                    "timed out after {WAIT:?} waiting for the decision of click {click}: {}",
                    detail_state(wd).await
                )
                .into());
            }
            // Still enabled: not in flight, so not taken. (Gone or disabled: in flight or decided.)
            if clicked.elapsed() > NOT_TAKEN_AFTER && wd.is_enabled(b).await.unwrap_or(false) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    Err(format!(
        "{APPROVE_CLICKS} clicks on the enabled button were not taken (no decision, no alert, the \
         button stayed enabled): {}",
        detail_state(wd).await
    )
    .into())
}

async fn click_tabs(wd: &WebDriver) -> Result<usize> {
    let tabs = wd.find_all("[role=tab]").await?;
    for t in &tabs {
        wd.click(t).await?;
        // Each tab renders (or fails to) before the next one is shown.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    Ok(tabs.len())
}

/// No element of the current document is a script without a source, a handler attribute, a link or
/// a loaded subresource (the document's own module script and its stylesheet are the only ones).
async fn assert_inert_document(wd: &WebDriver, what: &str) -> Result<()> {
    for css in [
        "script:not([src])",
        "[onerror],[onload],[onclick],[onfocus],[onmouseover],[onanimationstart]",
        "a[href]",
        "img",
        "object,embed,applet,base",
    ] {
        let hits = wd.find_all(css).await?;
        if !hits.is_empty() {
            return Err(format!("{what}: {} element(s) match {css:?}", hits.len()).into());
        }
    }
    Ok(())
}

// ---- UI-06 -----------------------------------------------------------------------------------------------

/// UI-06: the CLI submits `jira.issue.create`; the request appears; the user opens it and approves it
/// by hand; the CLI exits 0 with the receipt; "Verify now" passes. Enter and Space on the positive
/// button do nothing (PD-91: no single-key approval).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui06_create_approve_receipt_verify_now() -> Result<()> {
    if !opted_in("ui06_create_approve_receipt_verify_now") {
        return Ok(());
    }
    let world = jira_world().await?;
    mount_create(jira(&world)?).await;
    let rig = Rig::approvals(world).await?;
    let outcome = ui06(&rig).await;
    rig.finish("ui06", outcome).await
}

async fn ui06(rig: &Rig) -> Result<()> {
    let wd = &rig.wd;
    let mut cli = rig.world.cli_spawn(&[
        "jira",
        "issue",
        "create",
        "--project",
        "ABC",
        "--type",
        "Bug",
        "--summary",
        "E2E create",
        "--reason",
        BY_HAND,
        "--timeout",
        HOLD,
    ])?;
    open_row(wd, "jira.issue.create").await?;
    first_preview_row(wd, WAIT).await?;
    let approve = decision_button(wd).await?;
    // PD-91: neither key approves.
    wd.send_keys(&approve, keys::ENTER).await?;
    wd.send_keys(&approve, keys::SPACE).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    // A wrongly accepted key would still be in its write, POST and reply here: the CLI's exit is
    // not enough, so the page, the button and the mock are looked at too.
    ensure!(
        cli.try_wait()?.is_none(),
        "the request was decided by Enter or Space on the Approve button"
    );
    ensure!(
        !body_text(wd).await?.contains("Decision recorded"),
        "the page recorded a decision after Enter or Space"
    );
    ensure!(
        !wd.find_all("button[data-positive-decision]")
            .await?
            .is_empty(),
        "the Approve button is gone after Enter or Space"
    );
    let posted = jira(&rig.world)?
        .received()
        .await
        .iter()
        .any(|r| r.method.as_str() == "POST" && r.url.path().ends_with("/rest/api/2/issue"));
    ensure!(!posted, "the mock saw the create POST after Enter or Space");
    // The keys above may have focused the window (a driver's input can): a window focus starts the
    // inert period again (spec 5.6), and a click inside it is dropped. Wait it out, then click.
    click_until_decided(wd, &approve).await?;

    let out = tokio::time::timeout(Duration::from_secs(120), cli.wait_with_output())
        .await
        .map_err(|_| "the CLI did not end after the approval")??;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    ensure_eq!(out.status.code(), Some(0), "stdout: {stdout}");
    let env: Value = serde_json::from_str(stdout.trim())?;
    ensure_eq!(env["status"], "succeeded", "{stdout}");
    ensure_eq!(env["data"]["receipt"]["key"], "ABC-3", "{stdout}");
    ensure!(
        !stdout.contains(PAT_CANARY),
        "the token canary reached the CLI output"
    );
    ensure!(parse_envelope(&stdout).is_some(), "{stdout}");

    // Verify now, in the Audit window.
    rig.open_window("Audit", "Audit").await?;
    let verify = wd
        .wait_find_xpath("//button[normalize-space()='Verify now']", WAIT)
        .await?;
    wd.click(&verify).await?;
    let text = wait_text(wd, "the verification result", WAIT, |t| {
        t.contains("verified") || t.contains("did not complete") || t.contains("integrity incident")
    })
    .await?;
    ensure!(
        text.contains("verified")
            && !text.contains("did not complete")
            && !text.contains("integrity incident"),
        "Verify now: {text}"
    );
    Ok(())
}

// ---- S-06: payloads in a real webview ------------------------------------------------------------------

/// S-06 (webview half): canary payloads in the summary and description the mock serves and in the
/// reason. After every tab of the request has rendered, the window title, the page's own
/// `data-alive` marker and the number of windows are unchanged, and the document has no script,
/// handler or link.
/// (`window.__pwned` itself cannot be read without a script: the payload sets the title as well.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s06_payloads_inert_in_real_webview() -> Result<()> {
    if !opted_in("s06_payloads_inert_in_real_webview") {
        return Ok(());
    }
    let world = jira_world().await?;
    let joined = PAYLOADS.join(" | ");
    jira(&world)?
        .json(
            "/rest/api/2/issue/ABC-77",
            200,
            &issue_json("ABC-77", &joined, &joined)?,
        )
        .await;
    let rig = Rig::approvals(world).await?;
    let outcome = s06(&rig).await;
    rig.finish("s06", outcome).await
}

async fn s06(rig: &Rig) -> Result<()> {
    let wd = &rig.wd;
    let _cli = rig.world.cli_spawn(&[
        "jira",
        "issue",
        "get",
        "ABC-77",
        "--reason",
        PAYLOADS[1],
        "--timeout",
        HOLD,
    ])?;
    let title = wd.title().await?;
    let handles = wd.window_handles().await?;
    let alive = wd.find("html").await?;
    ensure_eq!(
        wd.attribute(&alive, "data-alive").await?.as_deref(),
        Some("1")
    );

    open_row(wd, "jira.issue.get").await?;
    first_preview_row(wd, WAIT).await?;
    let tabs = click_tabs(wd).await?;
    ensure!(tabs >= 4, "the detail pane has {tabs} tabs");
    // Back on the preview tab: the frame's own document.
    let preview = wd
        .wait_find_xpath("//button[@role='tab'][normalize-space()='Preview']", WAIT)
        .await?;
    wd.click(&preview).await?;
    first_preview_row(wd, WAIT).await?;
    let frame = wd.find("iframe[title='Preview']").await?;
    wd.switch_to_frame(&frame).await?;
    assert_inert_document(wd, "preview frame").await?;
    let in_frame = body_text(wd).await?;
    wd.switch_to_parent().await?;
    // The payload text is shown as text, not run: it is in the frame's text.
    ensure!(
        in_frame.contains("<script>") || in_frame.contains("&lt;script&gt;"),
        "the payload is not shown as text: {in_frame}"
    );
    assert_inert_document(wd, "approvals window").await?;

    ensure_eq!(wd.title().await?, title, "the window title changed");
    ensure!(!title.contains("pwned"));
    let alive = wd.find("html").await?;
    ensure_eq!(
        wd.attribute(&alive, "data-alive").await?.as_deref(),
        Some("1")
    );
    ensure_eq!(wd.window_handles().await?, handles, "a window appeared");
    Ok(())
}

// ---- S-07 and the credential page's CSP -----------------------------------------------------------------

/// S-07 (webview half): a value typed into the Approvals window's in-memory state (the deny reason) is
/// absent from the credential window, before and after a reload of each. This evidences in-memory
/// separation only: that the credential window has a data directory (or incognito mode) of its own
/// is `windows::credential_builder_incognito_or_own_dir` (T6), and the driver cannot show a storage
/// partition. Needs the credential window through the driver (see [`CREDENTIAL_UNREACHABLE`]).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s07_credential_window_incognito_or_own_data_dir() -> Result<()> {
    if !opted_in("s07_credential_window_incognito_or_own_data_dir") {
        return Ok(());
    }
    let world = jira_world().await?;
    let rig = Rig::approvals(world).await?;
    let outcome = s07(&rig).await;
    rig.finish("s07", outcome).await
}

/// Types `text` into a field of the Approvals window. The window swallows every key and text event
/// for a second after a focus the user did not ask for (spec 5.6 "focus inert": a window focus, or
/// the dialog field's own programmatic focus), and a driver's "Element Send Keys" is such input:
/// sent at once it is dropped and the field stays empty. So the keys are sent again, only while the
/// field is still empty, until they land or `WAIT` is over (a field that holds anything else is a
/// failure: the keys were not all swallowed).
async fn type_when_armed(wd: &WebDriver, field: &Element, text: &str) -> Result<()> {
    let deadline = Instant::now() + WAIT;
    loop {
        tokio::time::sleep(Duration::from_millis(1100)).await;
        wd.send_keys(field, text).await?;
        match wd.property(field, "value").await?.as_deref() {
            Some(v) if v == text => return Ok(()),
            None | Some("") if Instant::now() < deadline => {}
            other => return Err(format!("the field holds {other:?} after typing {text:?}").into()),
        }
    }
}

async fn s07(rig: &Rig) -> Result<()> {
    const TYPED: &str = "S07-typed-in-approvals-5b7e1c";
    let wd = &rig.wd;
    let _cli = hold_read(&rig.world)?;
    open_row(wd, "jira.issue.get").await?;
    first_preview_row(wd, WAIT).await?;
    let deny = wd
        .wait_find_xpath(
            "//div[@aria-label='Decision']//button[normalize-space()='Deny']",
            WAIT,
        )
        .await?;
    wd.click(&deny).await?;
    let field = wd
        .wait_find(".deny-dialog input, .deny-dialog textarea", WAIT)
        .await?;
    type_when_armed(wd, &field, TYPED).await?;
    // The typed value is the property (the content attribute stays empty on a strict driver).
    ensure_eq!(wd.property(&field, "value").await?.as_deref(), Some(TYPED));

    rig.open_credential().await?;
    let absent = |text: &str| !text.contains(TYPED);
    ensure!(
        absent(&body_text(wd).await?),
        "typed text in the credential window"
    );
    wd.refresh().await?;
    wd.wait_find("main#credential form.entry", WAIT).await?;
    ensure!(
        absent(&body_text(wd).await?),
        "typed text after the credential reload"
    );
    // The loop is not vacuous: the token form has inputs.
    let inputs = wd.find_all("main#credential input").await?;
    ensure!(!inputs.is_empty(), "the credential window has no input");
    for input in inputs {
        let v = wd.property(&input, "value").await?;
        ensure!(
            v.as_deref().is_none_or(str::is_empty),
            "a credential field is not empty"
        );
    }

    rig.to_approvals().await?;
    wd.refresh().await?;
    wd.wait_find("h1", WAIT).await?;
    ensure!(
        wd.find_all(".deny-dialog").await?.is_empty(),
        "the deny dialog survived the reload"
    );
    ensure!(
        absent(&body_text(wd).await?),
        "typed text after the Approvals reload"
    );

    rig.switch_to_credential().await?;
    wd.refresh().await?;
    wd.wait_find("main#credential form.entry", WAIT).await?;
    ensure!(
        absent(&body_text(wd).await?),
        "typed text in the credential window at the end"
    );
    Ok(())
}

/// V35: the credential page counts `securitypolicyviolation` events in its own production listener
/// (a `data-csp-violations` attribute on the root, no IPC): 0 in normal use. Its meta tag is the
/// Â§10.3 policy of the shipped page with this build's isolation origin in `frame-src`. The counter
/// starts from the page's module script, after Tauri's init scripts ran: it covers violations after
/// page start only (a blocked isolation frame shows as the page never loading its context). Needs
/// the credential window through the driver (see [`CREDENTIAL_UNREACHABLE`]).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credential_page_meta_csp_enforced() -> Result<()> {
    if !opted_in("credential_page_meta_csp_enforced") {
        return Ok(());
    }
    let world = jira_world().await?;
    let rig = Rig::approvals(world).await?;
    let outcome = csp(&rig).await;
    rig.finish("credential_csp", outcome).await
}

/// The `content` of the page's policy `<meta>`, from the shipped `credential.html` (HTML-escaped there).
fn shipped_credential_policy() -> Result<String> {
    let marker = "http-equiv=\"Content-Security-Policy\" content=\"";
    let start = CREDENTIAL_HTML
        .find(marker)
        .ok_or("credential.html has no policy meta")?
        + marker.len();
    let rest = &CREDENTIAL_HTML[start..];
    let end = rest.find('"').ok_or("unterminated policy meta")?;
    Ok(rest[..end].replace("&lt;", "<").replace("&gt;", ">"))
}

/// `frame-src <origin>` of a policy: the origin.
fn frame_src_of(policy: &str) -> Option<&str> {
    policy
        .split(';')
        .map(str::trim)
        .find_map(|d| d.strip_prefix("frame-src "))
        .map(str::trim)
}

/// `isolation-<uuid>://localhost` (macOS, Linux) or `http://isolation-<uuid>.localhost` (Windows).
fn is_isolation_origin(origin: &str) -> bool {
    let id = origin
        .strip_prefix("isolation-")
        .and_then(|r| r.strip_suffix("://localhost"))
        .or_else(|| {
            origin
                .strip_prefix("http://isolation-")
                .and_then(|r| r.strip_suffix(".localhost"))
        });
    id.is_some_and(|u| u.len() == 36 && u.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-'))
}

async fn csp(rig: &Rig) -> Result<()> {
    let wd = &rig.wd;
    rig.open_credential().await?;
    let meta = wd
        .find("meta[http-equiv='Content-Security-Policy']")
        .await?;
    let observed = wd
        .attribute(&meta, "content")
        .await?
        .ok_or("the policy meta has no content")?;
    let origin = frame_src_of(&observed)
        .ok_or("no frame-src in the page's policy")?
        .to_owned();
    ensure!(is_isolation_origin(&origin), "frame-src is {origin:?}");
    let template = shipped_credential_policy()?;
    ensure!(template.contains(ISOLATION_PLACEHOLDER), "{template}");
    ensure_eq!(
        observed,
        template.replace(ISOLATION_PLACEHOLDER, &origin),
        "the page's policy differs from the shipped Â§10.3 policy"
    );
    // Used for a while (a reload and a second look), still no violation.
    wd.refresh().await?;
    wd.wait_find("main#credential form.entry", WAIT).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let root = wd.find("html").await?;
    let count = wd.attribute(&root, "data-csp-violations").await?;
    ensure!(
        count.as_deref() == Some("0"),
        "the credential page reported a CSP violation: count {count:?}, last: {}",
        last_violation(wd, &root).await
    );
    Ok(())
}

// ---- S-08 (V24): the preview iframe --------------------------------------------------------------------

/// S-08 (webview half, V24): `preview.css` loads inside the sandboxed `srcdoc` frame (computed styles
/// of `table`, `bdi` and `pre` reflect its rules); the mock's summary is multi-line with a run of
/// spaces, so the renderer emits a `bdi` in a `pre` (the flow fails when either is absent: the UA
/// default of `pre` is `white-space: pre`, so `pre-wrap` shows the stylesheet applied). The mock body
/// carries an inline `<style>`, a `style` attribute and a remote `<img>` and `<link>`, and the
/// rendered document contains none of them (its one `<link>` is the renderer's own `preview.css`,
/// compared to the exact href) while the page loaded and the mock saw no image request. (That the
/// CSP would block such content if it survived the sanitizer is the CSP config check and V24
/// evidence: no test hook may inject unsanitized HTML.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s08_preview_css_loads_inline_style_and_remote_image_blocked() -> Result<()> {
    if !opted_in("s08_preview_css_loads_inline_style_and_remote_image_blocked") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mock = jira(&world)?;
    let pixel = format!("{}/pixel.png", mock.base_url());
    let body = format!(
        "<style>body{{display:none}}</style><p style=\"color:red\">styled</p>\
         <img src=\"{pixel}\"><link rel=\"stylesheet\" href=\"{pixel}\">"
    );
    mock.json(
        "/rest/api/2/issue/ABC-78",
        200,
        &issue_json("ABC-78", S08_SUMMARY, &body)?,
    )
    .await;
    let rig = Rig::approvals(world).await?;
    let outcome = s08(&rig).await;
    rig.finish("s08", outcome).await
}

async fn s08(rig: &Rig) -> Result<()> {
    let wd = &rig.wd;
    let _cli = rig.world.cli_spawn(&[
        "jira",
        "issue",
        "get",
        "ABC-78",
        "--reason",
        BY_HAND,
        "--timeout",
        HOLD,
    ])?;
    open_row(wd, "jira.issue.get").await?;
    first_preview_row(wd, WAIT).await?;
    let frame = wd.find("iframe[title='Preview']").await?;
    ensure_eq!(
        wd.attribute(&frame, "sandbox").await?.as_deref(),
        Some(""),
        "the preview iframe has a sandbox attribute with no tokens"
    );
    // The renderer sets no `src` (PreviewFrame.tsx renders `sandbox` and `srcDoc` only). A driver's "Get Element
    // Attribute" is the legacy atom on WebKit and WebView2: for `src` it answers the resolved
    // property, "" for an iframe without one (or "about:srcdoc" for a srcdoc frame), not `null`. So
    // the check is that no URL is there: absent, empty or the srcdoc document itself.
    let src = wd.attribute(&frame, "src").await?;
    ensure!(
        matches!(src.as_deref(), None | Some("") | Some("about:srcdoc")),
        "the preview iframe has a src: {src:?}"
    );
    wd.switch_to_frame(&frame).await?;
    // The stylesheet applied: element rules of preview.css (PD-92 contingency if this fails).
    let table = wd.find("table").await?;
    ensure_eq!(wd.css_value(&table, "border-collapse").await?, "collapse");
    // The multi-line summary is a `bdi` in a `pre`; both must exist and carry the stylesheet's rule.
    for element in ["bdi", "pre"] {
        let found = wd.find_all(element).await?;
        let Some(first) = found.first() else {
            return Err(format!(
                "the preview document has no <{element}>: the multi-line value did not reach the renderer"
            )
            .into());
        };
        ensure_eq!(
            wd.css_value(first, "white-space").await?,
            "pre-wrap",
            "white-space of the first <{element}>"
        );
    }
    // None of the active content is in the rendered document. The one `<link>` is the renderer's
    // own stylesheet, by its exact href; a `<style>` is allowed only in the head (the PD-92
    // contingency), never in the body.
    let expected_href = format!("{APP_ORIGIN}/preview.css");
    for link in wd.find_all("link").await? {
        ensure_eq!(
            wd.attribute(&link, "href").await?.as_deref(),
            Some(expected_href.as_str()),
            "a <link> of the preview document is not the renderer's stylesheet"
        );
        ensure_eq!(
            wd.attribute(&link, "rel").await?.as_deref(),
            Some("stylesheet")
        );
    }
    for css in [
        "body link",
        "body style",
        "[style]",
        "img",
        "script",
        "iframe,frame,object,embed,base,meta[http-equiv=refresh]",
        "[onerror],[onload],[onclick]",
        "[src],[srcset],[poster],[background],[action],[formaction],[data],[href]:not(link)",
    ] {
        let hits = wd.find_all(css).await?;
        ensure!(
            hits.is_empty(),
            "the preview document holds {} element(s) of {css:?}",
            hits.len()
        );
    }
    let shown = body_text(wd).await?;
    wd.switch_to_parent().await?;
    ensure!(
        shown.contains("styled"),
        "the body text is shown as text: {shown}"
    );
    let seen = jira(&rig.world)?.received().await;
    ensure!(
        seen.iter().all(|r| !r.url.path().ends_with("/pixel.png")),
        "the remote image was requested"
    );
    Ok(())
}

// ---- S-09: every window round-trips one granted call ---------------------------------------------------

/// S-09 (webview half, V34): in a real webview behind the isolation pattern each window shows the
/// result of one granted read-only call, shows no alert, and reports no `securitypolicyviolation`
/// (every window counts them in `data-csp-violations`: the production listener of `shared/alive.ts`,
/// and the credential page's own). The counters start from the page's module script, after Tauri's
/// init scripts: a blocked isolation frame (raised before) shows as the page never reaching its
/// result, which the waits below fail on. The credential part needs that window through the driver
/// (see [`CREDENTIAL_UNREACHABLE`]).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s09_isolation_invoke_round_trips_every_window() -> Result<()> {
    if !opted_in("s09_isolation_invoke_round_trips_every_window") {
        return Ok(());
    }
    let world = jira_world().await?;
    let rig = Rig::approvals(world).await?;
    let outcome = s09(&rig).await;
    rig.finish("s09", outcome).await
}

async fn s09(rig: &Rig) -> Result<()> {
    let wd = &rig.wd;
    // Approvals: queue_list answered (the empty queue).
    wait_text(wd, "the empty queue", WAIT, |t| {
        t.contains("No pending requests")
    })
    .await?;
    // Settings: settings_get answered (the provisioned instance).
    rig.open_window("Settings", "Settings").await?;
    wait_text(wd, "the instance row", WAIT, |t| t.contains("jira-main")).await?;
    // Audit: verify_now answered.
    rig.open_window("Audit", "Audit").await?;
    let verify = wd
        .wait_find_xpath("//button[normalize-space()='Verify now']", WAIT)
        .await?;
    wd.click(&verify).await?;
    wait_text(wd, "the verification result", WAIT, |t| {
        t.contains("verified")
    })
    .await?;
    // Running scripts: running_list answered.
    rig.open_window("Running scripts", "Running scripts")
        .await?;
    wait_text(wd, "the running list", WAIT, |t| {
        t.contains("No scripts are running.")
    })
    .await?;
    // Onboarding: onboarding_text answered.
    rig.open_window("Onboarding", "Onboarding").await?;
    wd.wait_find("pre.onboarding-text", WAIT).await?;
    // No window is in an error state or reported a policy violation.
    for title in [
        "Approvals",
        "Settings",
        "Audit",
        "Running scripts",
        "Onboarding",
    ] {
        wd.switch_to_title(&window_title(title), WAIT).await?;
        no_alert_no_violation(wd, title).await?;
    }
    // Credential, last (it may not be drivable, see above): credential_context answered
    // (`open_credential` waits for the token form, which the failed-load page does not have).
    rig.open_credential().await?;
    no_alert_no_violation(wd, "Credential").await?;
    Ok(())
}

/// The current window shows no `role=alert` and its violation counter reads exactly `0` (an absent
/// counter means the page's startup code did not run).
async fn no_alert_no_violation(wd: &WebDriver, title: &str) -> Result<()> {
    let alerts = wd.find_all("[role=alert]").await?;
    ensure!(alerts.is_empty(), "{title}: an alert is shown");
    let root = wd.find("html").await?;
    let count = wd.attribute(&root, "data-csp-violations").await?;
    ensure!(
        count.as_deref() == Some("0"),
        "{title}: securitypolicyviolation events were reported (or the counter is missing): count {count:?}, last: {}",
        last_violation(wd, &root).await
    );
    Ok(())
}

/// The page's `data-csp-last` (directive and blocked resource of the latest violation), for the
/// failure text only.
async fn last_violation(wd: &WebDriver, root: &Element) -> String {
    match wd.attribute(root, "data-csp-last").await {
        Ok(Some(v)) => v,
        Ok(None) => "none recorded".to_owned(),
        Err(e) => format!("unreadable ({e})"),
    }
}

/// S-09 (setup window): a world with no store opens the Setup window, which shows the wizard's step
/// from `wizard_state` through the isolation pattern.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s09_isolation_invoke_setup_window() -> Result<()> {
    if !opted_in("s09_isolation_invoke_setup_window") {
        return Ok(());
    }
    let world = World::new(WorldOpts::default())?;
    let rig = Rig::start(world, &window_title("Setup"), false).await?;
    let outcome = setup_window(&rig).await;
    rig.finish_setup("s09_setup", outcome).await
}

async fn setup_window(rig: &Rig) -> Result<()> {
    rig.wd.wait_find("section h2", WAIT).await?;
    let text = body_text(&rig.wd).await?;
    ensure!(!text.contains("Loading"), "{text}");
    no_alert_no_violation(&rig.wd, "Setup").await?;
    // Navigation refusal covers this window too (it is the one with a wizard behind it).
    assert_navigation_refused(&rig.wd, "Setup", "data-alive").await
}

// ---- main-frame navigation refusal -----------------------------------------------------------------------

/// The current window, asked by W3C "Navigate To" for a foreign URL, stays the app's page: the URL is
/// still under the app origin, and the title, the set of windows and the page's own `marker`
/// attribute (`data-alive`, or the credential page's `data-csp-violations`) are unchanged. The
/// driver's answer to the command is not looked at (a refusal may be an error, an ok or a timeout).
/// This is no script injection: it is the endpoint a user's address bar equals.
async fn assert_navigation_refused(wd: &WebDriver, what: &str, marker: &str) -> Result<()> {
    let title = wd.title().await?;
    let handles = wd.window_handles().await?;
    let before = wd.current_url().await?;
    ensure!(
        before.starts_with(APP_ORIGIN),
        "{what}: the window starts at {before:?}, not under {APP_ORIGIN}"
    );
    let root = wd.find("html").await?;
    let marked = wd.attribute(&root, marker).await?;
    ensure!(
        marked.is_some(),
        "{what}: no {marker} before the navigation"
    );
    let _ = wd.navigate(FOREIGN_URL).await;
    // A navigation that was not refused needs a moment to show.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let after = wd.current_url().await?;
    ensure!(
        after.starts_with(APP_ORIGIN),
        "{what}: the window navigated to {after:?}"
    );
    ensure_eq!(wd.title().await?, title, "{what}: the title changed");
    ensure_eq!(
        wd.window_handles().await?,
        handles,
        "{what}: a window appeared or went"
    );
    let root = wd.find("html").await?;
    ensure_eq!(
        wd.attribute(&root, marker).await?,
        marked,
        "{what}: the document was replaced ({marker} changed)"
    );
    Ok(())
}

/// Navigation refusal in the five main windows (every label the Approvals header opens, but the
/// credential one).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s09_main_frame_navigation_refused_in_every_window() -> Result<()> {
    if !opted_in("s09_main_frame_navigation_refused_in_every_window") {
        return Ok(());
    }
    let world = jira_world().await?;
    let rig = Rig::approvals(world).await?;
    let outcome = navigation_main(&rig).await;
    rig.finish("navigation", outcome).await
}

async fn navigation_main(rig: &Rig) -> Result<()> {
    let wd = &rig.wd;
    wd.wait_find("h1", WAIT).await?;
    assert_navigation_refused(wd, "Approvals", "data-alive").await?;
    for (button, title) in [
        ("Settings", "Settings"),
        ("Audit", "Audit"),
        ("Running scripts", "Running scripts"),
        ("Onboarding", "Onboarding"),
    ] {
        rig.open_window(button, title).await?;
        wd.wait_find("h1", WAIT).await?;
        assert_navigation_refused(wd, title, "data-alive").await?;
    }
    Ok(())
}

/// Navigation refusal in the credential window. Own flow: it needs that window through the driver
/// (see [`CREDENTIAL_UNREACHABLE`]) and must not hide the main windows' result.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s09_main_frame_navigation_refused_in_credential_window() -> Result<()> {
    if !opted_in("s09_main_frame_navigation_refused_in_credential_window") {
        return Ok(());
    }
    let world = jira_world().await?;
    let rig = Rig::approvals(world).await?;
    let outcome: Result<()> = async {
        rig.open_credential().await?;
        assert_navigation_refused(&rig.wd, "Credential", "data-csp-violations").await
    }
    .await;
    rig.finish("navigation_credential", outcome).await
}

// ---- chords and the preview frame's focus (spec 5.6, PD-91) -------------------------------------------------

/// Whether each queue row, in display (DOM) order, is the opened one (`aria-current`).
async fn queue_current(wd: &WebDriver) -> Result<Vec<bool>> {
    let mut out = Vec::new();
    for row in wd.find_all(".queue-item").await? {
        out.push(wd.attribute(&row, "aria-current").await?.as_deref() == Some("true"));
    }
    Ok(out)
}

/// Waits until exactly the row at `index` is the opened one.
async fn wait_current(wd: &WebDriver, index: usize) -> Result<()> {
    wait_for(
        &format!("queue row {index} to be the opened one"),
        WAIT,
        || async {
            let now = queue_current(wd).await?;
            let only = now.iter().filter(|c| **c).count() == 1;
            Ok((only && now.get(index) == Some(&true)).then_some(()))
        },
    )
    .await
}

/// The first of `children` to end within `within`: its index and status, or `None`.
async fn first_exit(
    children: &mut [tokio::process::Child],
    within: Duration,
) -> Result<Option<(usize, std::process::ExitStatus)>> {
    let start = Instant::now();
    loop {
        for (i, child) in children.iter_mut().enumerate() {
            if let Some(status) = child.try_wait()? {
                return Ok(Some((i, status)));
            }
        }
        if start.elapsed() > within {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// PD-91 in a real webview: Ctrl+Shift+Down / Up move the opened row, Ctrl+Shift+Enter decides it;
/// while the focus is inside the sandboxed preview frame none of them reaches the page (keystrokes
/// stay in the frame: a chord needs a click outside it), and after a click outside they work again.
/// The window must report focus for the decision to be live (T19), as in UI-06.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_chords_work_outside_the_preview_frame_and_stay_in_it() -> Result<()> {
    if !opted_in("ui_chords_work_outside_the_preview_frame_and_stay_in_it") {
        return Ok(());
    }
    let world = jira_world().await?;
    jira(&world)?
        .json(
            "/rest/api/2/issue/ABC-78",
            200,
            &issue_json("ABC-78", "Chords second", "second body")?,
        )
        .await;
    let rig = Rig::approvals(world).await?;
    let outcome = chords(&rig).await;
    rig.finish("chords", outcome).await
}

async fn chords(rig: &Rig) -> Result<()> {
    let wd = &rig.wd;
    let ctrl_shift = [keys::CONTROL, keys::SHIFT];
    let mut held = vec![
        hold_read(&rig.world)?,
        rig.world.cli_spawn(&[
            "jira",
            "issue",
            "get",
            "ABC-78",
            "--reason",
            BY_HAND,
            "--timeout",
            HOLD,
        ])?,
    ];
    wait_for("two queue rows", START_WAIT, || async {
        Ok((wd.find_all(".queue-item").await?.len() == 2).then_some(()))
    })
    .await?;
    let opens = wd
        .find_all(".queue-item button[aria-label^='Open ']")
        .await?;
    let Some(open_first) = opens.first() else {
        return Err("no Open button on the first queue row".into());
    };
    wd.click(open_first).await?;
    first_preview_row(wd, WAIT).await?;
    wait_current(wd, 0).await?;
    // Focus on the page, the inert period over: the chords below are live.
    decision_button(wd).await?;

    // Next and previous move the opened row.
    wd.chord(&ctrl_shift, keys::ARROW_DOWN).await?;
    wait_current(wd, 1).await?;
    first_preview_row(wd, WAIT).await?;
    wd.chord(&ctrl_shift, keys::ARROW_UP).await?;
    wait_current(wd, 0).await?;
    first_preview_row(wd, WAIT).await?;

    // Focus inside the preview frame: the same chords do nothing to the page.
    // The frame reloads when the opened row changes (new srcdoc): WebKit answers "no such frame" to
    // a switch made while it does, so the switch is retried until it takes.
    wait_for("the preview frame to be entered", WAIT, || async {
        let Ok(frame) = wd.find("iframe[title='Preview']").await else {
            return Ok(None);
        };
        Ok(wd.switch_to_frame(&frame).await.ok().map(|_| ()))
    })
    .await?;
    let inside = wd.find("body").await?;
    wd.click(&inside).await?;
    // Sent while the driver is switched into the frame: the keys go where the focus is, and a
    // driver that routes actions by browsing context still means the frame.
    wd.chord(&ctrl_shift, keys::ARROW_DOWN).await?;
    wd.chord(&ctrl_shift, keys::ENTER).await?;
    wd.switch_to_parent().await?;
    ensure!(
        first_exit(&mut held, Duration::from_millis(1500))
            .await?
            .is_none(),
        "a request was decided by a chord typed inside the preview frame"
    );
    ensure_eq!(
        queue_current(wd).await?,
        vec![true, false],
        "a chord typed inside the preview frame moved the opened row"
    );

    // A click outside brings the chords back: next, then the decision chord on the neighbour.
    decision_button(wd).await?;
    wd.chord(&ctrl_shift, keys::ARROW_DOWN).await?;
    wait_current(wd, 1).await?;
    first_preview_row(wd, WAIT).await?;
    decision_button(wd).await?;
    wd.chord(&ctrl_shift, keys::ENTER).await?;
    let Some((decided, status)) = first_exit(&mut held, WAIT).await? else {
        return Err("Ctrl+Shift+Enter outside the preview frame decided no request".into());
    };
    ensure_eq!(
        status.code(),
        Some(0),
        "the CLI of the request decided by the chord"
    );
    // Exactly one request was decided.
    let other = 1 - decided;
    let still_held = held
        .get_mut(other)
        .ok_or("no second held request")?
        .try_wait()?
        .is_none();
    ensure!(still_held, "the chord decided both requests");
    Ok(())
}

// ---- P-01: first screen under 1 s ----------------------------------------------------------------------

/// P-01 (webview half): from the click on a row's Open to the first table row inside the preview frame
/// is at most one second, for the three scenarios (`jira.issue.get` default, `jira.search` with 50
/// rows, `jira.issue.create`). The number includes the driver's round trips; it is printed as
/// `P01 <scenario> <ms>` for the evidence table. Thresholds are regression bounds: widen only with a
/// ledger note.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p01_first_screen_under_1s() -> Result<()> {
    if !opted_in("p01_first_screen_under_1s") {
        return Ok(());
    }
    let world = jira_world().await?;
    // A 50-row search page: the fixture set mounted a short one first, so start the mock over.
    let mock = jira(&world)?;
    mock.server().reset().await;
    mock.jira_myself(TEST_USER, TEST_USER_KEY, XAuser::Same)
        .await;
    mock.jira_server_info(fixtures::JIRA_9_12_VERSION).await;
    mock.json("/rest/api/2/issue/ABC-1", 200, fixtures::JIRA_ISSUE)
        .await;
    mock.json(
        "/rest/api/2/search",
        200,
        &fixtures::jira_search_page(0, 50, 50, 50),
    )
    .await;
    mount_create(mock).await;
    let rig = Rig::approvals(world).await?;
    let outcome = p01(&rig).await;
    rig.finish("p01", outcome).await
}

async fn p01(rig: &Rig) -> Result<()> {
    let wd = &rig.wd;
    let scenarios: [(&str, &str, Vec<&str>); 3] = [
        (
            "issue_get_default",
            "jira.issue.get",
            vec!["jira", "issue", "get", "ABC-1"],
        ),
        (
            "search_50_rows",
            "jira.search",
            vec!["jira", "search", "project = ABC"],
        ),
        (
            "issue_create",
            "jira.issue.create",
            vec![
                "jira",
                "issue",
                "create",
                "--project",
                "ABC",
                "--type",
                "Bug",
                "--summary",
                "P-01 create",
            ],
        ),
    ];
    let mut slow = Vec::new();
    // Held children: killed on drop at the end of the flow.
    let mut children = Vec::new();
    // The previous scenario's frame text: the next frame must differ from it, so a frame that is
    // still mounted from the scenario before cannot satisfy the clock.
    let mut previous: Option<String> = None;
    for (name, op_id, args) in scenarios {
        let mut full = args;
        full.extend(["--reason", BY_HAND, "--timeout", HOLD]);
        children.push(rig.world.cli_spawn(&full)?);
        // The row exists (fetched and enriched) before the clock starts.
        let open = wd
            .wait_find_xpath(&row_open_xpath(op_id), START_WAIT)
            .await?;
        let started = Instant::now();
        wd.click(&open).await?;
        let text = first_preview_text(wd, Duration::from_secs(10), previous.as_deref()).await?;
        let took = started.elapsed();
        println!("P01 {name} {} ms", took.as_millis());
        if took > P01_BUDGET {
            slow.push(format!("{name}: {} ms", took.as_millis()));
        }
        previous = Some(text);
    }
    drop(children);
    ensure!(
        slow.is_empty(),
        "P-01 budget {P01_BUDGET:?} exceeded: {slow:?}"
    );
    Ok(())
}

// ---- I-40 (Windows): WM_QUERYENDSESSION runs the shutdown path ----------------------------------------

/// I-40 (Windows): `WM_QUERYENDSESSION` posted to the app's end-session window (class
/// `atlas-duck-end-session`, found by class name among the app's own windows) runs the shutdown path
/// with reason `os_shutdown`: the answer is TRUE only after the path ended, and the audit log's last
/// record is `APP_STOP {os_shutdown}`. No WebDriver: the app is started in the background, as the CLI
/// starts it.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i40_wm_queryendsession_runs_shutdown_path() -> Result<()> {
    use atlas_duck_audit::EventType;

    if !opted_in("i40_wm_queryendsession_runs_shutdown_path") {
        return Ok(());
    }
    let world = jira_world().await?;
    let mut app = world.start_app().await?;
    let pid = app.pid().ok_or("the app has no pid")?;
    let answer = tokio::task::spawn_blocking(move || end_session::query(pid)).await??;
    // FALSE (0) is also what the app answers when its path outlives its own 4 s wait (T29): on a
    // slow runner that is a flake, not a finding, so the world's diagnostics come with it.
    if answer != 1 {
        return Err(format!(
            "WM_QUERYENDSESSION was answered {answer}, not TRUE\n{}",
            world.diagnostics()
        )
        .into());
    }
    // The path ended before the answer; the process follows (or the control file ends it: the path
    // is a single run, a second request does not append a second stop).
    let exited = tokio::task::block_in_place(|| {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(20) {
            if !world.app_running().unwrap_or(true) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        false
    });
    if !exited {
        world.quit_app().await?;
    }
    let _ = tokio::task::block_in_place(|| app.wait_exit());
    let records = world.audit_records()?;
    let (last, payload) = records.last().ok_or("the audit log is empty")?;
    ensure_eq!(
        *last,
        EventType::APP_STOP,
        "the last audit record\n{}",
        world.diagnostics()
    );
    ensure_eq!(payload["reason"], Value::from("os_shutdown"));
    Ok(())
}

#[cfg(windows)]
mod end_session {
    use windows_sys::Win32::Foundation::{HWND, LPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameW, GetWindowThreadProcessId, SMTO_ABORTIFHUNG,
        SendMessageTimeoutW, WM_QUERYENDSESSION,
    };

    /// The class of the app's hidden end-session window (`os_hooks::windows`).
    const CLASS: &str = "atlas-duck-end-session";
    /// The answer may take up to the app's 4 s wait; a hung window ends the call.
    const TIMEOUT_MS: u32 = 15_000;

    struct Search {
        pid: u32,
        found: Option<HWND>,
    }

    unsafe extern "system" fn visit(hwnd: HWND, lparam: LPARAM) -> i32 {
        // SAFETY: `lparam` is the `&mut Search` `find` passed to `EnumWindows` below, alive for the
        // whole (synchronous) enumeration.
        let search = unsafe { &mut *(lparam as *mut Search) };
        let mut owner = 0u32;
        // SAFETY: `owner` is a valid out pointer.
        unsafe { GetWindowThreadProcessId(hwnd, &mut owner) };
        if owner != search.pid {
            return 1;
        }
        let mut buf = [0u16; 64];
        // SAFETY: `buf` holds 64 wide characters, the length passed.
        let n = unsafe { GetClassNameW(hwnd, buf.as_mut_ptr(), 64) };
        let name = usize::try_from(n)
            .ok()
            .and_then(|n| buf.get(..n))
            .map(String::from_utf16_lossy);
        if name.as_deref() == Some(CLASS) {
            search.found = Some(hwnd);
            return 0;
        }
        1
    }

    /// The end-session window of process `pid`: a top-level window of that process with the class
    /// name (never by class name alone: parallel test homes run apps with the same class).
    pub fn find(pid: u32) -> Option<HWND> {
        let mut search = Search { pid, found: None };
        // SAFETY: the callback only touches `search`, which outlives the call.
        unsafe { EnumWindows(Some(visit), &mut search as *mut Search as LPARAM) };
        search.found
    }

    /// Sends `WM_QUERYENDSESSION` to the app's window and returns the answer (1 = TRUE).
    pub fn query(pid: u32) -> Result<usize, String> {
        let hwnd = (0..50)
            .find_map(|_| {
                let w = find(pid);
                if w.is_none() {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                w
            })
            .ok_or_else(|| "no end-session window in the app".to_owned())?;
        let mut answer = 0usize;
        // SAFETY: `answer` is a valid out pointer; the window belongs to another process, the call
        // blocks at most `TIMEOUT_MS`.
        let sent = unsafe {
            SendMessageTimeoutW(
                hwnd,
                WM_QUERYENDSESSION,
                0,
                0,
                SMTO_ABORTIFHUNG,
                TIMEOUT_MS,
                &mut answer,
            )
        };
        if sent == 0 {
            return Err("SendMessageTimeoutW failed or timed out".to_owned());
        }
        Ok(answer)
    }
}

// ---- pure tests --------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_credential_policy_is_read_with_its_placeholder() {
        let policy = shipped_credential_policy().unwrap_or_default();
        assert!(policy.starts_with("default-src 'none'"), "{policy}");
        assert_eq!(frame_src_of(&policy), Some(ISOLATION_PLACEHOLDER));
        assert!(!policy.contains("&lt;"));
    }

    #[test]
    fn isolation_origins_are_the_two_platform_spellings() {
        let id = "0123abcd-4567-89ef-0123-456789abcdef";
        assert!(is_isolation_origin(&format!("isolation-{id}://localhost")));
        assert!(is_isolation_origin(&format!(
            "http://isolation-{id}.localhost"
        )));
        for bad in [
            "isolation://localhost",
            "http://isolation.localhost",
            "'self'",
            ISOLATION_PLACEHOLDER,
            &format!("https://isolation-{id}.localhost"),
            &format!("isolation-{id}://example.com"),
            "isolation-xyz://localhost",
        ] {
            assert!(!is_isolation_origin(bad), "{bad}");
        }
    }

    #[test]
    fn frame_src_is_found_among_the_directives() {
        assert_eq!(
            frame_src_of(
                "default-src 'none'; frame-src isolation-x://localhost; worker-src 'none'"
            ),
            Some("isolation-x://localhost")
        );
        assert_eq!(frame_src_of("default-src 'none'"), None);
    }

    #[test]
    fn the_queue_row_xpath_names_the_op_id() {
        let x = row_open_xpath("jira.search");
        assert!(x.contains("normalize-space()='jira.search'"), "{x}");
        assert!(x.contains("starts-with(@aria-label,'Open ')"), "{x}");
    }

    #[test]
    fn the_issue_fixture_takes_a_new_key_summary_and_description() {
        let text = issue_json("ABC-77", "s", "d").unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        assert_eq!(v["key"], "ABC-77");
        assert_eq!(v["fields"]["summary"], "s");
        assert_eq!(v["fields"]["description"], "d");
    }

    #[test]
    fn every_payload_is_markup_a_url_scheme_or_a_bidi_override() {
        for p in PAYLOADS {
            assert!(
                p.contains('<') || p.starts_with("javascript:") || p.contains('\u{202e}'),
                "{p}"
            );
        }
    }

    fn passes() -> Result<()> {
        let one = std::hint::black_box(1);
        ensure!(one + 1 == 2);
        ensure!(true, "never shown {}", 1);
        let two = one + 1;
        ensure_eq!(two, 2);
        ensure_eq!(two.to_string(), "2", "never shown");
        Ok(())
    }

    fn fails_plain() -> Result<()> {
        let one = std::hint::black_box(1);
        ensure!(one + 1 == 3);
        Ok(())
    }

    fn fails_with_message() -> Result<()> {
        ensure!(false, "the {} failed", "check");
        Ok(())
    }

    fn fails_eq() -> Result<()> {
        ensure_eq!(1, 2, "numbers of {}", "a");
        Ok(())
    }

    #[test]
    fn the_ensure_macros_return_errors_and_never_panic() {
        assert!(passes().is_ok());
        let plain = fails_plain().unwrap_err().to_string();
        assert!(plain.contains("one + 1 == 3"), "{plain}");
        assert_eq!(
            fails_with_message().unwrap_err().to_string(),
            "the check failed"
        );
        let eq = fails_eq().unwrap_err().to_string();
        assert!(
            eq.contains("numbers of a") && eq.contains("left: 1") && eq.contains("right: 2"),
            "{eq}"
        );
    }

    /// A failed check must reach `Rig::finish` (screenshot, diagnostics, quit): the flows' code has
    /// no panicking assertion.
    #[test]
    fn the_flows_use_no_panicking_assertion() {
        let source = include_str!("flows.rs");
        let code = source.split("#[cfg(test)]").next().unwrap_or_default();
        for needle in [["assert", "!("].concat(), ["assert", "_eq!("].concat()] {
            // The two macro doc comments name them; code lines do not.
            for line in code.lines().filter(|l| !l.trim_start().starts_with("//")) {
                assert!(!line.contains(&needle), "{line}");
            }
        }
    }

    #[test]
    fn the_app_origin_and_foreign_url_differ() {
        assert!(!FOREIGN_URL.starts_with(APP_ORIGIN));
        assert!(APP_ORIGIN.ends_with("localhost"));
    }

    #[test]
    fn window_titles_are_the_pages() {
        assert_eq!(window_title("Approvals"), "atlas-duck: Approvals");
    }

    /// Nothing of the flows runs without the opt-in: the guard is the first statement of every one.
    #[test]
    fn every_flow_starts_with_the_opt_in_guard() {
        let source = include_str!("flows.rs");
        let flows: Vec<&str> = source
            .match_indices("async fn ")
            .map(|(i, _)| &source[i..])
            .filter(|rest| {
                // A flow is the `async fn` directly under a `#[tokio::test..]` attribute, whatever
                // its arguments.
                let before = &source[..source.len() - rest.len()];
                before
                    .trim_end()
                    .lines()
                    .next_back()
                    .is_some_and(|l| l.trim_start().starts_with("#[tokio::test"))
            })
            .collect();
        assert!(flows.len() >= 12, "{} flows found", flows.len());
        for rest in flows {
            let open = rest.find('{').unwrap_or(0);
            let body = &rest[open + 1..];
            let guard = body.find("opted_in(").unwrap_or(usize::MAX);
            let world = body.find("World::new").unwrap_or(usize::MAX);
            let jira_world_call = body.find("jira_world().await").unwrap_or(usize::MAX);
            assert!(
                guard < world.min(jira_world_call),
                "a flow builds a world before the opt-in guard: {}",
                rest.lines().next().unwrap_or_default()
            );
        }
    }

    #[test]
    fn the_flow_files_never_set_the_opt_in() {
        let ours = [include_str!("flows.rs"), include_str!("webdriver.rs")];
        let needles = [
            ["set", "_var("].concat(),
            [".env(", "ENV_OPT_IN"].concat(),
            ["\"ATLAS_DUCK_CLI", "_FLOWS\""].concat(),
        ];
        for s in ours {
            for needle in &needles {
                assert!(!s.contains(needle.as_str()), "{needle}");
            }
        }
    }
}

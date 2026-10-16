#!/usr/bin/env python3
"""WebDriver steps for the packaged-app CI scripts (M6 plan Task 33): a small W3C client over the
standard library, talking to `tauri-driver`, and the two flows the shell scripts need.

  e2e-drive.py wizard --app <atlas-duck-app> --driver <tauri-driver> [--cli-install]
      Completes the first-run wizard through the real windows: default data folder, the recovery
      passphrase twice in the credential window, the recovery note step, "Skip for now" for the
      instances, "Install CLI to PATH" when --cli-install, "Finish setup". Ends the session.

  e2e-drive.py fedora --app <atlas-duck-app> --cli <atlas-duck> --driver <tauri-driver> --home <test home>
      The CI-03 no-tray-host run on a store the wizard has made: cold no-argument start opens
      Approvals; `doctor` says tray_host missing; a forwarded no-argument launch and a forwarded
      `--background` launch (each a second process, exit 0) are logged as forwarded_launch and open
      no new window; Settings opens from the Approvals header; header Quit ends the process; the
      next start comes up clean (no quit_wait_expired / quit_core_lost in the diag log).

The app under test is the debug `scripted-approver` build: a release build scrubs the WebDriver
variables from its environment (spec §2.5, S-04) and cannot be driven. It needs
ATLAS_DUCK_TEST_HOME and ATLAS_DUCK_TEST_KEYSTORE in the environment of this script (inherited by
tauri-driver and the app it starts). No script is ever executed in a webview: only element, title and
window commands are used, as in app/src-tauri/tests/e2e/webdriver.rs.

Exit 0 on success, 1 with a message on a failed step, 2 on a usage error.
"""
import argparse
import glob
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ELEMENT_KEY = "element-6066-11e4-a52e-4f735466cecf"
WAIT = 30
START_WAIT = 90
# Seconds a forwarded launch gets to open (or not open) a window before the windows are counted.
SETTLE = 4
PASSPHRASE = "ci-recovery-passphrase-0123456789"
TITLE_PREFIX = "atlas-duck: "


class Failed(Exception):
    pass


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Driver:
    """A tauri-driver process on its own ports, killed on close."""

    def __init__(self, exe, log):
        self.port = free_port()
        native = free_port()
        env = dict(os.environ)
        env["ATLAS_DUCK_E2E_ALLOW_DRIVER"] = "1"
        self.log = open(log, "ab")
        self.proc = subprocess.Popen(
            [exe, "--port", str(self.port), "--native-port", str(native)],
            stdin=subprocess.DEVNULL,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            env=env,
        )
        self.base = "http://127.0.0.1:%d" % self.port
        deadline = time.time() + WAIT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise Failed("tauri-driver ended at start (%s), log %s" % (self.proc.returncode, log))
            try:
                with opener.open(self.base + "/status", timeout=2) as r:
                    if r.status == 200:
                        return
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(0.2)
        raise Failed("tauri-driver answered no /status within %d s, log %s" % (WAIT, log))

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.log.close()

    def tail(self, lines=60):
        """The end of the driver's log (tauri-driver and the native driver it starts write there)."""
        self.log.flush()
        try:
            with open(self.log.name, encoding="utf-8", errors="replace") as f:
                return "".join(f.readlines()[-lines:])
        except OSError as e:
            return "(the driver log is unreadable: %s)" % e


def run_text(cmd, timeout=20):
    """`cmd`'s output for a failure report, or why there is none (never raises)."""
    try:
        r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip() or "(no output, exit %s)" % r.returncode
    except (OSError, subprocess.SubprocessError) as e:
        return "(%s: %s)" % (cmd[0], e)


def new_session(drv, app, args=()):
    """A session for `app`. On "session not created" the failure says what the driver and the
    system showed: the driver log, the processes still running, the native driver's version, the
    app's diag logs, and whether a session WITHOUT `browserName` can be created. WebKitWebDriver
    answers "Failed to match capabilities" when the browser name the app's automation session
    reports is not the requested one (wry reports "wry" only once its first webview is
    registered), so that probe tells a name mismatch from a launch or connection failure."""
    try:
        return Session(drv.base, app, args)
    except Failed as e:
        if "session not created" not in str(e).lower():
            raise
        report = [str(e)]
        report.append("--- processes\n" + run_text(["pgrep", "-a", "-f", "atlas-duck|WebKit|tauri-driver"]))
        report.append("--- WebKitWebDriver --version\n" + run_text(["WebKitWebDriver", "--version"]))
        # The probe starts the app again: end what the failed attempt left running, so the probe is
        # not forwarded to it (single instance).
        run_text(["pkill", "-x", "atlas-duck-app"])
        for _ in range(20):
            if subprocess.run(["pgrep", "-x", "atlas-duck-app"], capture_output=True).returncode != 0:
                break
            time.sleep(0.5)
        try:
            probe = Session(drv.base, app, args, browser_name=None)
            probe.quit()
            report.append("--- probe: a session WITHOUT browserName was created: the app's automation "
                          "session reports another browser name than \"wry\"")
        except Failed as p:
            report.append("--- probe: a session without browserName failed too: %s" % p)
        report.append("--- driver log (end)\n" + drv.tail())
        home = os.environ.get("ATLAS_DUCK_TEST_HOME")
        if home:
            for path in sorted(glob.glob(os.path.join(home, "**", "logs", "diag.log"), recursive=True)):
                with open(path, encoding="utf-8", errors="replace") as f:
                    report.append("--- %s\n%s" % (path, f.read()[-4000:]))
        raise Failed("\n".join(report))


opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Session:
    def __init__(self, base, app, args=(), browser_name="wry"):
        # The same body as the Rust client (app/src-tauri/tests/e2e/webdriver.rs session_request),
        # which creates sessions on the same tauri-driver and WebKitWebDriver. The native driver
        # answers "Failed to match capabilities" without saying which one, so the path is checked
        # first (an absolute, executable file) and the body is part of the failure text.
        # `browser_name=None` is new_session's diagnostic probe only.
        if not os.path.isabs(app) or not os.path.isfile(app) or not os.access(app, os.X_OK):
            raise Failed("the app under test is not an absolute path to an executable file: %s" % app)
        match = {"tauri:options": {"application": app, "args": list(args)}}
        if browser_name is not None:
            match["browserName"] = browser_name
        body = {"capabilities": {"alwaysMatch": match}}
        try:
            value = self._send("POST", base + "/session", body, timeout=120)
        except Failed as e:
            raise Failed("%s (new session body: %s)" % (e, json.dumps(body)))
        self.base = base
        self.id = value["sessionId"]

    @staticmethod
    def _send(method, url, body=None, timeout=60):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("content-type", "application/json; charset=utf-8")
        try:
            with opener.open(req, timeout=timeout) as r:
                text = r.read().decode()
        except urllib.error.HTTPError as e:
            return Session._http_error(e)
        except (urllib.error.URLError, OSError) as e:
            raise Failed("webdriver connection: %s" % e)
        doc = json.loads(text) if text.strip() else {"value": None}
        return doc["value"]

    @staticmethod
    def _http_error(e):
        text = e.read().decode(errors="replace")
        try:
            v = json.loads(text)["value"]
            detail = "webdriver %s: %s" % (v.get("error"), v.get("message"))
        except (ValueError, KeyError, TypeError, AttributeError):
            detail = "webdriver HTTP %s: %s" % (e.code, text[:300])
        raise Failed(detail)

    def call(self, method, path, body=None):
        return self._send(method, "%s/session/%s%s" % (self.base, self.id, path), body)

    # elements
    def find_all(self, using, value):
        found = self.call("POST", "/elements", {"using": using, "value": value})
        return [e[ELEMENT_KEY] for e in found]

    def css(self, selector):
        return self.find_all("css selector", selector)

    def xpath(self, expr):
        return self.find_all("xpath", expr)

    def wait(self, what, probe, within=WAIT):
        deadline = time.time() + within
        while True:
            v = probe()
            if v:
                return v
            if time.time() > deadline:
                raise Failed("timed out after %d s waiting for %s" % (within, what))
            time.sleep(0.2)

    def wait_xpath(self, expr, within=WAIT):
        return self.wait(expr, lambda: (self.xpath(expr) or [None])[0], within)

    def wait_css(self, selector, within=WAIT):
        return self.wait(selector, lambda: (self.css(selector) or [None])[0], within)

    def click(self, e):
        self.call("POST", "/element/%s/click" % e, {})

    def send_keys(self, e, text):
        self.call("POST", "/element/%s/value" % e, {"text": text})

    def text(self, e):
        return self.call("GET", "/element/%s/text" % e) or ""

    def enabled(self, e):
        return bool(self.call("GET", "/element/%s/enabled" % e))

    def button(self, label, within=WAIT):
        return self.wait_xpath("//button[normalize-space()='%s']" % label, within)

    def click_button(self, label, within=WAIT):
        b = self.button(label, within)
        self.wait("the %r button to be enabled" % label, lambda: self.enabled(b), within)
        self.click(b)

    # windows
    def handles(self):
        return self.call("GET", "/window/handles")

    def switch(self, handle):
        self.call("POST", "/window", {"handle": handle})

    def title(self):
        return self.call("GET", "/title") or ""

    def switch_to_title(self, name, within=WAIT):
        want = TITLE_PREFIX + name

        def probe():
            for h in self.handles():
                try:
                    self.switch(h)
                except Failed:
                    continue  # a window that closed between the listing and the switch
                try:
                    if self.title() == want:
                        return h
                except Failed:
                    continue
            return None

        return self.wait("a window titled %r" % want, probe, within)

    def quit(self):
        try:
            self.call("DELETE", "")
        except Failed:
            pass


# ---- wizard -----------------------------------------------------------------------------------------------


def set_passphrase(s):
    """The credential window of the passphrase step: the passphrase twice, then Set passphrase."""
    s.switch_to_title("Credential", START_WAIT)
    fields = s.wait("the two passphrase fields", lambda: len(s.css("form.entry input")) >= 2 and s.css("form.entry input"))
    s.send_keys(fields[0], PASSPHRASE)
    s.send_keys(fields[1], PASSPHRASE)
    submit = s.wait_css("form.entry button.primary")
    s.wait("Set passphrase to be enabled", lambda: s.enabled(submit))
    s.click(submit)
    s.wait_css("div.result.ok", START_WAIT)


def wizard(args):
    drv = Driver(args.driver, args.driver_log)
    s = None
    try:
        s = new_session(drv, args.app)
        setup = s.switch_to_title("Setup", START_WAIT)
        passphrase_done = False
        cli_done = not args.cli_install
        deadline = time.time() + 600
        while time.time() < deadline:
            # The Setup window is destroyed and rebuilt after the data folder step: find it by title.
            try:
                s.switch_to_title("Setup", 10)
            except Failed:
                # Setup is gone: either the wizard ended and Approvals opened, or the window is
                # being rebuilt (the data folder step destroys it); only the first is the end.
                try:
                    s.switch_to_title("Approvals", 3)
                except Failed:
                    continue
                print("wizard: finished, the Approvals window is open")
                return
            try:
                if s.xpath("//button[normalize-space()='Use the default folder']"):
                    s.click_button("Use the default folder")
                elif s.xpath("//button[normalize-space()='Continue with this log']"):
                    s.click_button("Continue with this log")
                elif s.xpath("//button[normalize-space()='Begin']") and not passphrase_done:
                    s.click_button("Begin")
                    set_passphrase(s)
                    passphrase_done = True
                    print("wizard: recovery passphrase set")
                elif s.xpath("//button[normalize-space()='Skip for now']"):
                    s.click_button("Skip for now")
                elif s.xpath("//button[normalize-space()='Install CLI to PATH']") and not cli_done:
                    s.click_button("Install CLI to PATH")
                    s.wait_xpath("//section//p[@role='status']", WAIT)
                    cli_done = True
                    print("wizard: Install CLI to PATH pressed")
                elif s.xpath("//button[normalize-space()='Finish setup']"):
                    s.click_button("Finish setup")
                elif s.xpath("//section[@aria-label='Command line']//button[normalize-space()='Continue']"):
                    s.click_button("Continue")
                elif s.xpath("//section[@aria-label='Recovery note']//button[normalize-space()='Continue']"):
                    s.click_button("Continue")
                elif s.xpath("//section[@aria-label='Setup cannot continue']"):
                    raise Failed("the wizard stopped: " + s.text(s.css("body")[0]))
            except Failed as e:
                # The window went away between the lookup and the command (a step rebuilds it).
                if "no such window" in str(e).lower() or "stale element" in str(e).lower() or "no such element" in str(e).lower():
                    time.sleep(1)
                    continue
                raise
            time.sleep(1)
        raise Failed("the wizard did not finish within 600 s")
    finally:
        if s is not None:
            s.quit()
        drv.close()


# ---- the Fedora no-tray-host run ---------------------------------------------------------------------------


def diag_log(home):
    found = sorted(glob.glob(os.path.join(home, "**", "logs", "diag.log"), recursive=True))
    return found[0] if found else None


def diag_text(home):
    path = diag_log(home)
    if path is None:
        return ""
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def count(pattern, text):
    return len(re.findall(pattern, text))


def run_second(exe, extra, home):
    """A second process of the app (what the .desktop launcher or the CLI does): it forwards to the
    running instance and exits 0."""
    r = subprocess.run([exe] + extra, stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
    if r.returncode != 0:
        raise Failed("the forwarded %r launch exited %s: %s" % (extra, r.returncode, r.stderr[-300:]))


def app_running():
    return subprocess.run(["pgrep", "-x", "atlas-duck-app"], capture_output=True).returncode == 0


def fedora(args):
    home = args.home
    drv = Driver(args.driver, args.driver_log)
    s = None
    try:
        s = new_session(drv, args.app)
        approvals = s.switch_to_title("Approvals", START_WAIT)
        print("no-tray-host: a cold no-argument start opened the Approvals window")

        r = subprocess.run([args.cli, "doctor", "--timeout", "60"], capture_output=True, text=True, timeout=120)
        if not re.search(r'"tray_host"\s*:\s*"missing"', r.stdout):
            raise Failed("doctor does not report tray_host missing (exit %s): %s" % (r.returncode, r.stdout[:600]))
        print("no-tray-host: doctor reports tray_host missing")
        if not re.search(r"tray_host=missing", diag_text(home)):
            raise Failed("the diag log has no tray_host=missing")

        windows = len(s.handles())
        forwarded = count(r"forwarded_launch", diag_text(home))
        for extra, what in (([], "no-argument"), (["--background"], "--background")):
            run_second(args.app, extra, home)
            s.wait(
                "a forwarded_launch line for the %s launch" % what,
                lambda: count(r"forwarded_launch", diag_text(home)) > forwarded,
                WAIT,
            )
            forwarded += 1
            # tray.rs logs forwarded_launch before it acts on the launch: let a window that a
            # mistaken --background open would have opened appear before it is counted.
            time.sleep(SETTLE)
            if len(s.handles()) != windows:
                raise Failed("the forwarded %s launch changed the window count (%d -> %d)" % (what, windows, len(s.handles())))
            s.switch(approvals)
            if s.title() != TITLE_PREFIX + "Approvals":
                raise Failed("the Approvals window went away after the forwarded %s launch" % what)
            print("no-tray-host: the forwarded %s launch was logged and left the windows alone" % what)

        header = "//header//button[normalize-space()='%s']"
        s.click(s.wait_xpath(header % "Settings"))
        s.switch_to_title("Settings", WAIT)
        s.wait_xpath("//h1")
        print("no-tray-host: Settings opened from the Approvals header")
        s.switch(approvals)

        # Only the lines written from here on are the Quit's: the log is append-only and holds the
        # whole run (and the wizard's).
        quit_offset = len(diag_text(home))
        try:
            s.click(s.wait_xpath(header % "Quit"))
        except Failed as e:
            print("no-tray-host: the Quit click ended the session (%s)" % e)
        s.wait("the app to exit after header Quit", lambda: not app_running(), WAIT)
        print("no-tray-host: header Quit ended the process")
    finally:
        if s is not None:
            s.quit()
        drv.close()

    # The process is gone. Its orderly shutdown logged `app_stop reason=quit` (serve.rs, after the core
    # appended APP_STOP; absent after a crash or a SIGKILL), and only in lines written after the click.
    after = diag_text(home)[quit_offset:]
    if not re.search(r"event=app_stop reason=quit\b", after):
        print(after)
        raise Failed("no app_stop reason=quit line in the diag log after header Quit")
    for bad in ("quit_wait_expired", "quit_core_lost"):
        if bad in after:
            print(after)
            raise Failed("the diag log shows %s after header Quit" % bad)
    if app_running():
        raise Failed("the app is running again after header Quit")
    print("no-tray-host: header Quit logged app_stop reason=quit and the process exited")

    # The next start comes up clean (the single-instance lock was released).
    drv = Driver(args.driver, args.driver_log)
    s = None
    try:
        s = new_session(drv, args.app)
        s.switch_to_title("Approvals", START_WAIT)
        print("no-tray-host: the next start came up clean")
    finally:
        if s is not None:
            s.quit()
        drv.close()

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", choices=["wizard", "fedora"])
    p.add_argument("--app", required=True)
    p.add_argument("--driver", required=True, help="the tauri-driver executable")
    p.add_argument("--driver-log", default=os.path.join(os.environ.get("TMPDIR", "."), "tauri-driver.log"))
    p.add_argument("--cli", help="the atlas-duck CLI (fedora)")
    p.add_argument("--home", help="ATLAS_DUCK_TEST_HOME (fedora): where the diag log is found")
    p.add_argument("--cli-install", action="store_true", help="press Install CLI to PATH on the wizard's CLI step")
    args = p.parse_args()
    if args.command == "fedora" and not (args.cli and args.home):
        p.error("fedora needs --cli and --home")
    try:
        wizard(args) if args.command == "wizard" else fedora(args)
    except Failed as e:
        print("FAIL: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

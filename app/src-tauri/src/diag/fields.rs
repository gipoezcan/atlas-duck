//! Metadata-only event formatter (§7.7 Diagnostic log, §1.4 SC4).
//!
//! Every event becomes one line:
//! `<RFC 3339 UTC timestamp> <LEVEL> <target> <file>:<line> [<allowed>=<value> ...] dropped_fields=<n>`.
//! Only fields whose *name* is on the allowlist are written, and only for
//! events whose target starts with `ALLOWED_TARGET_PREFIX`. The `message`
//! field and every other field are counted, never formatted, and never
//! written. Span fields are never written. Events from any other target
//! (third-party crates) are dropped whole.

use std::fmt::{self, Write as _};
use std::io::Write as _;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::Registry;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::Context;

/// §7.7 metadata: op id, request id, instance alias, HTTP method, path
/// template, status code, duration, error class; §3.3: connection id,
/// peer pid/exe, reason. `event` names the log line itself.
pub const ALLOWED_FIELDS: &[&str] = &[
    "event",
    "op_id",
    "request_id",
    "instance_alias",
    "http_method",
    "path_template",
    "status_code",
    "duration_ms",
    "error_class",
    "connection_id",
    "peer_pid",
    "peer_exe",
    "reason",
];

/// Target rule, the second half of the allowlist: only events whose
/// `meta.target()` starts with this prefix are written. Every workspace crate's
/// module path does (`atlas_duck_app_lib::...`, `atlas_duck_ipc::...`); a
/// dependency's events (tauri, zbus, later reqwest/hyper) do not, and some of
/// their fields carry free-form text under allowlisted names such as `reason`
/// or `peer_exe`. A field name alone therefore proves nothing about its value:
/// field names are trusted only for events that atlas-duck code emitted.
pub const ALLOWED_TARGET_PREFIX: &str = "atlas_duck";

/// Names added by later tasks through `Diag::extend_allowed_fields`.
static EXTRA_FIELDS: RwLock<Vec<&'static str>> = RwLock::new(Vec::new());

pub(crate) fn extend_allowed(fields: &'static [&'static str]) {
    let mut extra = EXTRA_FIELDS.write().unwrap_or_else(|e| e.into_inner());
    for f in fields {
        if !ALLOWED_FIELDS.contains(f) && !extra.contains(f) {
            extra.push(f);
        }
    }
}

pub(crate) fn is_allowed(name: &str) -> bool {
    ALLOWED_FIELDS.contains(&name)
        || EXTRA_FIELDS
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&name)
}

/// The allowlist layer writing through `writer`. Used by `Diag` and,
/// scoped with `tracing::subscriber::with_default`, by tests.
pub fn allowlist_layer<W>(writer: W) -> impl Layer<Registry>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    AllowlistLayer { writer }
}

pub(crate) struct AllowlistLayer<W> {
    pub(crate) writer: W,
}

impl<S, W> Layer<S> for AllowlistLayer<W>
where
    S: Subscriber,
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // Foreign targets are dropped before any field is visited.
        if !event.metadata().target().starts_with(ALLOWED_TARGET_PREFIX) {
            return;
        }
        let line = format_event(event);
        let mut w = self.writer.make_writer_for(event.metadata());
        // A failed log write is dropped: logging must never fail the caller.
        let _ = w.write_all(line.as_bytes());
    }
}

pub(crate) fn format_event(event: &Event<'_>) -> String {
    let meta = event.metadata();
    let location = match (meta.file(), meta.line()) {
        (Some(f), Some(l)) => format!("{f}:{l}"),
        (Some(f), None) => f.to_owned(),
        _ => "unknown".to_owned(),
    };
    let mut fields = String::new();
    let mut visitor = AllowVisitor {
        out: &mut fields,
        dropped: 0,
    };
    event.record(&mut visitor);
    let dropped = visitor.dropped;
    let _ = write!(fields, "dropped_fields={dropped}");
    format_line(meta.level().as_str(), meta.target(), &location, &fields)
}

/// One complete log line, newline-terminated. `fields` is already formatted.
pub(crate) fn format_line(level: &str, target: &str, location: &str, fields: &str) -> String {
    let mut s = String::with_capacity(64 + target.len() + location.len() + fields.len());
    push_timestamp(&mut s, SystemTime::now());
    s.push(' ');
    s.push_str(level);
    s.push(' ');
    push_bare(&mut s, target);
    s.push(' ');
    push_bare(&mut s, location);
    if !fields.is_empty() {
        s.push(' ');
        s.push_str(fields);
    }
    s.push('\n');
    s
}

struct AllowVisitor<'a> {
    out: &'a mut String,
    dropped: u32,
}

impl AllowVisitor<'_> {
    /// Returns true when the field may be written; counts it otherwise.
    fn admit(&mut self, field: &Field) -> bool {
        if is_allowed(field.name()) {
            self.out.push_str(field.name());
            self.out.push('=');
            true
        } else {
            self.dropped += 1;
            false
        }
    }

    fn finish(&mut self) {
        self.out.push(' ');
    }
}

impl Visit for AllowVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // The value of a dropped field is never formatted.
        if self.admit(field) {
            let text = format!("{value:?}");
            push_value(self.out, &text);
            self.finish();
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if self.admit(field) {
            push_value(self.out, value);
            self.finish();
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if self.admit(field) {
            let _ = write!(self.out, "{value}");
            self.finish();
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if self.admit(field) {
            let _ = write!(self.out, "{value}");
            self.finish();
        }
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        if self.admit(field) {
            let _ = write!(self.out, "{value}");
            self.finish();
        }
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        if self.admit(field) {
            let _ = write!(self.out, "{value}");
            self.finish();
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        if self.admit(field) {
            let _ = write!(self.out, "{value}");
            self.finish();
        }
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        if self.admit(field) {
            let _ = write!(self.out, "{value}");
            self.finish();
        }
    }
}

fn is_plain(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/' | '\\' | '+' | '@')
}

/// Writes `value` bare when it is a plain token, else as a Rust-escaped
/// quoted string, so a value can never start a new line or forge a field.
pub(crate) fn push_value(out: &mut String, value: &str) {
    if !value.is_empty() && value.chars().all(is_plain) {
        out.push_str(value);
    } else {
        let _ = write!(out, "{value:?}");
    }
}

/// Writes a column (target, location, thread name) with every whitespace
/// or control character replaced by `_`.
pub(crate) fn push_bare(out: &mut String, value: &str) {
    if value.is_empty() {
        out.push('_');
        return;
    }
    for c in value.chars() {
        out.push(if c.is_whitespace() || c.is_control() {
            '_'
        } else {
            c
        });
    }
}

/// `YYYY-MM-DDTHH:MM:SS.ffffffZ` (UTC). Before 1970 prints the epoch.
pub(crate) fn push_timestamp(out: &mut String, t: SystemTime) {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (y, m, day) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    let _ = write!(
        out,
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{:06}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_micros()
    );
}

/// Days since 1970-01-01 -> (year, month, day), proleptic Gregorian
/// (H. Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Capture {
            self.clone()
        }
    }

    fn capture(f: impl FnOnce()) -> String {
        let cap = Capture::default();
        let subscriber = Registry::default().with(allowlist_layer(cap.clone()));
        tracing::subscriber::with_default(subscriber, f);
        let bytes = cap.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    const SENTINELS: [&str; 3] = ["SENTINEL-JQL-7f3a", "SENTINEL-T", "SENTINEL-MSG"];

    #[test]
    fn non_allowlisted_fields_and_message_are_dropped_at_every_level() {
        let out = capture(|| {
            tracing::trace!(
                jql = "SENTINEL-JQL-7f3a",
                summary = "SENTINEL-T",
                op_id = "jira.search",
                "{}",
                "SENTINEL-MSG"
            );
            tracing::debug!(
                jql = "SENTINEL-JQL-7f3a",
                summary = "SENTINEL-T",
                op_id = "jira.search",
                "{}",
                "SENTINEL-MSG"
            );
            tracing::info!(
                jql = "SENTINEL-JQL-7f3a",
                summary = "SENTINEL-T",
                op_id = "jira.search",
                "{}",
                "SENTINEL-MSG"
            );
            tracing::warn!(
                jql = "SENTINEL-JQL-7f3a",
                summary = "SENTINEL-T",
                op_id = "jira.search",
                "{}",
                "SENTINEL-MSG"
            );
            tracing::error!(
                jql = "SENTINEL-JQL-7f3a",
                summary = "SENTINEL-T",
                op_id = "jira.search",
                "{}",
                "SENTINEL-MSG"
            );
        });
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 5, "{out}");
        for (line, level) in lines
            .iter()
            .zip(["TRACE", "DEBUG", "INFO", "WARN", "ERROR"])
        {
            assert!(line.contains(&format!(" {level} ")), "{line}");
            assert!(line.contains("op_id=jira.search"), "{line}");
            assert!(line.contains("dropped_fields=3"), "{line}");
            assert!(line.contains(&format!("{}:", file!())), "{line}");
            assert!(line.contains(module_path!()), "{line}");
        }
        for s in SENTINELS {
            assert!(!out.contains(s), "sentinel {s} leaked: {out}");
        }

        // The same bytes through the SC4 grep harness.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("diag.log"), &out).unwrap();
        assert!(
            super::super::scan_logs_for(dir.path(), &SENTINELS)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn span_fields_are_never_written() {
        let out = capture(|| {
            let span = tracing::info_span!("req", jql = "SENTINEL-JQL-7f3a", op_id = "jira.search");
            let _g = span.enter();
            tracing::info!(status_code = 200u16);
        });
        assert!(out.contains("status_code=200"), "{out}");
        assert!(!out.contains("SENTINEL"), "{out}");
    }

    #[test]
    fn events_from_foreign_targets_are_dropped_whole() {
        let out = capture(|| {
            // Allowlisted field names, but not from an atlas_duck target.
            tracing::info!(target: "zbus", reason = "SENTINEL-ZBUS", peer_exe = "SENTINEL-EXE");
            tracing::error!(target: "tauri::app", event = "SENTINEL-TAURI", "SENTINEL-MSG");
            // These two targets pass: this module and another workspace crate.
            tracing::info!(op_id = "own.target");
            tracing::info!(target: "atlas_duck_ipc::paths", op_id = "other.crate");
        });
        assert!(!out.contains("SENTINEL"), "foreign event leaked: {out}");
        assert!(out.contains("op_id=own.target"), "{out}");
        assert!(out.contains("op_id=other.crate"), "{out}");
        assert_eq!(
            out.lines().count(),
            2,
            "only the two atlas_duck events: {out}"
        );

        let only_foreign = capture(|| {
            tracing::info!(target: "zbus", reason = "SENTINEL-ZBUS");
        });
        assert_eq!(only_foreign, "", "nothing at all is written");
    }

    #[test]
    fn allowed_values_cannot_break_the_line() {
        let out = capture(|| {
            tracing::info!(reason = "a\nb c=d", duration_ms = 12u64, error_class = ?Some("timeout"));
        });
        assert_eq!(out.lines().count(), 1, "{out}");
        assert!(out.contains(r#"reason="a\nb c=d""#), "{out}");
        assert!(out.contains("duration_ms=12"), "{out}");
        assert!(out.contains(r#"error_class="Some(\"timeout\")""#), "{out}");
        assert!(out.contains("dropped_fields=0"), "{out}");
    }

    #[test]
    fn extended_fields_are_written() {
        static EXTRA: &[&str] = &["t08_test_field"];
        let before = capture(|| tracing::info!(t08_test_field = "x1"));
        assert!(!before.contains("x1"), "{before}");
        extend_allowed(EXTRA);
        let after = capture(|| tracing::info!(t08_test_field = "x1"));
        assert!(after.contains("t08_test_field=x1"), "{after}");
    }

    #[test]
    fn allowlist_matches_plan() {
        assert_eq!(
            ALLOWED_FIELDS,
            [
                "event",
                "op_id",
                "request_id",
                "instance_alias",
                "http_method",
                "path_template",
                "status_code",
                "duration_ms",
                "error_class",
                "connection_id",
                "peer_pid",
                "peer_exe",
                "reason"
            ]
        );
    }

    #[test]
    fn timestamp_is_rfc3339_utc() {
        let mut s = String::new();
        push_timestamp(&mut s, UNIX_EPOCH);
        assert_eq!(s, "1970-01-01T00:00:00.000000Z");
        s.clear();
        push_timestamp(&mut s, UNIX_EPOCH + Duration::from_secs(951_782_400));
        assert_eq!(s, "2000-02-29T00:00:00.000000Z");
        s.clear();
        push_timestamp(
            &mut s,
            UNIX_EPOCH + Duration::from_micros(1_000_000_000_123_456),
        );
        assert_eq!(s, "2001-09-09T01:46:40.123456Z");
    }
}

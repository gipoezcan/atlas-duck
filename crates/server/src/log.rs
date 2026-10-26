//! JSON logging to stdout (SM-8.3): one JSON object per line, `{"ts", "level", "event", ...}`.
//! Callers log fixed event names with `event = "..."` and plain fields; secrets never reach a
//! field (they are `secrecy` types or [`Redacted`]), and the formatter adds no span data.

use std::fmt;
use std::io::Write;

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// A value that prints as `[redacted]` in `Debug` and `Display`, whatever it holds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Redacted<T>(pub T);

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Collects an event's fields into a JSON object (`message` included as a plain field).
struct Fields(Map<String, Value>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0
            .insert(field.name().to_owned(), Value::from(format!("{value:?}")));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }
}

/// The SM-8.3 line: `ts` (RFC 3339 UTC, ms), `level`, then the event's own fields.
pub struct JsonLine;

/// One log line for `level` and `fields` (shared by the formatter and the pre-subscriber lines
/// `cli` prints, such as `config_error`).
pub fn line(level: &str, fields: Map<String, Value>) -> String {
    let mut m = Map::new();
    m.insert(
        "ts".into(),
        Value::from(
            chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
        ),
    );
    m.insert("level".into(), Value::from(level));
    for (k, v) in fields {
        m.entry(k).or_insert(v);
    }
    Value::Object(m).to_string()
}

impl<S, N> FormatEvent<S, N> for JsonLine
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut fields = Fields(Map::new());
        event.record(&mut fields);
        let level = event.metadata().level().as_str().to_ascii_lowercase();
        writeln!(writer, "{}", line(&level, fields.0))
    }
}

/// Installs the global subscriber: JSON lines on stdout filtered by `rust_log` (`info` when it
/// does not parse). A second call is a no-op.
pub fn init(rust_log: &str) {
    let filter: Targets = rust_log
        .parse()
        .unwrap_or_else(|_| Targets::new().with_default(LevelFilter::INFO));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(std::io::stdout)
        .event_format(JsonLine)
        .finish();
    use tracing_subscriber::layer::SubscriberExt;
    let _ = tracing::subscriber::set_global_default(subscriber.with(filter));
}

/// Writes one line to stderr directly (before the subscriber exists); a failed write is ignored.
pub fn stderr_line(level: &str, fields: Map<String, Value>) {
    let _ = writeln!(std::io::stderr(), "{}", line(level, fields));
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde_json::json;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    #[test]
    fn redacted_never_prints_its_content() {
        let r = Redacted("hunter2-canary");
        assert_eq!(format!("{r:?} {r}"), "[redacted] [redacted]");
        assert_eq!(
            format!("{:?}", Some(Redacted(vec![1u8, 2]))),
            "Some([redacted])"
        );
    }

    #[test]
    fn json_line_shape() {
        let buf = Buf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .event_format(JsonLine)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(event = "test_directory_active", users = 3u64, secret = ?Redacted("canary-pw"));
        });
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        let v: Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(v["level"], "warn");
        assert_eq!(v["event"], "test_directory_active");
        assert_eq!(v["users"], 3);
        assert_eq!(v["secret"], "[redacted]");
        assert!(v["ts"].as_str().unwrap().ends_with('Z'));
        assert!(!text.contains("canary-pw"));
    }

    #[test]
    fn line_keeps_ts_and_level_first_and_unshadowed() {
        let mut f = Map::new();
        f.insert("level".into(), json!("spoofed"));
        f.insert("event".into(), json!("config_error"));
        let v: Value = serde_json::from_str(&line("error", f)).unwrap();
        assert_eq!(v["level"], "error");
        assert_eq!(v["event"], "config_error");
    }
}

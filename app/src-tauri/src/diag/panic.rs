//! Payload-free panic hook (§7.7 Panics): the diagnostic log gets only
//! `file:line`, the thread name and a static category. The payload is
//! never read, formatted or written anywhere, including stderr: the hook
//! replaces the default hook (which prints the payload) and never calls it.

use super::Diag;
use super::fields::{format_line, push_bare, push_value};

/// Static category for panics in the app process.
pub const PANIC_CATEGORY_APP: &str = "app_panic";

/// Replaces the process panic hook. Before `Diag::init` the hook writes
/// nothing; before `Diag::attach_dir` the line stays in the memory buffer.
pub fn install_panic_hook(category: &'static str) {
    std::panic::set_hook(Box::new(move |info: &std::panic::PanicHookInfo<'_>| {
        let Some(diag) = Diag::get() else {
            return;
        };
        let location = match info.location() {
            Some(l) => format!("{}:{}", l.file(), l.line()),
            None => "unknown".to_owned(),
        };
        let current = std::thread::current();
        let mut fields = String::from("event=panic thread=");
        push_bare(&mut fields, current.name().unwrap_or("unnamed"));
        fields.push_str(" category=");
        push_value(&mut fields, category);
        diag.push_line(format_line("ERROR", "panic", &location, &fields));
    }));
}

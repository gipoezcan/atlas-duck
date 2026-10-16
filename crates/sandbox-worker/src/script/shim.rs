//! Installs the `Date` prelude and the `atlas` shim into a script context, with the Rust natives
//! the shim calls (spec §9.2; plan M8 PD-131, PD-151, PD-152).
//!
//! The natives write frames synchronously, during the JS call that makes them (PD-131: `host.log`
//! frames are written synchronously; the host always drains). Before every send they check the
//! run's halt state, so after a heap refusal nothing more leaves the worker (PD-134).

use std::rc::Rc;

use atlas_duck_ipc::sandbox::script::M_HOST_CALL;
use atlas_duck_ipc::sandbox::script::{InstanceInfo, decode_worker_frame, encode_request};
use atlas_duck_ipc::sandbox::{HostCall, WORKER_FRAME_MAX_BYTES};
use rquickjs::{Ctx, Exception, Function, Object};
use serde_json::Value;

use super::{Halt, HostPort, Outcome, ScriptError, Shared};

/// The `Date` prelude (PD-151, R4): JS source text, never bytecode.
pub const PRELUDE_JS: &str = include_str!("prelude.js");

/// The `atlas` shim: JS source text, never bytecode.
pub const SHIM_JS: &str = include_str!("shim.js");

/// The message of the error a native throws once the run is halted.
const HALTED: &str = "the script run is halted";

/// Plan text: a host call whose frame would exceed the worker → host cap (§3.4) rejects inside the
/// script, catchably, and is never sent.
pub const CALL_TOO_LARGE: &str = "the host call is above the 1 MiB frame limit";

/// Plan text: a host call the host's decoder would refuse (its `params` nest deeper than
/// serde_json's recursion limit allows inside a `HostCall`) rejects inside the script, catchably,
/// and is never sent: the host would end the run as a protocol violation.
pub const CALL_NOT_DECODABLE: &str = "the host call params nest too deeply";

/// The JSON text of the init data the shim reads (`JSON.parse`d once in JS). `max_result_units`
/// is the terminal-frame budget for the result text in bytes, and `max_frame_units` the worker →
/// host frame cap, both used by the shim as UTF-16 unit bounds (a UTF-8 text is never shorter in
/// bytes than in UTF-16 units): a call text above the cap is refused with [`CALL_TOO_LARGE`] and
/// a log line is cut to it before either is copied to Rust (outside the heap limit).
pub(crate) fn config_json(
    read_op_ids: &[String],
    instances: &[InstanceInfo],
    args: &Value,
    max_concurrent_calls: u32,
    max_result_units: usize,
) -> serde_json::Result<String> {
    Ok(format!(
        "{{\"read_op_ids\":{},\"instances\":{},\"args\":{},\"max_concurrent_calls\":{},\
         \"max_result_units\":{},\"max_frame_units\":{},\"call_too_large\":{}}}",
        serde_json::to_string(read_op_ids)?,
        serde_json::to_string(instances)?,
        serde_json::to_string(args)?,
        max_concurrent_calls,
        max_result_units,
        WORKER_FRAME_MAX_BYTES,
        serde_json::to_string(CALL_TOO_LARGE)?,
    ))
}

/// The functions the shim returns, read once at install.
pub(crate) struct ShimApi<'js> {
    /// `start(main)`: calls `main(args, atlas)`, observes it, returns its promise.
    pub start: Function<'js>,
    /// `deliver(frameText)`: the dispatcher, answers 0..=3.
    pub deliver: Function<'js>,
    /// `fulfilled(value)`: records a fulfilled `main` (the JSON result rules).
    pub fulfilled: Function<'js>,
    /// `fail(thrown)`: records a rejected `main` or a thrown value, described as untrusted payload.
    pub fail: Function<'js>,
}

/// Evaluates and runs the `Date` prelude.
pub(crate) fn install_prelude(ctx: &Ctx<'_>) -> rquickjs::Result<()> {
    let prelude: Function = ctx.eval(PRELUDE_JS)?;
    prelude.call::<_, ()>(())
}

/// Evaluates the shim, calls it with the natives and the config, and returns its functions.
pub(crate) fn install_shim<'js, H: HostPort + 'static>(
    ctx: &Ctx<'js>,
    shared: &Rc<Shared<H>>,
    config: &str,
) -> rquickjs::Result<ShimApi<'js>> {
    let natives = natives(ctx, shared)?;
    let shim: Function = ctx.eval(SHIM_JS)?;
    let api: Object = shim.call((natives, config))?;
    Ok(ShimApi {
        start: api.get("start")?,
        deliver: api.get("deliver")?,
        fulfilled: api.get("fulfilled")?,
        fail: api.get("fail")?,
    })
}

/// The four natives, as an object the shim reads once.
fn natives<'js, H: HostPort + 'static>(
    ctx: &Ctx<'js>,
    shared: &Rc<Shared<H>>,
) -> rquickjs::Result<Object<'js>> {
    let obj = Object::new(ctx.clone())?;

    let s = Rc::clone(shared);
    let call = Function::new(
        ctx.clone(),
        move |ctx: Ctx<'js>,
              id: f64,
              op_id: String,
              params: String,
              instance: Option<String>,
              all: bool|
              -> rquickjs::Result<()> {
            send_call(&ctx, &s, id, op_id, &params, instance, all)
        },
    )?;
    obj.set("call", call)?;

    let s = Rc::clone(shared);
    let log = Function::new(
        ctx.clone(),
        move |ctx: Ctx<'js>, line: String| -> rquickjs::Result<()> {
            if s.halted().is_some() {
                return Err(Exception::throw_internal(&ctx, HALTED));
            }
            let sent = s.host.borrow_mut().send_log(&line);
            sent.map_err(|err| io_halt(&ctx, &s, &err))
        },
    )?;
    obj.set("log", log)?;

    let s = Rc::clone(shared);
    let ok = Function::new(ctx.clone(), move |text: String| {
        s.settle(Outcome::Result(text));
    })?;
    obj.set("ok", ok)?;

    let s = Rc::clone(shared);
    let err = Function::new(
        ctx.clone(),
        move |class: String, message: String, stack: String| {
            s.settle(Outcome::Error(ScriptError {
                class,
                message,
                stack,
            }));
        },
    )?;
    obj.set("err", err)?;

    Ok(obj)
}

/// `natives.call`: builds the `HostCall`, refuses one whose frame would exceed 1 MiB or that the
/// host's decoder (`decode_worker_frame`, the same code) would refuse, and writes it through the
/// host port.
fn send_call<H: HostPort>(
    ctx: &Ctx<'_>,
    shared: &Shared<H>,
    id: f64,
    op_id: String,
    params: &str,
    instance: Option<String>,
    all: bool,
) -> rquickjs::Result<()> {
    if shared.halted().is_some() {
        return Err(Exception::throw_internal(ctx, HALTED));
    }
    // The shim numbers calls 1, 2, 3, ... and sends them in increasing id order (gaps where a call
    // was refused before sending); anything else is a broken shim, not a script error, and is
    // never sent: a reused id would make the host end the run as a protocol violation.
    if !((1.0..=9_007_199_254_740_991.0).contains(&id) && id.fract() == 0.0) {
        return Err(Exception::throw_internal(ctx, "invalid host call id"));
    }
    let id = id as u64;
    if id <= shared.last_call_id.get() {
        return Err(Exception::throw_internal(ctx, "host call id out of order"));
    }
    if params.len() > WORKER_FRAME_MAX_BYTES {
        return Err(Exception::throw_range(ctx, CALL_TOO_LARGE));
    }
    // The text is the shim's `JSON.stringify` output, so the only way it fails to parse is
    // serde_json's recursion limit.
    let params: Value =
        serde_json::from_str(params).map_err(|_| Exception::throw_type(ctx, CALL_NOT_DECODABLE))?;
    let call = HostCall {
        id,
        op_id,
        params,
        instance,
        all,
    };
    let frame = encode_request(M_HOST_CALL, id, &call);
    if frame.len() > WORKER_FRAME_MAX_BYTES {
        return Err(Exception::throw_range(ctx, CALL_TOO_LARGE));
    }
    // Inside a `HostCall` the params sit one level deeper than in the parse above.
    if decode_worker_frame(&frame).is_err() {
        return Err(Exception::throw_type(ctx, CALL_NOT_DECODABLE));
    }
    let sent = shared.host.borrow_mut().send_call(id, &call);
    match sent {
        Ok(()) => {
            shared.last_call_id.set(id);
            shared
                .outstanding
                .set(shared.outstanding.get().saturating_add(1));
            Ok(())
        }
        Err(err) => Err(io_halt(ctx, shared, &err)),
    }
}

/// Records a failed send as the run's halt and throws (the interrupt handler then stops the
/// script within one interrupt interval).
fn io_halt<H: HostPort>(
    ctx: &Ctx<'_>,
    shared: &Shared<H>,
    err: &std::io::Error,
) -> rquickjs::Error {
    shared.set_halt(Halt::Io(err.kind()));
    Exception::throw_internal(ctx, HALTED)
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::rc::Rc;
    use std::time::Duration;

    use atlas_duck_ipc::sandbox::HostCall;
    use rquickjs::{CatchResultExt, Function};

    use super::natives;
    use crate::engine::{new_context, new_runtime_with_heap_limit};
    use crate::script::interrupt::Deadline;
    use crate::script::{HostPort, Shared};

    #[derive(Default)]
    struct Recorder(Vec<u64>);

    impl HostPort for Recorder {
        fn send_call(&mut self, id: u64, _call: &HostCall) -> io::Result<()> {
            self.0.push(id);
            Ok(())
        }

        fn send_log(&mut self, _line: &str) -> io::Result<()> {
            Ok(())
        }
    }

    /// Defence in depth behind the shim's queue: the native never sends an id that is not above
    /// the last one sent (a reused id would be the host's protocol violation, not the script's).
    #[test]
    fn native_call_refuses_an_id_not_above_the_last_sent() -> Result<(), String> {
        let (rt, meter) = new_runtime_with_heap_limit(16 << 20).map_err(|e| e.to_string())?;
        let ctx = new_context(&rt).map_err(|e| e.to_string())?;
        let shared = Rc::new(Shared {
            host: RefCell::new(Recorder::default()),
            meter,
            halt: Cell::new(None),
            outcome: RefCell::new(None),
            outstanding: Cell::new(0),
            last_call_id: Cell::new(0),
            deadline: Deadline::after(Duration::from_secs(3600)),
        });
        let sent = ctx
            .with(|ctx| -> rquickjs::Result<Vec<bool>> {
                let call: Function = natives(&ctx, &shared)?.get("call")?;
                let mut sent = Vec::new();
                for id in [1.0, 1.0, 3.0, 2.0, 3.0, 4.0] {
                    let args = (id, "jira.search", "{}", None::<String>, false);
                    sent.push(call.call::<_, ()>(args).catch(&ctx).is_ok());
                }
                Ok(sent)
            })
            .map_err(|e| e.to_string())?;
        assert_eq!(sent, [true, false, true, false, false, true]);
        assert_eq!(shared.host.borrow().0, [1, 3, 4]);
        assert_eq!(shared.outstanding.get(), 3);
        assert!(shared.halted().is_none());
        Ok(())
    }
}

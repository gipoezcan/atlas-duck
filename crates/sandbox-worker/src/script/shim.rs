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
/// is the terminal-frame budget for the result text in bytes, used by the shim as a UTF-16 unit
/// bound (a UTF-8 text is never shorter in bytes than in UTF-16 units).
pub(crate) fn config_json(
    read_op_ids: &[String],
    instances: &[InstanceInfo],
    args: &Value,
    max_concurrent_calls: u32,
    max_result_units: usize,
) -> serde_json::Result<String> {
    Ok(format!(
        "{{\"read_op_ids\":{},\"instances\":{},\"args\":{},\"max_concurrent_calls\":{},\
         \"max_result_units\":{}}}",
        serde_json::to_string(read_op_ids)?,
        serde_json::to_string(instances)?,
        serde_json::to_string(args)?,
        max_concurrent_calls,
        max_result_units,
    ))
}

/// Evaluates and runs the `Date` prelude.
pub(crate) fn install_prelude(ctx: &Ctx<'_>) -> rquickjs::Result<()> {
    let prelude: Function = ctx.eval(PRELUDE_JS)?;
    prelude.call::<_, ()>(())
}

/// Evaluates the shim, calls it with the natives and the config, and returns `(start, deliver)`.
pub(crate) fn install_shim<'js, H: HostPort + 'static>(
    ctx: &Ctx<'js>,
    shared: &Rc<Shared<H>>,
    config: &str,
) -> rquickjs::Result<(Function<'js>, Function<'js>)> {
    let natives = natives(ctx, shared)?;
    let shim: Function = ctx.eval(SHIM_JS)?;
    let api: Object = shim.call((natives, config))?;
    Ok((api.get("start")?, api.get("deliver")?))
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
    // The shim numbers calls 1, 2, 3, ...; anything else is a broken shim, not a script error.
    if !((1.0..=9_007_199_254_740_991.0).contains(&id) && id.fract() == 0.0) {
        return Err(Exception::throw_internal(ctx, "invalid host call id"));
    }
    let id = id as u64;
    if params.len() > WORKER_FRAME_MAX_BYTES {
        return Err(Exception::throw_range(ctx, CALL_TOO_LARGE));
    }
    // The text is `JSON.stringify` output, so the only way it fails to parse is serde_json's
    // recursion limit.
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

//! `admin maintenance on|off` (M13 T6): while on, `/readyz` answers 503 `maintenance` and every
//! request but the probes is refused (`server/maintenance`), so `admin restore` runs inside the
//! live pod without a second store opener. Each switch is an anchor-chain `MAINTENANCE` row.

use serde_json::{Value, json};

use super::AdminCtx;
use crate::anchor::KIND_MAINTENANCE;

pub fn set(ctx: &AdminCtx, on: bool) -> Result<Value, &'static str> {
    let was = ctx.registry.maintenance();
    if was != on {
        ctx.writer
            .operational(KIND_MAINTENANCE, &json!({"on": on}))
            .map_err(|_| "anchor/append_failed")?;
        ctx.registry.set_maintenance(on);
    }
    Ok(json!({"maintenance": on, "changed": was != on}))
}

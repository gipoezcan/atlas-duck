//! `admin instances list|add|remove` (SM-4.1, SM-8.1): the same `crate::instances` functions as
//! the admin routes, so removal still deletes every user's PAT with a per-user
//! `CREDENTIAL_CHANGED` (SM-4.2).

use serde_json::Value;

use super::{AdminCtx, InstanceArgs};
use crate::instances::{self, CA_REF_ORG, InstanceSpec};

pub fn list(ctx: &AdminCtx) -> Result<Value, &'static str> {
    let views = instances::list(ctx.store.as_ref()).map_err(|e| e.code)?;
    serde_json::to_value(views).map_err(|_| "admin/internal")
}

pub async fn add(ctx: &AdminCtx, a: InstanceArgs) -> Result<Value, &'static str> {
    let spec = InstanceSpec {
        alias: a.alias,
        product: a.product,
        base_url: a.url,
        proxy: a.proxy,
        ca_ref: a.ca_org.then(|| CA_REF_ORG.to_owned()),
        is_default: a.default,
    };
    let view = instances::add(ctx.store.as_ref(), &ctx.registry, spec)
        .await
        .map_err(|e| e.code)?;
    serde_json::to_value(view).map_err(|_| "admin/internal")
}

pub async fn remove(ctx: &AdminCtx, alias: &str) -> Result<Value, &'static str> {
    instances::remove(ctx.store.as_ref(), &ctx.registry, alias)
        .await
        .map_err(|e| e.code)?;
    Ok(serde_json::json!({"removed": alias}))
}

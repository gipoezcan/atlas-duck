//! Inline `OperationSpec` literals: every field is `pub`, so tests need no registry test hook.
#![allow(dead_code)]

use atlas_duck_registry::*;

pub const SCHEMA: &str = r#"{"type":"object","properties":{"key":{"type":"string"},"max":{"type":"integer"},"expand":{"type":"boolean"}},"additionalProperties":false,"examples":[{"key":"ABC-123","max":10,"expand":true}]}"#;

pub const FLAGS: &[FlagBinding] = &[
    FlagBinding {
        param: "max",
        flag: "--max",
        kind: FlagKind::Int,
        file_variant: false,
    },
    FlagBinding {
        param: "expand",
        flag: "--expand",
        kind: FlagKind::Bool,
        file_variant: false,
    },
    FlagBinding {
        param: "body",
        flag: "--body",
        kind: FlagKind::Str,
        file_variant: true,
    },
];

pub const READ: OperationSpec = OperationSpec {
    id: "test.thing.get",
    product: Product::Jira,
    class: OpClass::Read,
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/api/2/issue/{key}",
        query: &[],
        body: BodySource::None,
    },
    alt_endpoint: None,
    params_schema: SCHEMA,
    cli: CliBinding {
        noun_path: &["jira", "issue", "get"],
        positional: Some("key"),
        flags: FLAGS,
    },
    target_params: &["key"],
    conflict_baselines: &[],
    target_display: TargetDisplay::Param("key"),
    similarity: Similarity::Target,
    field_rules: None,
    caps: Caps {
        max: Some(MaxCap {
            param: "max",
            default: 50,
            hard_cap_default: 100,
            configurable: true,
        }),
        move_limit: None,
        comments_cap: None,
        upload_max_bytes: None,
        static_result_cap_bytes: RELEASE_CAP_BYTES,
    },
    min_version: None,
    paginated: None,
    result_projection: Projection::Empty,
    success: SuccessShape {
        statuses: StatusSet::Any2xx,
        body: SuccessBody::Json,
    },
    redaction_rules: RedactionRules {
        copies: &[],
        mirrors: &[],
        url_fields: &[],
    },
    result_example: r#"{"key":"ABC-123"}"#,
    result_example_sparse: r#"{}"#,
    result_schema: r#"{"type":"object"}"#,
    write_guidance: false,
};

pub fn with_display(display: TargetDisplay) -> OperationSpec {
    OperationSpec {
        target_display: display,
        ..READ
    }
}

pub fn env() -> DescribeEnv {
    DescribeEnv {
        limits_source: LimitsSource::Default,
        available: None,
        caps: serde_json::Value::Null,
        script_limits: serde_json::json!({"timeout_s": 120}),
    }
}

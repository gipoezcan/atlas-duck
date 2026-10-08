//! The 7 Confluence write specs (§7.4), in table order. Every write is one HTTP request (§7.2);
//! the declared success shape decides whether the receipt is projected or `{}`.

use super::{DEFAULT_SUCCESS, EMPTY_204, NO_CAPS, NO_REDACTION, RECEIPT_FIELDS, schemas};
use crate::RELEASE_CAP_BYTES;
use crate::model::*;

const BODY_FLAG: FlagBinding = FlagBinding {
    param: "body",
    flag: "--body",
    kind: FlagKind::Str,
    file_variant: true,
};

const BODY_FORMAT_FLAG: FlagBinding = FlagBinding {
    param: "body_format",
    flag: "--body-format",
    kind: FlagKind::Str,
    file_variant: false,
};

const TITLE_FLAG: FlagBinding = FlagBinding {
    param: "title",
    flag: "--title",
    kind: FlagKind::Str,
    file_variant: false,
};

const fn post(path: &'static str) -> Endpoint {
    Endpoint {
        method: Method::Post,
        path,
        query: &[],
        body: BodySource::OpSpecific,
    }
}

const fn put(path: &'static str) -> Endpoint {
    Endpoint {
        method: Method::Put,
        ..post(path)
    }
}

pub(crate) const PAGE_CREATE: OperationSpec = OperationSpec {
    id: "confluence.page.create",
    product: Product::Confluence,
    class: OpClass::Write,
    endpoint: post("/rest/api/content"),
    alt_endpoint: None,
    params_schema: schemas::PAGE_CREATE_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "page", "create"],
        positional: None,
        flags: &[
            FlagBinding {
                param: "space",
                flag: "--space",
                kind: FlagKind::Str,
                file_variant: false,
            },
            TITLE_FLAG,
            BODY_FLAG,
            BODY_FORMAT_FLAG,
            FlagBinding {
                param: "parent",
                flag: "--parent",
                kind: FlagKind::Str,
                file_variant: false,
            },
        ],
    },
    // Both identify where the page goes (§5.4 step 4).
    target_params: &["space", "parent"],
    conflict_baselines: &[],
    target_display: TargetDisplay::CreateIn("space"),
    similarity: Similarity::Create,
    field_rules: None,
    caps: NO_CAPS,
    min_version: None,
    paginated: None,
    result_projection: Projection::Fields(RECEIPT_FIELDS),
    success: DEFAULT_SUCCESS,
    redaction_rules: NO_REDACTION,
    result_example: schemas::PAGE_RECEIPT_EXAMPLE,
    result_example_sparse: schemas::PAGE_RECEIPT_EXAMPLE,
    result_schema: schemas::CONTENT_RECEIPT_RESULT,
    write_guidance: true,
};

pub(crate) const PAGE_UPDATE: OperationSpec = OperationSpec {
    id: "confluence.page.update",
    endpoint: put("/rest/api/content/{id}"),
    params_schema: schemas::PAGE_UPDATE_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "page", "update"],
        positional: Some("id"),
        flags: &[
            FlagBinding {
                param: "base_version",
                flag: "--base-version",
                kind: FlagKind::Int,
                file_variant: false,
            },
            BODY_FLAG,
            BODY_FORMAT_FLAG,
            TITLE_FLAG,
        ],
    },
    target_params: &["id"],
    // The request carries `version.number = base_version + 1`.
    conflict_baselines: &["base_version"],
    target_display: TargetDisplay::Param("id"),
    similarity: Similarity::Target,
    result_example: schemas::PAGE_UPDATE_RECEIPT_EXAMPLE,
    result_example_sparse: schemas::PAGE_UPDATE_RECEIPT_EXAMPLE,
    ..PAGE_CREATE
};

/// Same space only (M7 checks it); `parent` is the change itself, not a target param.
pub(crate) const PAGE_MOVE: OperationSpec = OperationSpec {
    id: "confluence.page.move",
    params_schema: schemas::PAGE_MOVE_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "page", "move"],
        positional: Some("id"),
        flags: &[FlagBinding {
            param: "parent",
            flag: "--parent",
            kind: FlagKind::Str,
            file_variant: false,
        }],
    },
    conflict_baselines: &[],
    ..PAGE_UPDATE
};

pub(crate) const COMMENT_ADD: OperationSpec = OperationSpec {
    id: "confluence.comment.add",
    endpoint: post("/rest/api/content"),
    params_schema: schemas::COMMENT_ADD_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "comment", "add"],
        positional: Some("content_id"),
        flags: &[
            BODY_FLAG,
            BODY_FORMAT_FLAG,
            FlagBinding {
                param: "reply_to",
                flag: "--reply-to",
                kind: FlagKind::Str,
                file_variant: false,
            },
        ],
    },
    target_params: &["content_id"],
    target_display: TargetDisplay::Param("content_id"),
    result_example: schemas::COMMENT_RECEIPT_EXAMPLE,
    result_example_sparse: schemas::COMMENT_RECEIPT_EXAMPLE,
    ..PAGE_MOVE
};

/// §4.2: the receipt lists only the labels the agent supplied.
pub(crate) const LABEL_ADD: OperationSpec = OperationSpec {
    id: "confluence.label.add",
    endpoint: post("/rest/api/content/{id}/label"),
    params_schema: schemas::LABEL_ADD_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "label", "add"],
        positional: Some("id"),
        flags: &[FlagBinding {
            param: "labels",
            flag: "--labels",
            kind: FlagKind::CsvList,
            file_variant: false,
        }],
    },
    target_params: &["id"],
    target_display: TargetDisplay::Param("id"),
    result_projection: Projection::AgentLabels,
    result_example: schemas::LABEL_ADD_EXAMPLE,
    result_example_sparse: schemas::LABEL_ADD_EXAMPLE_SPARSE,
    result_schema: schemas::LABEL_ADD_RESULT,
    ..COMMENT_ADD
};

/// The only DELETE (§1.3); empty 204 success.
pub(crate) const LABEL_REMOVE: OperationSpec = OperationSpec {
    id: "confluence.label.remove",
    endpoint: Endpoint {
        method: Method::Delete,
        path: "/rest/api/content/{id}/label/{label}",
        query: &[],
        body: BodySource::None,
    },
    params_schema: schemas::LABEL_REMOVE_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "label", "remove"],
        positional: Some("id"),
        flags: &[FlagBinding {
            param: "label",
            flag: "--label",
            kind: FlagKind::Str,
            file_variant: false,
        }],
    },
    target_params: &["id", "label"],
    target_display: TargetDisplay::Pair("id", "label"),
    success: EMPTY_204,
    result_projection: Projection::Empty,
    result_example: schemas::EMPTY_RECEIPT_EXAMPLE,
    result_example_sparse: schemas::EMPTY_RECEIPT_EXAMPLE,
    result_schema: schemas::EMPTY_RECEIPT_RESULT,
    ..LABEL_ADD
};

/// `replace` (PUT to `/{attachmentId}/data`) is M7.
pub(crate) const ATTACHMENT_UPLOAD: OperationSpec = OperationSpec {
    id: "confluence.attachment.upload",
    endpoint: post("/rest/api/content/{id}/child/attachment"),
    params_schema: schemas::ATTACHMENT_UPLOAD_PARAMS,
    cli: CliBinding {
        noun_path: &["confluence", "attachment", "upload"],
        positional: Some("id"),
        flags: &[
            FlagBinding {
                param: "filename",
                flag: "--filename",
                kind: FlagKind::Str,
                file_variant: false,
            },
            FlagBinding {
                param: "content_base64",
                flag: "--content-base64",
                kind: FlagKind::Str,
                file_variant: true,
            },
            FlagBinding {
                param: "replace",
                flag: "--replace",
                kind: FlagKind::Bool,
                file_variant: false,
            },
            FlagBinding {
                param: "comment",
                flag: "--comment",
                kind: FlagKind::Str,
                file_variant: false,
            },
        ],
    },
    target_params: &["id"],
    target_display: TargetDisplay::Param("id"),
    caps: Caps {
        upload_max_bytes: Some(10 * 1024 * 1024),
        static_result_cap_bytes: RELEASE_CAP_BYTES,
        ..NO_CAPS
    },
    success: DEFAULT_SUCCESS,
    result_projection: Projection::Fields(RECEIPT_FIELDS),
    result_example: schemas::ATTACHMENT_RECEIPT_EXAMPLE,
    result_example_sparse: schemas::ATTACHMENT_RECEIPT_EXAMPLE,
    result_schema: schemas::CONTENT_RECEIPT_RESULT,
    ..LABEL_ADD
};

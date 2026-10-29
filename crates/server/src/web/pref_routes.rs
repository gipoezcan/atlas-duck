//! `PUT /api/me/preferences` (M15 T4, PD-295): the session user's own display preferences, today
//! the UI language. Session + CSRF + Origin through the `/api` guard (a bearer is refused there).
//! A display preference: no audit record, no anchor row.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::AppState;
use super::auth_routes::body_bytes;
use super::extract::SessionUser;
use crate::errors::ApiError;
use crate::store::LangPref;
use atlas_duck_core::Lang;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrefsBody {
    lang_pref: String,
}

pub async fn put(
    State(st): State<AppState>,
    SessionUser(s): SessionUser,
    req: Request,
) -> Result<Response, ApiError> {
    let bytes = body_bytes(req.into_body()).await?;
    let body: PrefsBody = serde_json::from_slice(&bytes).map_err(|_| ApiError::BAD_REQUEST)?;
    let pref = LangPref::parse(&body.lang_pref).ok_or(ApiError::BAD_REQUEST)?;
    st.store
        .set_user_lang_pref(&s.user_id, pref)
        .map_err(|_| ApiError::STORE_UNAVAILABLE)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// M15 T10b (PD-291, PD-295): the language a reader's preview and audit documents are written in:
/// the user's stored preference, and for `auto` the first language of the request's
/// `Accept-Language` (German iff its primary subtag is `de`). A store that cannot be read is
/// `auto`.
pub fn reader_lang(st: &AppState, user_id: &str, headers: &axum::http::HeaderMap) -> Lang {
    match st.store.user_lang_pref(user_id).unwrap_or_default() {
        LangPref::En => Lang::En,
        LangPref::De => Lang::De,
        LangPref::Auto => accept_language(headers),
    }
}

/// `Accept-Language`'s first tag: German iff its primary subtag is `de`, else English.
pub fn accept_language(headers: &axum::http::HeaderMap) -> Lang {
    let first = headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|tag| tag.split(';').next())
        .unwrap_or("");
    let primary = first.trim().split(['-', '_']).next().unwrap_or("");
    if primary.eq_ignore_ascii_case("de") {
        Lang::De
    } else {
        Lang::En
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::*;

    #[test]
    fn accept_language_takes_the_first_tag() {
        let lang = |v: &str| {
            let mut h = HeaderMap::new();
            if let Ok(v) = HeaderValue::from_str(v) {
                h.insert(header::ACCEPT_LANGUAGE, v);
            }
            accept_language(&h)
        };
        assert_eq!(lang("de-DE,de;q=0.9,en;q=0.8"), Lang::De);
        assert_eq!(lang("de"), Lang::De);
        assert_eq!(lang("DE-at"), Lang::De);
        assert_eq!(lang("en-US,de;q=0.9"), Lang::En);
        assert_eq!(lang("fr"), Lang::En);
        assert_eq!(lang(""), Lang::En);
        assert_eq!(accept_language(&HeaderMap::new()), Lang::En);
    }
}

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
/// the user's stored preference, and for `auto` the request's `Accept-Language` by its weights
/// ([`accept_language`]). A store that cannot be read is `auto`.
pub fn reader_lang(st: &AppState, user_id: &str, headers: &axum::http::HeaderMap) -> Lang {
    match st.store.user_lang_pref(user_id).unwrap_or_default() {
        LangPref::En => Lang::En,
        LangPref::De => Lang::De,
        LangPref::Auto => accept_language(headers),
    }
}

/// The longest `Accept-Language` value read; a longer one is English (m-3: bounded work).
const ACCEPT_LANGUAGE_MAX_BYTES: usize = 1024;
/// At most this many entries of the list are read; later ones are ignored.
const ACCEPT_LANGUAGE_MAX_ENTRIES: usize = 32;

/// `Accept-Language` by RFC 9110 §12.5.4 weights (M15 T10b fix m-3): German when `de` (any
/// region) weighs more than `en`, or as much and comes first. A language not listed weighs as much
/// as `*` (nothing without one); `q=0` excludes. A malformed entry (bad `q`, an empty tag) is
/// skipped; a missing, non-visible-ASCII or oversized header is English.
pub fn accept_language(headers: &axum::http::HeaderMap) -> Lang {
    let Some(value) = headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= ACCEPT_LANGUAGE_MAX_BYTES)
    else {
        return Lang::En;
    };
    // (weight in thousandths, position) of the best entry for de, en and `*`.
    let mut best: [Option<(u16, usize)>; 3] = [None; 3];
    for (pos, entry) in value
        .split(',')
        .take(ACCEPT_LANGUAGE_MAX_ENTRIES)
        .enumerate()
    {
        let mut parts = entry.split(';');
        let tag = parts.next().unwrap_or("").trim();
        let mut q = Some(1000u16);
        for param in parts {
            let (k, v) = param.split_once('=').unwrap_or((param, ""));
            if k.trim().eq_ignore_ascii_case("q") {
                q = qvalue(v.trim());
            }
        }
        let Some(q) = q else { continue };
        let primary = tag.split(['-', '_']).next().unwrap_or("");
        let slot = if primary.eq_ignore_ascii_case("de") {
            0
        } else if primary.eq_ignore_ascii_case("en") {
            1
        } else if tag == "*" {
            2
        } else {
            continue;
        };
        if best[slot].is_none_or(|(b, _)| q > b) {
            best[slot] = Some((q, pos));
        }
    }
    let star = best[2];
    let de = best[0].or(star).filter(|(q, _)| *q > 0);
    let en = best[1].or(star).filter(|(q, _)| *q > 0);
    match (de, en) {
        (Some((qd, pd)), Some((qe, pe))) if qd > qe || (qd == qe && pd < pe) => Lang::De,
        (Some(_), None) => Lang::De,
        _ => Lang::En,
    }
}

/// An RFC 9110 qvalue (`0`, `0.5`, `1.000`; at most three decimals) in thousandths.
fn qvalue(v: &str) -> Option<u16> {
    let (int, frac) = v.split_once('.').unwrap_or((v, ""));
    if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let frac_k = format!("{frac:0<3}").parse::<u16>().ok()?;
    match int {
        "0" => Some(frac_k),
        "1" if frac_k == 0 => Some(1000),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::*;

    fn lang(v: &str) -> Lang {
        let mut h = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(v) {
            h.insert(header::ACCEPT_LANGUAGE, v);
        }
        accept_language(&h)
    }

    /// M15 T10b fix m-3: q-values, `*`, `q=0`, malformed and oversized headers.
    #[test]
    fn accept_language_honours_weights() {
        assert_eq!(lang("en;q=0.1, de"), Lang::De);
        assert_eq!(lang("en;q=0.1, de;q=0.9"), Lang::De);
        assert_eq!(lang("de;q=0.5, en;q=0.6"), Lang::En);
        assert_eq!(lang("de, en"), Lang::De);
        assert_eq!(lang("en, de"), Lang::En);
        assert_eq!(lang("de;q=0, en;q=0.1"), Lang::En);
        assert_eq!(lang("de;q=0"), Lang::En);
        assert_eq!(lang("fr, *;q=0.5, en;q=0.4"), Lang::De);
        // `*` alone weighs both the same at the same place: the default, English.
        assert_eq!(lang("*"), Lang::En);
        assert_eq!(lang("*, en"), Lang::De);
        assert_eq!(lang("de-CH;q=0.3, de;q=0.8, en;q=0.7"), Lang::De);
        assert_eq!(lang("DE-at"), Lang::De);
        // Malformed entries are skipped.
        assert_eq!(lang("de;q=2, en"), Lang::En);
        assert_eq!(lang("de;q=abc, en;q=0.5"), Lang::En);
        assert_eq!(lang("de;q=0.12345"), Lang::En);
        assert_eq!(lang(";;;,,,"), Lang::En);
        assert_eq!(lang("de;q=1.000"), Lang::De);
        assert_eq!(lang("de;q=1.001"), Lang::En);
        // Oversized: English, whatever it says.
        let long = format!("de,{}", "x-y;q=0.1,".repeat(200));
        assert!(long.len() > ACCEPT_LANGUAGE_MAX_BYTES);
        assert_eq!(lang(&long), Lang::En);
        // Only the first entries count.
        let many = format!("{}de", "fr,".repeat(ACCEPT_LANGUAGE_MAX_ENTRIES));
        assert_eq!(lang(&many), Lang::En);
        // Not visible ASCII: `to_str` fails, English.
        let mut h = HeaderMap::new();
        h.insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_bytes(b"de\xff").unwrap_or(HeaderValue::from_static("en")),
        );
        assert_eq!(accept_language(&h), Lang::En);
    }

    #[test]
    fn accept_language_takes_the_first_tag() {
        assert_eq!(lang("de-DE,de;q=0.9,en;q=0.8"), Lang::De);
        assert_eq!(lang("de"), Lang::De);
        assert_eq!(lang("DE-at"), Lang::De);
        assert_eq!(lang("en-US,de;q=0.9"), Lang::En);
        assert_eq!(lang("fr"), Lang::En);
        assert_eq!(lang(""), Lang::En);
        assert_eq!(accept_language(&HeaderMap::new()), Lang::En);
    }
}

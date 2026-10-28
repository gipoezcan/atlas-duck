use super::*;
use crate::store::LangPref;

impl H {
    /// `PUT /api/me/preferences` with `body`, the session cookie, and the given token and origin.
    async fn put_prefs(
        &self,
        cookie: &str,
        csrf: Option<&str>,
        origin: Option<&str>,
        body: Value,
    ) -> Response {
        let mut b = Request::builder()
            .method(Method::PUT)
            .uri("/api/me/preferences")
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::COOKIE,
                format!("__Host-atlas_duck_session={cookie}"),
            );
        if let Some(c) = csrf {
            b = b.header("x-csrf-token", c);
        }
        if let Some(o) = origin {
            b = b.header(header::ORIGIN, o);
        }
        self.send(b.body(Body::from(body.to_string())).unwrap())
            .await
    }
}

#[tokio::test]
async fn session_reports_lang_pref() {
    let h = H::new();
    let (cookie, csrf) = h.session("alice", PW_CANARY).await;
    let res = h.get_session(&cookie).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(json_body(res).await["lang_pref"], "auto");
    for word in ["de", "en", "auto", "de"] {
        let res = h
            .put_prefs(
                &cookie,
                Some(&csrf),
                Some(ORIGIN),
                json!({"lang_pref": word}),
            )
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT, "{word}");
        let body = json_body(h.get_session(&cookie).await).await;
        assert_eq!(body["lang_pref"], word);
    }
    // Stored for the user, not the session: a second login sees it.
    let (other, _) = h.session("alice", PW_CANARY).await;
    assert_eq!(
        json_body(h.get_session(&other).await).await["lang_pref"],
        "de"
    );
    let uid = user_id_for("alice");
    assert_eq!(h.store.user_lang_pref(&uid).unwrap(), LangPref::De);
}

#[tokio::test]
async fn put_preferences_requires_csrf() {
    let h = H::new();
    let (cookie, csrf) = h.session("alice", PW_CANARY).await;
    let de = json!({"lang_pref": "de"});
    for token in [None, Some("wrong"), Some("")] {
        let (s, c) = code(h.put_prefs(&cookie, token, Some(ORIGIN), de.clone()).await).await;
        assert_eq!(
            (s, c.as_str()),
            (StatusCode::FORBIDDEN, "auth/csrf_mismatch"),
            "{token:?}"
        );
    }
    for origin in [None, Some("https://evil.example.test")] {
        let (s, c) = code(h.put_prefs(&cookie, Some(&csrf), origin, de.clone()).await).await;
        assert_eq!(
            (s, c.as_str()),
            (StatusCode::FORBIDDEN, "auth/origin_mismatch"),
            "{origin:?}"
        );
    }
    // Without a session at all.
    let (s, _) = code(h.put_prefs("none", Some(&csrf), Some(ORIGIN), de).await).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let uid = user_id_for("alice");
    assert_eq!(
        h.store.user_lang_pref(&uid).unwrap(),
        LangPref::Auto,
        "nothing stored"
    );
}

#[tokio::test]
async fn put_preferences_rejects_unknown() {
    let h = H::new();
    let (cookie, csrf) = h.session("alice", PW_CANARY).await;
    for body in [
        json!({"lang_pref": "fr"}),
        json!({"lang_pref": "DE"}),
        json!({"lang_pref": ""}),
        json!({"lang_pref": null}),
        json!({"lang_pref": 1}),
        json!({}),
        json!({"lang_pref": "de", "theme": "dark"}),
        json!("de"),
    ] {
        let (s, c) = code(
            h.put_prefs(&cookie, Some(&csrf), Some(ORIGIN), body.clone())
                .await,
        )
        .await;
        assert_eq!(
            (s, c.as_str()),
            (StatusCode::BAD_REQUEST, "api/bad_request"),
            "{body}"
        );
    }
    let uid = user_id_for("alice");
    assert_eq!(h.store.user_lang_pref(&uid).unwrap(), LangPref::Auto);
}

/// PD-295: a display preference writes no audit record and no anchor row.
#[tokio::test]
async fn put_preferences_is_not_audited() {
    let h = H::new();
    let (cookie, csrf) = h.session("alice", PW_CANARY).await;
    let rt = h
        .registry
        .runtime(&crate::runtime::UserCtx::from_authenticated(&user_id_for(
            "alice",
        )))
        .await
        .unwrap();
    let head = rt.head();
    let anchors = h.store.anchor_all().unwrap().len();
    let res = h
        .put_prefs(
            &cookie,
            Some(&csrf),
            Some(ORIGIN),
            json!({"lang_pref": "de"}),
        )
        .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(rt.head(), head, "no record in the user's chain");
    assert_eq!(
        h.store.anchor_all().unwrap().len(),
        anchors,
        "no anchor row"
    );
}

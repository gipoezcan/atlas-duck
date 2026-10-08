//! `MockDc`: a wiremock server answering like Jira / Confluence Data Center under a context path.

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use super::{TEST_USER, config_for_base, fixtures};
use crate::client::{ClientConfig, Product};
use crate::url::NormalizedBaseUrl;

/// What `X-AUSERNAME` a Jira fixture response carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XAuser {
    /// The name the fixture is about (or the mock's user).
    Same,
    Missing,
    Anonymous,
    /// Another user's name.
    Other(String),
    /// Exactly this header text (percent-encoded names, odd spacing).
    Raw(String),
}

/// `confluence_user_current` answer kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserKind {
    Known,
    Anonymous,
}

pub struct MockDc {
    server: MockServer,
    product: Product,
    context_path: String,
    user: String,
    date: Option<String>,
}

impl MockDc {
    /// `context_path` is empty or starts with `/` (no trailing slash), e.g. `"/jira"`.
    pub async fn start(product: Product, context_path: &str) -> MockDc {
        MockDc {
            server: MockServer::start().await,
            product,
            context_path: context_path.trim_end_matches('/').to_owned(),
            user: TEST_USER.to_owned(),
            date: None,
        }
    }

    /// The `X-AUSERNAME` of fixture responses (`XAuser::Same` in the generic helpers).
    pub fn with_user(mut self, user: &str) -> Self {
        self.user = user.to_owned();
        self
    }

    /// A fixed `Date` on every fixture response mounted afterwards; otherwise the mount time.
    pub fn with_date(mut self, date: &str) -> Self {
        self.date = Some(date.to_owned());
        self
    }

    /// `http://127.0.0.1:<port><context_path>`.
    pub fn base_url(&self) -> String {
        format!("{}{}", self.server.uri(), self.context_path)
    }

    pub fn base(&self) -> NormalizedBaseUrl {
        NormalizedBaseUrl {
            scheme: "http".to_owned(),
            host: self.server.address().ip().to_string(),
            port: Some(self.server.address().port()),
            context_path: self.context_path.clone(),
        }
    }

    pub fn client_config(&self) -> ClientConfig {
        config_for_base(self.product, self.base())
    }

    pub fn server(&self) -> &MockServer {
        &self.server
    }

    /// Every request the server received so far.
    pub async fn received(&self) -> Vec<Request> {
        self.server.received_requests().await.unwrap_or_default()
    }

    /// `path` under the context path.
    pub fn path(&self, p: &str) -> String {
        format!("{}{}", self.context_path, p)
    }

    /// A response with `Date` and, for Jira, `X-AUSERNAME` set to the mock's user.
    pub fn response(&self, status: u16) -> ResponseTemplate {
        self.response_with(status, &XAuser::Same, &self.user)
    }

    fn response_with(&self, status: u16, header: &XAuser, same: &str) -> ResponseTemplate {
        let date = self
            .date
            .clone()
            .unwrap_or_else(|| httpdate::fmt_http_date(std::time::SystemTime::now()));
        let t = ResponseTemplate::new(status).insert_header("Date", date.as_str());
        if self.product != Product::Jira {
            return t;
        }
        match header {
            XAuser::Same => t.insert_header("X-AUSERNAME", same),
            XAuser::Missing => t,
            XAuser::Anonymous => t.insert_header("X-AUSERNAME", "anonymous"),
            XAuser::Other(v) | XAuser::Raw(v) => t.insert_header("X-AUSERNAME", v.as_str()),
        }
    }

    async fn mount_get(&self, p: &str, t: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(self.path(p)))
            .respond_with(t)
            .mount(&self.server)
            .await;
    }

    async fn mount_any(&self, p: &str, t: ResponseTemplate) {
        Mock::given(path(self.path(p)))
            .respond_with(t)
            .mount(&self.server)
            .await;
    }

    /// `GET /rest/api/2/myself` for `name`/`key`, with the given `X-AUSERNAME`.
    pub async fn jira_myself(&self, name: &str, key: &str, header: XAuser) {
        let t = self
            .response_with(200, &header, name)
            .set_body_raw(fixtures::jira_myself(name, key), "application/json");
        self.mount_get("/rest/api/2/myself", t).await;
    }

    pub async fn jira_server_info(&self, version: &str) {
        let t = self
            .response(200)
            .set_body_raw(fixtures::jira_server_info(version), "application/json");
        self.mount_get("/rest/api/2/serverInfo", t).await;
    }

    pub async fn confluence_user_current(&self, kind: UserKind, username: &str, key: &str) {
        let body = match kind {
            UserKind::Known => fixtures::confluence_user_current(username, key),
            UserKind::Anonymous => fixtures::CONFLUENCE_USER_ANONYMOUS.to_owned(),
        };
        let t = self.response(200).set_body_raw(body, "application/json");
        self.mount_get("/rest/api/user/current", t).await;
    }

    pub async fn applinks_manifest(&self, version: &str) {
        let t = self
            .response(200)
            .set_body_raw(fixtures::applinks_manifest(version), "application/json");
        self.mount_get("/rest/applinks/1.0/manifest", t).await;
    }

    /// Any method on `p`: `status` with a JSON body.
    pub async fn json(&self, p: &str, status: u16, body: &str) {
        let t = self.response(status).set_body_raw(body, "application/json");
        self.mount_any(p, t).await;
    }

    /// An SSO / maintenance style HTML page.
    pub async fn html(&self, p: &str, status: u16) {
        let t = self.response(status).set_body_raw(
            "<html><body>Please log in</body></html>",
            "text/html; charset=UTF-8",
        );
        self.mount_any(p, t).await;
    }

    /// `302` to `to` with a small HTML body.
    pub async fn redirect(&self, p: &str, to: &str) {
        let t = self
            .response(302)
            .insert_header("Location", to)
            .set_body_raw("<html>moved</html>", "text/html");
        self.mount_any(p, t).await;
    }

    /// `status` with an empty body and the given `Content-Type` (none when `None`).
    pub async fn empty(&self, p: &str, status: u16, content_type: Option<&str>) {
        let mut t = self.response(status);
        if let Some(ct) = content_type {
            t = t.insert_header("Content-Type", ct);
        }
        self.mount_any(p, t).await;
    }
}

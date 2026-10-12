//! `AppHandler` (PD-30): the handler the server's cell holds. It delegates every method to the
//! served handler (`Core`'s or the gate's) and adds the app-side fields to `doctor`.

use std::sync::Arc;

use atlas_duck_ipc::envelope::{Envelope, Status};
use atlas_duck_ipc::paths::{LocalDataDir, read_endpoint_file};
use atlas_duck_ipc::proto::{
    AwaitParams, ConnectionMeta, Hello, HelloReply, ListState, MatchParams, ProgressSink,
    RequestHandler, SubmitParams, SubmitReply,
};
use serde_json::Value;

use crate::secret_service::SecretServiceCheck;
use crate::tray_host::TrayHost;

/// What the app adds to `doctor` (PD-30, L65).
pub struct DoctorExtras {
    /// The M1 startup check (Linux); `None` elsewhere (`null`).
    pub tray_host: Option<TrayHost>,
    pub secret_service: Arc<dyn SecretServiceCheck>,
    /// The data dir whose `endpoint` file tells whether the server still accepts connections:
    /// the server removes it when it stops accepting (Windows: every rebind failed, L65; and
    /// at shutdown). `None`: `ipc_accepting` is `null`.
    pub data: Option<LocalDataDir>,
}

impl DoctorExtras {
    /// The added fields, computed on a blocking thread (the Secret Service probe may take up
    /// to 2 s; the endpoint check reads a file).
    async fn fields(self: Arc<Self>) -> [(&'static str, Value); 3] {
        let tray_host = match self.tray_host {
            Some(t) => Value::String(t.as_str().to_owned()),
            None => Value::Null,
        };
        let probed = tokio::task::spawn_blocking(move || {
            let secret = self.secret_service.check();
            let accepting = self
                .data
                .as_ref()
                .map(|d| matches!(read_endpoint_file(d), Ok(Some(_))));
            (secret, accepting)
        })
        .await;
        let (secret, accepting) = probed.unwrap_or((None, None));
        [
            ("tray_host", tray_host),
            (
                "secret_service",
                secret.map_or(Value::Null, |s| Value::String(s.as_str().to_owned())),
            ),
            ("ipc_accepting", accepting.map_or(Value::Null, Value::Bool)),
        ]
    }
}

/// Wraps the served handler (PD-30). Only `doctor` is post-processed: a `succeeded` answer whose
/// `data` is an object gains `tray_host`, `secret_service` and `ipc_accepting`; any other answer
/// passes through unchanged.
pub struct AppHandler {
    inner: Arc<dyn RequestHandler>,
    extras: Arc<DoctorExtras>,
}

impl AppHandler {
    pub fn new(inner: Arc<dyn RequestHandler>, extras: Arc<DoctorExtras>) -> Arc<AppHandler> {
        Arc::new(AppHandler { inner, extras })
    }
}

#[async_trait::async_trait]
impl RequestHandler for AppHandler {
    async fn hello(&self, conn: &ConnectionMeta, h: Hello) -> Result<HelloReply, Envelope> {
        self.inner.hello(conn, h).await
    }

    async fn ops_list(&self, instance: Option<&str>) -> Envelope {
        self.inner.ops_list(instance).await
    }

    async fn ops_describe(&self, op_id: &str, instance: Option<&str>) -> Envelope {
        self.inner.ops_describe(op_id, instance).await
    }

    async fn instances_list(&self) -> Envelope {
        self.inner.instances_list().await
    }

    async fn submit(&self, conn: &ConnectionMeta, p: SubmitParams) -> SubmitReply {
        self.inner.submit(conn, p).await
    }

    async fn submit_script(&self, conn: &ConnectionMeta, p: SubmitParams) -> SubmitReply {
        self.inner.submit_script(conn, p).await
    }

    async fn await_request(
        &self,
        conn: &ConnectionMeta,
        a: AwaitParams,
        progress: &dyn ProgressSink,
    ) -> Envelope {
        self.inner.await_request(conn, a, progress).await
    }

    async fn status(&self, request_id: &str) -> Envelope {
        self.inner.status(request_id).await
    }

    async fn cancel(&self, request_id: &str) -> Envelope {
        self.inner.cancel(request_id).await
    }

    async fn requests_list(
        &self,
        agent: Option<&str>,
        state: Option<ListState>,
        match_params: Option<MatchParams>,
    ) -> Envelope {
        self.inner.requests_list(agent, state, match_params).await
    }

    async fn doctor(&self) -> Envelope {
        let mut env = self.inner.doctor().await;
        if env.status != Status::Succeeded {
            return env;
        }
        let Some(Value::Object(data)) = env.data.as_mut() else {
            return env;
        };
        // Taken out so the map is not borrowed across the await.
        let mut map = std::mem::take(data);
        for (key, value) in self.extras.clone().fields().await {
            map.insert(key.to_owned(), value);
        }
        env.data = Some(Value::Object(map));
        env
    }

    /// Δ2 (T2/T3 review I-2): the core forgets the connection's session here.
    async fn disconnected(&self, conn: &ConnectionMeta) {
        self.inner.disconnected(conn).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use atlas_duck_ipc::envelope::ErrorCode;
    use atlas_duck_ipc::proto::{ClientKind, PeerInfo};
    use serde_json::json;

    use super::*;
    use crate::secret_service::SecretService;

    /// Records each call by name; `doctor` answers what the test set.
    struct Inner {
        calls: Mutex<Vec<String>>,
        doctor: Envelope,
    }

    impl Inner {
        fn new(doctor: Envelope) -> Arc<Inner> {
            Arc::new(Inner {
                calls: Mutex::new(Vec::new()),
                doctor,
            })
        }

        fn record(&self, name: &str) -> Envelope {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(name.to_owned());
            succeeded(json!({ "by": name }))
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    fn succeeded(data: Value) -> Envelope {
        Envelope {
            request_id: None,
            op_id: None,
            instance: None,
            status: Status::Succeeded,
            data: Some(data),
            edited: false,
            redacted: false,
            redaction_note: None,
            message: None,
            error: None,
            meta: None,
        }
    }

    #[async_trait::async_trait]
    impl RequestHandler for Inner {
        async fn hello(&self, _c: &ConnectionMeta, h: Hello) -> Result<HelloReply, Envelope> {
            self.record("hello");
            Ok(HelloReply {
                build_id: h.build_id,
            })
        }
        async fn ops_list(&self, _i: Option<&str>) -> Envelope {
            self.record("ops_list")
        }
        async fn ops_describe(&self, _o: &str, _i: Option<&str>) -> Envelope {
            self.record("ops_describe")
        }
        async fn instances_list(&self) -> Envelope {
            self.record("instances_list")
        }
        async fn submit(&self, _c: &ConnectionMeta, _p: SubmitParams) -> SubmitReply {
            SubmitReply {
                envelope: self.record("submit"),
                params_sha256: None,
            }
        }
        async fn submit_script(&self, _c: &ConnectionMeta, _p: SubmitParams) -> SubmitReply {
            SubmitReply {
                envelope: self.record("submit_script"),
                params_sha256: None,
            }
        }
        async fn await_request(
            &self,
            _c: &ConnectionMeta,
            _a: AwaitParams,
            _s: &dyn ProgressSink,
        ) -> Envelope {
            self.record("await_request")
        }
        async fn status(&self, _id: &str) -> Envelope {
            self.record("status")
        }
        async fn cancel(&self, _id: &str) -> Envelope {
            self.record("cancel")
        }
        async fn requests_list(
            &self,
            _a: Option<&str>,
            _s: Option<ListState>,
            _m: Option<MatchParams>,
        ) -> Envelope {
            self.record("requests_list")
        }
        async fn doctor(&self) -> Envelope {
            self.record("doctor");
            self.doctor.clone()
        }
        async fn disconnected(&self, conn: &ConnectionMeta) {
            self.record(&format!("disconnected:{}", conn.connection_id));
        }
    }

    struct Fixed(Option<SecretService>);

    impl SecretServiceCheck for Fixed {
        fn check(&self) -> Option<SecretService> {
            self.0
        }
    }

    fn extras(tray_host: Option<TrayHost>, secret: Option<SecretService>) -> Arc<DoctorExtras> {
        Arc::new(DoctorExtras {
            tray_host,
            secret_service: Arc::new(Fixed(secret)),
            data: None,
        })
    }

    fn meta() -> ConnectionMeta {
        ConnectionMeta {
            connection_id: "conn_0123".into(),
            peer: PeerInfo::default(),
        }
    }

    struct NoProgress;
    impl ProgressSink for NoProgress {
        fn progress(&self, _n: atlas_duck_ipc::proto::ProgressNotification) {}
    }

    fn submit_params() -> SubmitParams {
        SubmitParams {
            op_id: "jira.search".into(),
            params: json!({}),
            instance: None,
            reason: None,
        }
    }

    #[tokio::test]
    async fn app_handler_merges_doctor() {
        let inner = Inner::new(succeeded(
            json!({ "instances": {}, "pac_configured": false }),
        ));
        let h = AppHandler::new(
            inner.clone(),
            extras(Some(TrayHost::Missing), Some(SecretService::Locked)),
        );
        let env = h.doctor().await;
        assert_eq!(env.status, Status::Succeeded);
        assert_eq!(
            env.data,
            Some(json!({
                "instances": {},
                "pac_configured": false,
                "tray_host": "missing",
                "secret_service": "locked",
                "ipc_accepting": null,
            }))
        );

        // Off Linux both are null; the keys are still there.
        let h = AppHandler::new(inner.clone(), extras(None, None));
        let data = h.doctor().await.data.unwrap_or_default();
        assert_eq!(data["tray_host"], Value::Null);
        assert_eq!(data["secret_service"], Value::Null);
        assert!(
            data.as_object()
                .is_some_and(|m| m.contains_key("tray_host") && m.contains_key("secret_service"))
        );
    }

    #[tokio::test]
    async fn app_handler_passes_other_doctor_answers_through() {
        // Not an object.
        let inner = Inner::new(succeeded(json!(["x"])));
        let h = AppHandler::new(inner.clone(), extras(Some(TrayHost::Present), None));
        assert_eq!(h.doctor().await, succeeded(json!(["x"])));
        // Not succeeded.
        let failed = Envelope::failed(ErrorCode::Internal, false, "internal error");
        let inner = Inner::new(failed.clone());
        let h = AppHandler::new(inner, extras(Some(TrayHost::Present), None));
        assert_eq!(h.doctor().await, failed);
    }

    #[tokio::test]
    async fn app_handler_delegates_every_other_method_untouched() {
        let inner = Inner::new(succeeded(json!({})));
        let h = AppHandler::new(inner.clone(), extras(Some(TrayHost::Present), None));
        let m = meta();
        let hello = Hello {
            build_id: "b".into(),
            client_kind: ClientKind::Cli,
            agent_name: None,
            agent_name_source: atlas_duck_ipc::proto::AgentNameSource::None,
            cwd_basename: String::new(),
        };
        assert!(h.hello(&m, hello).await.is_ok());
        let answers = [
            h.ops_list(None).await,
            h.ops_describe("jira.search", None).await,
            h.instances_list().await,
            h.submit(&m, submit_params()).await.envelope,
            h.submit_script(&m, submit_params()).await.envelope,
            h.await_request(
                &m,
                AwaitParams {
                    request_id: "req_1".into(),
                    timeout_ms: None,
                },
                &NoProgress,
            )
            .await,
            h.status("req_1").await,
            h.cancel("req_1").await,
            h.requests_list(None, None, None).await,
        ];
        let names = [
            "ops_list",
            "ops_describe",
            "instances_list",
            "submit",
            "submit_script",
            "await_request",
            "status",
            "cancel",
            "requests_list",
        ];
        for (env, name) in answers.iter().zip(names) {
            assert_eq!(env, &succeeded(json!({ "by": name })), "{name}");
        }
        let mut want = vec!["hello".to_owned()];
        want.extend(names.iter().map(|n| (*n).to_owned()));
        assert_eq!(inner.calls(), want);
    }

    #[tokio::test]
    async fn app_handler_forwards_disconnected() {
        let inner = Inner::new(succeeded(json!({})));
        let h = AppHandler::new(inner.clone(), extras(None, None));
        h.disconnected(&meta()).await;
        assert_eq!(inner.calls(), ["disconnected:conn_0123"]);
    }

    #[tokio::test]
    async fn ipc_accepting_follows_the_endpoint_file() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let data = match atlas_duck_ipc::paths::check_data_dir(dir.path())? {
            atlas_duck_ipc::paths::DataDirResolution::Local(d) => d,
            _ => return Err("the temp dir is not a local data dir".into()),
        };
        let extras = Arc::new(DoctorExtras {
            tray_host: None,
            secret_service: Arc::new(Fixed(None)),
            data: Some(data.clone()),
        });
        let h = AppHandler::new(Inner::new(succeeded(json!({}))), extras);
        let data_of = |env: Envelope| env.data.unwrap_or_default();
        assert_eq!(data_of(h.doctor().await)["ipc_accepting"], json!(false));
        atlas_duck_ipc::paths::write_endpoint_file(&data, "endpoint-name")?;
        assert_eq!(data_of(h.doctor().await)["ipc_accepting"], json!(true));
        Ok(())
    }
}

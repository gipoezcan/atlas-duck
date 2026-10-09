//! Builds the per-instance `InstanceClient` (§7.2): resolves the proxy (L42) from the instance
//! setting and the OS reading, and gives the client the user agent `atlas-duck/<APP_VERSION>`.
//! The app rebuilds clients at start and on `CONFIG_CHANGED`, so a proxy change applies then.

use std::sync::Arc;

use atlas_duck_atlassian::{
    BuildError, ClientConfig, CredentialProvider, DateObserver, InstanceClient, NormalizedBaseUrl,
    Product, Timeouts,
};
use atlas_duck_ipc::build_info::APP_VERSION;

use crate::proxy::{OsProxySource, ProxySetting, ResolvedProxy, resolve_proxy};

/// What `build` needs of an instance (the M3 runtime type of Task 25 carries more).
#[derive(Clone, Debug)]
pub struct InstanceHttpSpec {
    pub instance_id: String,
    pub product: Product,
    pub base: NormalizedBaseUrl,
    /// PEM bundle of the instance's custom CA (§7.2), merged with the OS roots.
    pub ca_pem: Option<Vec<u8>>,
    pub proxy: ProxySetting,
}

pub struct HttpFactory {
    os: Arc<dyn OsProxySource>,
    creds: Arc<dyn CredentialProvider>,
    dates: Arc<dyn DateObserver>,
    user_agent: String,
    #[cfg(feature = "testing")]
    timeouts: Option<Timeouts>,
}

impl HttpFactory {
    pub fn new(
        os: Arc<dyn OsProxySource>,
        creds: Arc<dyn CredentialProvider>,
        dates: Arc<dyn DateObserver>,
    ) -> Self {
        HttpFactory {
            os,
            creds,
            dates,
            user_agent: format!("atlas-duck/{APP_VERSION}"),
            #[cfg(feature = "testing")]
            timeouts: None,
        }
    }

    /// Short budgets for tests.
    #[cfg(feature = "testing")]
    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = Some(timeouts);
        self
    }

    /// Whether the OS proxy setting uses a PAC script (never evaluated, L42; `doctor`, PD-11).
    /// Reads the OS setting (cached 60 s), which can block: call it off the async runtime.
    pub fn pac_configured(&self) -> bool {
        self.os.read().pac_configured
    }

    /// The client plus the proxy decision, which the caller records (`APP_START`,
    /// `CONFIG_CHANGED`) and surfaces (`pac_configured`).
    pub fn build(
        &self,
        inst: &InstanceHttpSpec,
    ) -> Result<(InstanceClient, ResolvedProxy), BuildError> {
        let resolved = resolve_proxy(&inst.proxy, inst.base.host(), &self.os.read());
        #[allow(unused_mut)]
        let mut timeouts = Timeouts::default();
        #[cfg(feature = "testing")]
        if let Some(t) = self.timeouts {
            timeouts = t;
        }
        let cfg = ClientConfig {
            instance_id: inst.instance_id.clone(),
            product: inst.product,
            base: inst.base.clone(),
            custom_ca_pem: inst.ca_pem.clone(),
            proxy: resolved.choice.clone(),
            user_agent: self.user_agent.clone(),
            timeouts,
        };
        let client = InstanceClient::build(cfg, self.creds.clone(), self.dates.clone())?;
        Ok((client, resolved))
    }
}

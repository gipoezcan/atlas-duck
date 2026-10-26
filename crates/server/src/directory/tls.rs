//! The TLS client configuration for LDAPS (SM-9.2, SM-9.3): the `ring` provider; with
//! `ATLAS_DUCK_CA_BUNDLE_FILE` the bundle's certificates are the only roots, without it the
//! platform verifier (the same OS-root verifier the instances' HTTP client uses). No verifier
//! override exists anywhere.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore};
use rustls_platform_verifier::BuilderVerifierExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsConfigError {
    /// The bundle file cannot be read.
    BundleUnreadable,
    /// The bundle holds no usable certificate.
    BundleInvalid,
    /// rustls refused the configuration.
    Config,
}

pub fn client_config(ca_bundle: Option<&Path>) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsConfigError::Config)?;
    let config = match ca_bundle {
        Some(path) => {
            let pem = std::fs::read(path).map_err(|_| TlsConfigError::BundleUnreadable)?;
            builder
                .with_root_certificates(roots_from_pem(&pem)?)
                .with_no_client_auth()
        }
        None => builder
            .with_platform_verifier()
            .map_err(|_| TlsConfigError::Config)?
            .with_no_client_auth(),
    };
    Ok(Arc::new(config))
}

/// Every certificate of a PEM bundle; none, or one rustls refuses, is `BundleInvalid`.
pub fn roots_from_pem(pem: &[u8]) -> Result<RootCertStore, TlsConfigError> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem) {
        let cert = cert.map_err(|_| TlsConfigError::BundleInvalid)?;
        roots.add(cert).map_err(|_| TlsConfigError::BundleInvalid)?;
    }
    if roots.is_empty() {
        return Err(TlsConfigError::BundleInvalid);
    }
    Ok(roots)
}

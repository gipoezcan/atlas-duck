//! The rustls crypto provider and the per-instance custom CA (§7.2: trust store = OS roots plus an
//! optional PEM bundle).
//!
//! Review Focus 1 decision (Task 9 spike, `tests/tls_ca.rs::custom_ca_merges_with_os_roots`):
//! the custom CA goes through `ClientBuilder::tls_certs_merge`. With `rustls-no-provider`,
//! reqwest 0.13.5 hands merged roots to `rustls_platform_verifier::Verifier::new_with_extra_roots`
//! on Windows, macOS and Linux alike, so the OS roots stay trusted next to the custom CA. The
//! fallback (`tls_backend_preconfigured` with a hand-built `rustls::ClientConfig`) is not needed
//! as long as that test passes on all three CI legs.

use std::sync::OnceLock;

use super::BuildError;

static PROVIDER: OnceLock<()> = OnceLock::new();

/// Installs `ring` as the process-wide rustls provider once; reqwest's `rustls-no-provider`
/// build panics in `ClientBuilder::build` without one.
pub(crate) fn ensure_provider() {
    PROVIDER.get_or_init(|| {
        // Err means another crate installed one first; ring is what we ship, so log nothing.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Every certificate of a PEM bundle; a bundle without one is an error, not "no custom CA".
pub(crate) fn ca_certs(pem: &[u8]) -> Result<Vec<reqwest::Certificate>, BuildError> {
    let certs =
        reqwest::Certificate::from_pem_bundle(pem).map_err(|e| BuildError::CaPem(e.to_string()))?;
    if certs.is_empty() {
        return Err(BuildError::CaPem("no certificate in the bundle".to_owned()));
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_or_garbage_bundle_is_ca_pem_error() {
        assert!(matches!(ca_certs(b""), Err(BuildError::CaPem(_))));
        assert!(matches!(
            ca_certs(b"not a certificate"),
            Err(BuildError::CaPem(_))
        ));
    }
}

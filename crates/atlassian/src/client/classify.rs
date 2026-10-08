//! Pure classification helpers of the one-request engine (§7.2, §11.2).

use std::error::Error;
use std::io;
use std::time::{Duration, SystemTime};

use crate::types::ConnClass;

/// Longest single wait for a `429` or a rate-limit pause (§7.2).
pub(crate) const MAX_WAIT: Duration = Duration::from_secs(30);
/// `429` without a usable `Retry-After`.
const DEFAULT_RETRY_WAIT: Duration = Duration::from_secs(1);

/// `application/json` or any `+json` subtype; case-insensitive, parameters ignored. A missing
/// header is not JSON.
pub(crate) fn is_json_content_type(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let mime = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let Some((ty, sub)) = mime.split_once('/') else {
        return false;
    };
    if ty.is_empty() || sub.contains('/') {
        return false;
    }
    (ty == "application" && sub == "json") || (sub.len() > "+json".len() && sub.ends_with("+json"))
}

/// The wait before retrying a `429`: `Retry-After` as delta-seconds or HTTP-date, 1 s when absent
/// or unreadable, never more than 30 s.
pub(crate) fn retry_after_wait(retry_after: Option<&str>, now: SystemTime) -> Duration {
    retry_after
        .and_then(|v| parse_retry_after(v, now))
        .unwrap_or(DEFAULT_RETRY_WAIT)
        .min(MAX_WAIT)
}

/// Token-bucket pacing (§7.2): when a response says `X-RateLimit-Remaining: 0`, the pause until
/// `Retry-After` or `X-RateLimit-Reset`, at most 30 s. `None` when there is nothing to wait for.
pub(crate) fn rate_limit_pause(
    remaining: Option<&str>,
    reset: Option<&str>,
    retry_after: Option<&str>,
    now: SystemTime,
) -> Option<Duration> {
    if remaining?.trim().parse::<u64>().ok()? != 0 {
        return None;
    }
    let wait = retry_after
        .and_then(|v| parse_retry_after(v, now))
        .or_else(|| reset.and_then(|v| parse_reset(v, now)))?;
    (!wait.is_zero()).then(|| wait.min(MAX_WAIT))
}

fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let v = value.trim();
    if let Ok(secs) = v.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let at = httpdate::parse_http_date(v).ok()?;
    Some(at.duration_since(now).unwrap_or(Duration::ZERO))
}

/// Jira DC sends an ISO 8601 instant (`2026-10-07T10:00Z` or RFC 3339); epoch seconds and an
/// HTTP-date are accepted as well.
fn parse_reset(value: &str, now: SystemTime) -> Option<Duration> {
    let v = value.trim();
    let at = if let Ok(secs) = v.parse::<u64>() {
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs))?
    } else if let Ok(t) = httpdate::parse_http_date(v) {
        t
    } else {
        let dt = chrono::DateTime::parse_from_rfc3339(v)
            .map(|d| d.to_utc())
            .or_else(|_| {
                chrono::NaiveDateTime::parse_from_str(v, "%Y-%m-%dT%H:%MZ").map(|n| n.and_utc())
            })
            .ok()?;
        let secs = u64::try_from(dt.timestamp()).ok()?;
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs))?
    };
    Some(at.duration_since(now).unwrap_or(Duration::ZERO))
}

/// Inputs that only `reqwest::Error` can answer (its own timeout type, its DNS check).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ConnFlags {
    pub(crate) timeout: bool,
    pub(crate) dns: bool,
}

/// The §11.2 class of a failure before any byte of the request was written. Walks the whole
/// `source()` chain, looking inside `io::Error` wrappers too: `io::Error::source` skips the
/// wrapped error, and reqwest 0.13 delivers a certificate failure as
/// `io::Error(Other, io::Error(InvalidData, rustls::Error))`.
///
/// Proxy tunnel failures are matched on hyper-util's `TunnelError` text (no direct hyper-util
/// dependency): `ProxyAuthRequired` displays as "tunnel error: proxy authorization required"
/// (a 407 to CONNECT); every other tunnel failure starts with "tunnel error".
pub(crate) fn classify_connect(err: &(dyn Error + 'static), flags: ConnFlags) -> ConnClass {
    let mut seen = Seen::default();
    let mut cur = Some(err);
    while let Some(e) = cur {
        seen.inspect(e);
        cur = e.source();
    }
    if seen.tunnel_407 {
        ConnClass::ProxyConnect407
    } else if seen.tunnel {
        ConnClass::ProxyConnect
    } else if let Some(tls) = seen.tls {
        tls
    } else if flags.timeout || seen.timed_out {
        ConnClass::ConnectTimeout
    } else if flags.dns || seen.dns {
        ConnClass::Dns
    } else if seen.tcp {
        ConnClass::Connect
    } else if seen.io {
        // TCP connected (no connector context on the chain), then the handshake failed.
        ConnClass::TlsHandshake
    } else {
        ConnClass::Connect
    }
}

#[derive(Default)]
struct Seen {
    tunnel_407: bool,
    tunnel: bool,
    tls: Option<ConnClass>,
    timed_out: bool,
    dns: bool,
    tcp: bool,
    io: bool,
}

impl Seen {
    fn inspect(&mut self, e: &(dyn Error + 'static)) {
        if let Some(r) = e.downcast_ref::<rustls::Error>() {
            self.tls.get_or_insert(tls_class(r));
        }
        if let Some(io) = e.downcast_ref::<io::Error>() {
            self.io = true;
            if io.kind() == io::ErrorKind::TimedOut {
                self.timed_out = true;
            }
            // The wrapped error, and whatever it wraps in turn.
            if let Some(inner) = io.get_ref() {
                let mut cur = Some(inner as &(dyn Error + 'static));
                while let Some(x) = cur {
                    self.inspect(x);
                    cur = x.source();
                }
            }
        }
        let text = e.to_string();
        if text.starts_with("tunnel error") {
            self.tunnel = true;
            if text.contains("proxy authorization required") || text.contains("407") {
                self.tunnel_407 = true;
            }
        }
        if text.starts_with("dns error") {
            self.dns = true;
        }
        if text.starts_with("tcp ") {
            self.tcp = true;
        }
    }
}

/// `TlsUnknownIssuer` gets the "add a custom CA" hint; the other certificate problems get the
/// "contact the server administrator" hint (§11.2).
fn tls_class(e: &rustls::Error) -> ConnClass {
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(C::UnknownIssuer) => ConnClass::TlsUnknownIssuer,
        // Windows' chain engine reports a leaf whose issuer is in no store as CERT_E_CHAINING,
        // which rustls-platform-verifier passes through as `Other` with the OS error text.
        rustls::Error::InvalidCertificate(C::Other(o)) if is_windows_chaining(&o.to_string()) => {
            ConnClass::TlsUnknownIssuer
        }
        rustls::Error::InvalidCertificate(_) => ConnClass::TlsCertificate,
        _ => ConnClass::TlsHandshake,
    }
}

/// CERT_E_CHAINING (0x800B010A) as `std::io::Error::from_raw_os_error` prints it.
fn is_windows_chaining(text: &str) -> bool {
    text.contains("os error -2146762486")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[test]
    fn json_content_types() {
        for ct in [
            "application/json",
            "Application/JSON",
            "application/json; charset=UTF-8",
            " application/json ;x=y",
            "application/problem+json",
            "application/vnd.atl+JSON; v=1",
        ] {
            assert!(is_json_content_type(Some(ct)), "{ct}");
        }
        for ct in [
            "",
            "text/html",
            "text/html; charset=utf-8",
            "application/jsonx",
            "application/x-json",
            "json",
            "application/+json",
            "text/plain; application/json",
        ] {
            assert!(!is_json_content_type(Some(ct)), "{ct}");
        }
        assert!(!is_json_content_type(None));
    }

    #[test]
    fn retry_after_values() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_791_367_200);
        assert_eq!(retry_after_wait(Some("0"), now), Duration::ZERO);
        assert_eq!(retry_after_wait(Some(" 5 "), now), Duration::from_secs(5));
        assert_eq!(retry_after_wait(Some("120"), now), MAX_WAIT);
        assert_eq!(retry_after_wait(None, now), Duration::from_secs(1));
        assert_eq!(retry_after_wait(Some("soon"), now), Duration::from_secs(1));
        assert_eq!(retry_after_wait(Some("-3"), now), Duration::from_secs(1));
        // 2026-10-07 10:00:00 GMT is `now`; ten seconds later and one in the past.
        assert_eq!(
            retry_after_wait(Some("Wed, 07 Oct 2026 10:00:10 GMT"), now),
            Duration::from_secs(10)
        );
        assert_eq!(
            retry_after_wait(Some("Wed, 07 Oct 2026 09:00:00 GMT"), now),
            Duration::ZERO
        );
        assert_eq!(
            retry_after_wait(Some("Thu, 08 Oct 2026 10:00:00 GMT"), now),
            MAX_WAIT
        );
    }

    #[test]
    fn rate_limit_pacing() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_791_367_200);
        let p = |rem, reset, ra| rate_limit_pause(rem, reset, ra, now);
        assert_eq!(p(Some("3"), Some("2026-10-07T10:00:05Z"), None), None);
        assert_eq!(p(None, None, Some("5")), None);
        assert_eq!(p(Some("0"), None, None), None);
        assert_eq!(p(Some("0"), None, Some("4")), Some(Duration::from_secs(4)));
        assert_eq!(
            p(Some("0"), Some("2026-10-07T10:00:07Z"), None),
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            p(Some("0"), Some("2026-10-07T10:01Z"), None),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            p(Some("0"), Some("2026-10-07T12:00:09+02:00"), None),
            Some(Duration::from_secs(9))
        );
        assert_eq!(
            p(Some("0"), Some("1791367212"), None),
            Some(Duration::from_secs(12))
        );
        assert_eq!(p(Some("0"), Some("2026-10-07T09:00:00Z"), None), None);
        assert_eq!(p(Some("0"), Some("whenever"), None), None);
    }

    #[derive(Debug)]
    struct Node {
        text: &'static str,
        source: Option<Box<dyn Error + Send + Sync>>,
    }

    impl fmt::Display for Node {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.text)
        }
    }

    impl Error for Node {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.source.as_deref().map(|e| e as &(dyn Error + 'static))
        }
    }

    fn chain(texts: &[&'static str], leaf: Option<Box<dyn Error + Send + Sync>>) -> Node {
        let mut cur = leaf;
        for t in texts.iter().rev() {
            cur = Some(Box::new(Node {
                text: t,
                source: cur,
            }));
        }
        Node {
            text: "client error (Connect)",
            source: cur,
        }
    }

    fn class(n: &Node) -> ConnClass {
        classify_connect(n, ConnFlags::default())
    }

    fn rustls_in_io(e: rustls::Error) -> Option<Box<dyn Error + Send + Sync>> {
        Some(Box::new(io::Error::new(io::ErrorKind::InvalidData, e)))
    }

    #[test]
    fn tls_classes() {
        use rustls::CertificateError as C;
        let unknown = chain(
            &[],
            rustls_in_io(rustls::Error::InvalidCertificate(C::UnknownIssuer)),
        );
        assert_eq!(class(&unknown), ConnClass::TlsUnknownIssuer);
        for c in [C::NotValidForName, C::Expired, C::BadEncoding, C::Revoked] {
            let n = chain(&[], rustls_in_io(rustls::Error::InvalidCertificate(c)));
            assert_eq!(class(&n), ConnClass::TlsCertificate);
        }
        let chaining = io::Error::from_raw_os_error(-2146762486).to_string();
        let other = rustls::Error::InvalidCertificate(C::Other(rustls::OtherError(
            std::sync::Arc::new(io::Error::other(chaining)),
        )));
        assert_eq!(
            class(&chain(&[], rustls_in_io(other))),
            ConnClass::TlsUnknownIssuer
        );
        let alert = rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure);
        assert_eq!(
            class(&chain(&[], rustls_in_io(alert))),
            ConnClass::TlsHandshake
        );
        // reqwest 0.13's shape: io::Error(Other) around io::Error(InvalidData) around rustls.
        let nested = chain(
            &[],
            Some(Box::new(io::Error::other(io::Error::new(
                io::ErrorKind::InvalidData,
                rustls::Error::InvalidCertificate(C::UnknownIssuer),
            )))),
        );
        assert_eq!(class(&nested), ConnClass::TlsUnknownIssuer);
        // A bare rustls error on the chain (not wrapped in io::Error) is found as well.
        let bare = chain(
            &[],
            Some(Box::new(rustls::Error::InvalidCertificate(
                C::UnknownIssuer,
            ))),
        );
        assert_eq!(class(&bare), ConnClass::TlsUnknownIssuer);
        // Handshake I/O: the peer hung up after TCP connected.
        let eof = chain(
            &[],
            Some(Box::new(io::Error::from(io::ErrorKind::UnexpectedEof))),
        );
        assert_eq!(class(&eof), ConnClass::TlsHandshake);
    }

    #[test]
    fn connector_classes() {
        let refused = chain(
            &["tcp connect error"],
            Some(Box::new(io::Error::from(io::ErrorKind::ConnectionRefused))),
        );
        assert_eq!(class(&refused), ConnClass::Connect);
        let timed_out = chain(
            &["tcp connect error"],
            Some(Box::new(io::Error::from(io::ErrorKind::TimedOut))),
        );
        assert_eq!(class(&timed_out), ConnClass::ConnectTimeout);
        let dns = chain(
            &["dns error"],
            Some(Box::new(io::Error::other("no such host"))),
        );
        assert_eq!(class(&dns), ConnClass::Dns);
        let flagged = chain(&["operation timed out"], None);
        assert_eq!(
            classify_connect(
                &flagged,
                ConnFlags {
                    timeout: true,
                    dns: false
                }
            ),
            ConnClass::ConnectTimeout
        );
        assert_eq!(
            classify_connect(
                &chain(&["whatever"], None),
                ConnFlags {
                    timeout: false,
                    dns: true
                }
            ),
            ConnClass::Dns
        );
        assert_eq!(class(&chain(&["something else"], None)), ConnClass::Connect);
    }

    #[test]
    fn proxy_classes() {
        let auth = chain(&["tunnel error: proxy authorization required"], None);
        assert_eq!(class(&auth), ConnClass::ProxyConnect407);
        let unsuccessful = chain(&["tunnel error: unsuccessful"], None);
        assert_eq!(class(&unsuccessful), ConnClass::ProxyConnect);
        // The proxy itself unreachable: tunnel context wins over the TCP error beneath it.
        let down = chain(
            &[
                "tunnel error: failed to create underlying connection",
                "tcp connect error",
            ],
            Some(Box::new(io::Error::from(io::ErrorKind::ConnectionRefused))),
        );
        assert_eq!(class(&down), ConnClass::ProxyConnect);
    }
}

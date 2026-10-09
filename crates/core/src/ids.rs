//! Identifiers `core` mints: request ids (§3.3), instance ids (PD-04), batch ids (§5.6) and
//! system-fetch ids (§8.3). Every random id is 128 CSPRNG bits in lowercase hex behind a fixed
//! prefix; a failing OS random source is an error, never a weaker id.

use std::fmt;

use atlas_duck_ipc::proto::new_request_id;

/// 16 random bytes, lowercase hex, behind `prefix`.
fn random_id(prefix: &str) -> Result<String, getrandom::Error> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b)?;
    Ok(format!("{prefix}{}", hex::encode(b)))
}

macro_rules! string_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

string_id!(
    /// `"req_" + 32 hex` (`ipc::proto::new_request_id`).
    RequestId
);
string_id!(
    /// `"ins_" + 32 hex`, the `[[instances]] id` key of `config.toml` (PD-04).
    InstanceId
);
string_id!(
    /// `"bat_" + 32 hex`, the `batch_id` of `BATCH_CONFIRMED` and its per-item decisions (§5.6).
    BatchId
);
string_id!(
    /// `"fet_" + 32 hex`, the `fetch_id` of a `SYSTEM_FETCH` start/result pair (§8.3).
    FetchId
);
string_id!(
    /// One IPC connection, by its `connection_id` (`ipc::proto::ConnectionMeta`). The agent key
    /// the pending limits count by is Task 20's `AgentKey`.
    ConnectionKey
);

impl RequestId {
    pub fn new() -> Result<RequestId, getrandom::Error> {
        new_request_id().map(RequestId)
    }
}

impl InstanceId {
    pub const PREFIX: &'static str = "ins_";

    pub fn new() -> Result<InstanceId, getrandom::Error> {
        random_id(Self::PREFIX).map(InstanceId)
    }
}

impl BatchId {
    pub const PREFIX: &'static str = "bat_";

    pub fn new() -> Result<BatchId, getrandom::Error> {
        random_id(Self::PREFIX).map(BatchId)
    }
}

impl FetchId {
    pub const PREFIX: &'static str = "fet_";

    pub fn new() -> Result<FetchId, getrandom::Error> {
        random_id(Self::PREFIX).map(FetchId)
    }
}

impl ConnectionKey {
    pub fn new(connection_id: &str) -> ConnectionKey {
        ConnectionKey(connection_id.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn is_prefixed_hex(s: &str, prefix: &str) -> bool {
        s.strip_prefix(prefix).is_some_and(|h| {
            h.len() == 32
                && h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    }

    #[test]
    fn ids_are_prefixed_128_bit_lowercase_hex() -> TestResult {
        assert!(is_prefixed_hex(RequestId::new()?.as_str(), "req_"));
        assert!(is_prefixed_hex(InstanceId::new()?.as_str(), "ins_"));
        assert!(is_prefixed_hex(BatchId::new()?.as_str(), "bat_"));
        assert!(is_prefixed_hex(FetchId::new()?.as_str(), "fet_"));
        assert_ne!(FetchId::new()?, FetchId::new()?);
        assert_eq!(ConnectionKey::new("c1").to_string(), "c1");
        Ok(())
    }
}

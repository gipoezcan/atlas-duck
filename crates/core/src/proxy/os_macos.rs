//! macOS: `SCDynamicStoreCopyProxies(NULL)`, the dictionary System Settings writes. The mapping
//! from its values to `OsProxy` is plain code (`from_settings`), tested on every OS; only the
//! CoreFoundation extraction is macOS-only.

use super::OsProxy;

/// The dictionary keys this reader uses, already extracted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MacSettings {
    pub https_enable: bool,
    pub https_proxy: Option<String>,
    pub https_port: Option<u32>,
    pub exceptions: Vec<String>,
    pub exclude_simple_hostnames: bool,
    pub auto_config_enable: bool,
    pub auto_discovery_enable: bool,
}

pub fn from_settings(s: &MacSettings) -> OsProxy {
    let https = match (&s.https_proxy, s.https_port) {
        (Some(h), Some(p)) if s.https_enable && !h.is_empty() => u16::try_from(p)
            .ok()
            .filter(|p| *p != 0)
            .map(|p| (h.clone(), p)),
        _ => None,
    };
    let mut bypass = s.exceptions.clone();
    if s.exclude_simple_hostnames {
        bypass.push("<local>".to_owned());
    }
    OsProxy {
        https,
        bypass,
        pac_configured: s.auto_config_enable || s.auto_discovery_enable,
        read_failed: false,
    }
}

/// A NULL answer from the store is `read_failed`. Ownership: the dictionary comes from a
/// `Copy` function (create rule, released once by the wrapper); the exceptions array is
/// borrowed from it through a retained `CFType` clone (get rule), after a type-id check.
#[cfg(target_os = "macos")]
pub fn read() -> OsProxy {
    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use system_configuration_sys::dynamic_store_copy_specific::SCDynamicStoreCopyProxies;

    // SAFETY: Apple documents NULL as a valid store argument (a temporary session is used).
    // The call returns NULL or a dictionary the caller owns (Copy rule).
    let raw: CFDictionaryRef = unsafe { SCDynamicStoreCopyProxies(std::ptr::null()) };
    if raw.is_null() {
        // NULL means the store could not be read, not "no proxies".
        return OsProxy {
            read_failed: true,
            ..OsProxy::default()
        };
    }
    // SAFETY: `raw` is non-null and owned by us; the wrapper releases it once.
    let dict: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_create_rule(raw) };
    let get = |key: &str| dict.find(CFString::new(key)).map(|v| v.clone());
    let int = |key: &str| {
        get(key)
            .and_then(|v| v.downcast::<CFNumber>())
            .and_then(|n| n.to_i64())
    };
    let string = |key: &str| {
        get(key)
            .and_then(|v| v.downcast::<CFString>())
            .map(|s| s.to_string())
    };
    let flag = |key: &str| int(key).is_some_and(|v| v != 0);
    let exceptions = get("ExceptionsList")
        .filter(|v| v.type_of() == CFArray::<CFType>::type_id())
        .map(|v| {
            // SAFETY: the type id was just checked to be CFArray; `get` rule keeps `v` alive.
            let arr: CFArray<CFType> =
                unsafe { CFArray::wrap_under_get_rule(v.as_CFTypeRef() as _) };
            arr.iter()
                .filter_map(|item| item.downcast::<CFString>().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    from_settings(&MacSettings {
        https_enable: flag("HTTPSEnable"),
        https_proxy: string("HTTPSProxy"),
        https_port: int("HTTPSPort").and_then(|p| u32::try_from(p).ok()),
        exceptions,
        exclude_simple_hostnames: flag("ExcludeSimpleHostnames"),
        auto_config_enable: flag("ProxyAutoConfigEnable"),
        auto_discovery_enable: flag("ProxyAutoDiscoveryEnable"),
    })
}

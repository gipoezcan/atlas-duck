//! PD-04: typed `[[instances]]` accessors, id assignment and the two writers Task 25 uses.

use std::fs;
use std::path::{Path, PathBuf};

use atlas_duck_core::config::instances::{
    InstanceConfig, InstancesError, add_instance, ensure_ids, instances, is_valid_instance_id,
    set_base_url,
};
use atlas_duck_core::config::{CONFIG_FILE_NAME, ConfigState, ConfigWriteError, load_config};
use atlas_duck_core::proxy::ProxySetting;
use atlas_duck_registry::Product;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ID_A: &str = "ins_0123456789abcdef0123456789abcdef";

fn write(dir: &Path, text: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(CONFIG_FILE_NAME);
    fs::write(&path, text)?;
    Ok(path)
}

#[test]
fn reads_typed_instances_in_file_order() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = write(
        dir.path(),
        &format!(
            r#"schema_version = 1

[[instances]]
id = "{ID_A}"
alias = "jira-main"
product = "jira"
base_url = "https://jira.corp.example/jira"
default = true
proxy = "direct"

[[instances]]
alias = "wiki"
product = "confluence"
base_url = "https://wiki.corp.example"
ca_bundle = "C:/certs/corp.pem"
proxy = "proxy.corp:3128"
"#
        ),
    )?;
    let list = instances(&load_config(&path)?)?;
    assert_eq!(
        list,
        vec![
            InstanceConfig {
                id: Some(ID_A.to_owned()),
                alias: "jira-main".to_owned(),
                product: Product::Jira,
                base_url_raw: "https://jira.corp.example/jira".to_owned(),
                ca_bundle: None,
                proxy: ProxySetting::Direct,
                is_default: true,
            },
            InstanceConfig {
                id: None,
                alias: "wiki".to_owned(),
                product: Product::Confluence,
                base_url_raw: "https://wiki.corp.example".to_owned(),
                ca_bundle: Some(PathBuf::from("C:/certs/corp.pem")),
                proxy: ProxySetting::HostPort {
                    host: "proxy.corp".to_owned(),
                    port: 3128
                },
                is_default: false,
            },
        ]
    );
    Ok(())
}

#[test]
fn absent_and_unreadable_have_no_instances() -> TestResult {
    let dir = tempfile::tempdir()?;
    let absent = load_config(&dir.path().join(CONFIG_FILE_NAME))?;
    assert!(matches!(absent, ConfigState::Absent));
    assert!(instances(&absent)?.is_empty());
    let path = write(dir.path(), "schema_version = 1\n[[instances]\nbroken")?;
    assert!(instances(&load_config(&path)?)?.is_empty());
    Ok(())
}

#[test]
fn malformed_entries_fail_the_list_without_echoing_values() -> TestResult {
    let dir = tempfile::tempdir()?;
    let cases: &[(&str, InstancesError)] = &[
        ("instances = 3", InstancesError::NotAnArrayOfTables),
        (
            "[[instances]]\nalias = \"a\"\nproduct = \"bitbucket\"\nbase_url = \"https://x\"",
            InstancesError::Malformed {
                index: 0,
                key: "product",
                reason: "must be \"jira\" or \"confluence\"",
            },
        ),
        (
            "[[instances]]\nalias = \"has space\"\nproduct = \"jira\"\nbase_url = \"https://x\"",
            InstancesError::Malformed {
                index: 0,
                key: "alias",
                reason: "must be 1-64 characters of A-Z a-z 0-9 . _ -",
            },
        ),
        (
            "[[instances]]\nid = \"ins_XYZ\"\nalias = \"a\"\nproduct = \"jira\"\nbase_url = \"https://x\"",
            InstancesError::Malformed {
                index: 0,
                key: "id",
                reason: "must be \"ins_\" + 32 lowercase hex",
            },
        ),
        (
            "[[instances]]\nalias = \"a\"\nproduct = \"jira\"",
            InstancesError::Malformed {
                index: 0,
                key: "base_url",
                reason: "is required",
            },
        ),
        (
            "[[instances]]\nalias = \"a\"\nproduct = \"jira\"\nbase_url = \"https://x\"\nproxy = \"u:p@h:1\"",
            InstancesError::Malformed {
                index: 0,
                key: "proxy",
                reason: "must be \"direct\" or \"host:port\"",
            },
        ),
        (
            "[[instances]]\nalias = \"a\"\nproduct = \"jira\"\nbase_url = \"https://x\"\n[[instances]]\nalias = \"a\"\nproduct = \"confluence\"\nbase_url = \"https://y\"",
            InstancesError::DuplicateAlias { index: 1 },
        ),
        (
            "[[instances]]\nalias = \"a\"\nproduct = \"jira\"\nbase_url = \"https://x\"\ndefault = true\n[[instances]]\nalias = \"b\"\nproduct = \"jira\"\nbase_url = \"https://y\"\ndefault = true",
            InstancesError::DuplicateDefault { index: 1 },
        ),
    ];
    for (body, want) in cases {
        let path = write(dir.path(), &format!("schema_version = 1\n{body}\n"))?;
        let got = instances(&load_config(&path)?);
        assert_eq!(got.as_ref().err(), Some(want), "{body}");
        let text = got.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            !text.contains("bitbucket") && !text.contains("u:p@"),
            "{text}"
        );
    }
    Ok(())
}

#[test]
fn ensure_ids_writes_ids_only_when_writable() -> TestResult {
    let dir = tempfile::tempdir()?;
    let body = "[[instances]]\nalias = \"a\"\nproduct = \"jira\"\nbase_url = \"https://x\"\n";
    let path = write(
        dir.path(),
        &format!("# keep me\nschema_version = 1\n{body}"),
    )?;
    ensure_ids(&path, &load_config(&path)?)?;
    let list = instances(&load_config(&path)?)?;
    let id = list
        .first()
        .and_then(|i| i.id.clone())
        .ok_or("no id written")?;
    assert!(is_valid_instance_id(&id), "{id}");
    assert!(fs::read_to_string(&path)?.contains("# keep me"));

    // Idempotent: a second run leaves the file byte-identical.
    let before = fs::read(&path)?;
    ensure_ids(&path, &load_config(&path)?)?;
    assert_eq!(fs::read(&path)?, before);

    // A newer (read-only) file is never written.
    let newer = write(dir.path(), &format!("schema_version = 99\n{body}"))?;
    let before = fs::read(&newer)?;
    let state = load_config(&newer)?;
    assert!(matches!(state, ConfigState::ReadOnly { .. }));
    ensure_ids(&newer, &state)?;
    assert_eq!(fs::read(&newer)?, before);
    assert_eq!(instances(&state)?.first().map(|i| i.id.clone()), Some(None));
    Ok(())
}

#[test]
fn add_instance_and_set_base_url_roundtrip() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(CONFIG_FILE_NAME);
    let inst = InstanceConfig {
        id: Some(ID_A.to_owned()),
        alias: "jira-main".to_owned(),
        product: Product::Jira,
        base_url_raw: "https://jira.corp.example".to_owned(),
        ca_bundle: None,
        proxy: ProxySetting::Os,
        is_default: true,
    };
    add_instance(&path, &inst)?;
    assert_eq!(instances(&load_config(&path)?)?, vec![inst.clone()]);

    assert!(set_base_url(&path, ID_A, "https://jira2.corp.example")?);
    assert!(!set_base_url(
        &path,
        "ins_ffffffffffffffffffffffffffffffff",
        "https://x"
    )?);
    let list = instances(&load_config(&path)?)?;
    assert_eq!(
        list.first().map(|i| i.base_url_raw.as_str()),
        Some("https://jira2.corp.example")
    );

    let newer = write(dir.path(), "schema_version = 99\n")?;
    assert!(matches!(
        add_instance(&newer, &inst),
        Err(ConfigWriteError::ReadOnly)
    ));
    Ok(())
}

#[test]
fn routing_default_single_and_wrong_product() -> TestResult {
    use atlas_duck_core::instances::{InstanceTable, RouteError};
    let dir = tempfile::tempdir()?;
    let entry = |alias: &str, product: &str, default: bool| {
        format!(
            "[[instances]]\nid = \"ins_{:0>32}\"\nalias = \"{alias}\"\nproduct = \"{product}\"\nbase_url = \"https://{alias}.example\"\ndefault = {default}\n",
            alias.len()
        )
    };
    let table = |body: String| -> Result<InstanceTable, Box<dyn std::error::Error>> {
        let path = write(dir.path(), &format!("schema_version = 1\n{body}"))?;
        Ok(InstanceTable::from_config(&load_config(&path)?))
    };
    // One Jira instance without `default`: it is the default (plan decision).
    let t = table(entry("j", "jira", false))?;
    assert_eq!(
        t.resolve(Product::Jira, None).map(|i| i.alias.as_str()),
        Ok("j")
    );
    assert_eq!(
        t.resolve(Product::Confluence, None).err(),
        Some(RouteError::NoInstance)
    );
    // Two without a default: none (PD-01); naming one works.
    let t = table(format!(
        "{}{}",
        entry("j1", "jira", false),
        entry("j22", "jira", false)
    ))?;
    assert_eq!(
        t.resolve(Product::Jira, None).err(),
        Some(RouteError::NoInstance)
    );
    assert_eq!(
        t.resolve(Product::Jira, Some("j22"))
            .map(|i| i.alias.as_str()),
        Ok("j22")
    );
    // The marked default wins; a Confluence alias for a Jira op is refused.
    let t = table(format!(
        "{}{}{}",
        entry("j1", "jira", false),
        entry("j22", "jira", true),
        entry("w", "confluence", false)
    ))?;
    assert_eq!(
        t.resolve(Product::Jira, None).map(|i| i.alias.as_str()),
        Ok("j22")
    );
    assert_eq!(
        t.resolve(Product::Jira, Some("w")).err(),
        Some(RouteError::WrongProduct)
    );
    assert_eq!(
        t.resolve(Product::Jira, Some("x")).err(),
        Some(RouteError::UnknownAlias)
    );
    // An unreadable list refuses everything.
    let t = table("[[instances]]\nalias = \"bad alias\"\n".to_owned())?;
    assert_eq!(
        t.resolve(Product::Jira, None).err(),
        Some(RouteError::ConfigUnreadable)
    );
    Ok(())
}

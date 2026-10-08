use atlas_duck_ipc::jcs::{JcsError, to_jcs_vec};
use serde_json::Value;

fn jcs(input: &str) -> String {
    let v: Value = serde_json::from_str(input).unwrap();
    String::from_utf8(to_jcs_vec(&v).unwrap()).unwrap()
}

#[test]
fn jcs_rfc8785_example() {
    let input = r#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}"#;
    assert_eq!(
        jcs(input),
        r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#
    );
}

#[test]
fn jcs_utf16_key_order() {
    let input = r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}"#;
    let out = jcs(input);
    // JCS escapes U+000D as `\r` but writes U+0080 raw.
    let keys = [
        "\"\\r\"",
        "\"1\"",
        "\"\u{80}\"",
        "\"ö\"",
        "\"€\"",
        "\"😀\"",
        "\"\u{fb33}\"",
    ];
    let mut last = 0;
    for k in keys {
        let at = out
            .find(&format!("{k}:"))
            .unwrap_or_else(|| panic!("key {k} missing in {out}"));
        assert!(at >= last, "key {k} out of order in {out}");
        last = at;
    }
}

#[test]
fn jcs_bmp_edge_order() {
    let out = jcs(r#"{"\uffff":"a","\ud800\udc00":"b"}"#);
    assert_eq!(out, "{\"\u{10000}\":\"b\",\"\u{ffff}\":\"a\"}");
}

#[test]
fn jcs_numbers() {
    for (input, want) in [
        ("0", "0"),
        ("-0.0", "0"),
        ("1e21", "1e+21"),
        ("1e20", "100000000000000000000"),
        ("5e-324", "5e-324"),
        ("1.7976931348623157e308", "1.7976931348623157e+308"),
        ("0.000001", "0.000001"),
        ("1e-7", "1e-7"),
        ("-1.5", "-1.5"),
        ("9007199254740991", "9007199254740991"),
    ] {
        assert_eq!(jcs(input), want, "input {input}");
    }
}

#[test]
fn jcs_rejects_unsafe_integers() {
    for input in [
        "9007199254740992",
        "-9007199254740992",
        "18446744073709551615",
        "[1,[9007199254740992]]",
        r#"{"a":{"b":[-9007199254740992]}}"#,
        r#"[{"n":18446744073709551615}]"#,
    ] {
        let v: Value = serde_json::from_str(input).unwrap();
        assert_eq!(
            to_jcs_vec(&v),
            Err(JcsError::IntegerOutOfRange),
            "input {input}"
        );
    }
}

#[test]
fn jcs_is_idempotent() {
    for input in [
        r#"{"b":[1,2.5,{"z":null,"a":"x"}],"a":true}"#,
        r#"{"\u00f6":{"\u20ac":[1e21,1e-7,-0.0]},"k":"\u0001\n"}"#,
        r#"[{"y":{"x":{"w":[]}},"a":{}},"s",0.1]"#,
    ] {
        let v: Value = serde_json::from_str(input).unwrap();
        let once = to_jcs_vec(&v).unwrap();
        let again = to_jcs_vec(&serde_json::from_slice(&once).unwrap()).unwrap();
        assert_eq!(once, again);
    }
}

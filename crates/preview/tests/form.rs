use atlas_duck_preview::form::{AllowedValues, EditForm, EditInput, InputKind};
use serde_json::{Value, json};

#[test]
fn edit_form_serializes_kinds() -> Result<(), serde_json::Error> {
    let kinds = [
        (InputKind::Text, json!({"kind": "text"})),
        (InputKind::LongText, json!({"kind": "long_text"})),
        (InputKind::Integer, json!({"kind": "integer"})),
        (InputKind::Boolean, json!({"kind": "boolean"})),
        (InputKind::Json, json!({"kind": "json"})),
        (
            InputKind::choice(vec!["A".to_owned(), "B".to_owned()]),
            json!({"kind": "choice", "allowed_values": ["A", "B"]}),
        ),
    ];
    for (kind, want) in kinds {
        assert_eq!(serde_json::to_value(&kind)?, want);
    }
    let form = EditForm {
        inputs: vec![EditInput {
            path: "fields.customfield_10200".to_owned(),
            label: "Team".to_owned(),
            kind: InputKind::Text,
            read_only: false,
            required: true,
            pre_added: true,
            value: Value::Null,
        }],
    };
    assert_eq!(
        serde_json::to_value(&form)?,
        json!({"inputs": [{
            "path": "fields.customfield_10200", "label": "Team",
            "kind": {"kind": "text"}, "read_only": false, "required": true,
            "pre_added": true, "value": null
        }]})
    );
    Ok(())
}

#[test]
fn choice_allowed_values_capped_at_10() {
    let values: Vec<String> = (0..25).map(|i| format!("v{i}")).collect();
    let InputKind::Choice(allowed) = InputKind::choice(values.clone()) else {
        panic!("choice() must build Choice");
    };
    let allowed_values = allowed.as_slice();
    assert_eq!(allowed_values.len(), 10);
    assert_eq!(allowed_values.first().map(String::as_str), Some("v0"));
    assert_eq!(allowed_values.last().map(String::as_str), Some("v9"));
    // the only other way to build one goes through the same cap, and the wire shape shows it
    let direct = InputKind::Choice(AllowedValues::new(values));
    assert_eq!(
        direct,
        InputKind::choice((0..25).map(|i| format!("v{i}")).collect())
    );
    let wire = serde_json::to_value(&direct).unwrap_or(Value::Null);
    assert_eq!(wire["allowed_values"].as_array().map(Vec::len), Some(10));
}

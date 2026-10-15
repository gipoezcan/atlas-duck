use atlas_duck_preview::form::{AllowedValues, ChoiceRefusal, EditForm, EditInput, InputKind};
use serde_json::{Value, json};

#[test]
fn edit_form_serializes_kinds() -> Result<(), serde_json::Error> {
    let kinds = [
        (InputKind::Text, json!({"kind": "text"})),
        (InputKind::LongText, json!({"kind": "long_text"})),
        (InputKind::Integer, json!({"kind": "integer"})),
        (InputKind::Number, json!({"kind": "number"})),
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

/// T16 (M5 M-12): a multi-pick says so on the wire (`multiple`), a single pick does not.
#[test]
fn multi_choice_is_marked_on_the_wire() -> Result<(), serde_json::Error> {
    let pairs = vec![("UI".to_owned(), Some(json!([{"id": "1"}])))];
    let multi = InputKind::multi_choice_with_wire(pairs.clone());
    assert_eq!(
        serde_json::to_value(&multi)?,
        json!({"kind": "choice", "allowed_values": ["UI"], "multiple": true})
    );
    let single = InputKind::choice_with_wire(pairs);
    assert_eq!(
        serde_json::to_value(&single)?,
        json!({"kind": "choice", "allowed_values": ["UI"]})
    );
    let (InputKind::Choice(m), InputKind::Choice(s)) = (multi, single) else {
        panic!("both build Choice");
    };
    assert!(m.is_multiple() && !s.is_multiple());
    // The labels map as before.
    assert_eq!(m.wire_for("UI"), Ok(&json!([{"id": "1"}])));
    Ok(())
}

/// T12 review I1: a `Choice` carries (label, wire value) pairs; the UI sees and sends back the
/// labels only, core maps the picked label to its wire value.
#[test]
fn choice_wire_values_stay_private() -> Result<(), serde_json::Error> {
    let kind = InputKind::choice_with_wire(vec![
        ("Platform".to_owned(), Some(json!({"id": "10400"}))),
        ("Ops".to_owned(), Some(json!({"value": "Ops"}))),
        ("Legacy".to_owned(), None),
    ]);
    assert_eq!(
        serde_json::to_value(&kind)?,
        json!({"kind": "choice", "allowed_values": ["Platform", "Ops", "Legacy"]})
    );
    let InputKind::Choice(allowed) = kind else {
        panic!("choice_with_wire() must build Choice");
    };
    assert_eq!(allowed.wire_for("Platform"), Ok(&json!({"id": "10400"})));
    assert_eq!(allowed.wire_for("Ops"), Ok(&json!({"value": "Ops"})));
    assert_eq!(allowed.wire_for("Legacy"), Err(ChoiceRefusal::NoWireValue));
    assert_eq!(allowed.wire_for("Nope"), Err(ChoiceRefusal::NotListed));
    // A label-only `Choice` has no wire values: every pick is refused.
    let InputKind::Choice(plain) = InputKind::choice(vec!["A".to_owned()]) else {
        panic!("choice() must build Choice");
    };
    assert_eq!(plain.wire_for("A"), Err(ChoiceRefusal::NoWireValue));
    Ok(())
}

/// Two entries shown with the same label (cut names) cannot be told apart: a pick is refused.
#[test]
fn choice_same_label_twice_is_ambiguous() {
    let InputKind::Choice(allowed) = InputKind::choice_with_wire(vec![
        ("A…".to_owned(), Some(json!({"id": "1"}))),
        ("A…".to_owned(), Some(json!({"id": "2"}))),
    ]) else {
        panic!("choice_with_wire() must build Choice");
    };
    assert_eq!(allowed.wire_for("A…"), Err(ChoiceRefusal::Ambiguous));
}

#[test]
fn choice_with_wire_capped_at_10() {
    let pairs: Vec<(String, Option<Value>)> = (0..25)
        .map(|i| (format!("v{i}"), Some(json!({"id": i.to_string()}))))
        .collect();
    let InputKind::Choice(allowed) = InputKind::choice_with_wire(pairs) else {
        panic!("choice_with_wire() must build Choice");
    };
    assert_eq!(allowed.as_slice().len(), 10);
    assert_eq!(allowed.wire_for("v9"), Ok(&json!({"id": "9"})));
    assert_eq!(allowed.wire_for("v10"), Err(ChoiceRefusal::NotListed));
}

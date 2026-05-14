#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use crate::fuzzer::payloads::{ALL_CATEGORIES, INTEGER_BOUNDARIES};

/// A single generated test case — one argument object to pass to a tool call.
#[derive(Debug, Clone)]
pub struct FuzzCase {
    /// Short label describing the mutation, e.g. `"path:path_traversal:0"` or `"missing:path"`.
    pub label: String,
    /// Complete argument object ready to pass to `Session::call_tool`.
    pub args: Value,
}

pub struct ArgumentFuzzer;

impl ArgumentFuzzer {
    /// Generate fuzzing argument sets from a tool's `inputSchema`.
    ///
    /// Each returned `FuzzCase` contains a complete argument object with all fields
    /// populated — one field mutated per case, others filled with type-appropriate defaults.
    pub fn fuzz(schema: &Value) -> Vec<FuzzCase> {
        let mut cases = Vec::new();

        cases.push(FuzzCase {
            label: "empty_args".into(),
            args: json!({}),
        });
        cases.push(FuzzCase {
            label: "null_args".into(),
            args: Value::Null,
        });

        let Some(props) = schema.get("properties").and_then(|p| p.as_object()) else {
            return cases;
        };

        let required: HashSet<&str> = schema
            .get("required")
            .and_then(|r| r.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        // Type-appropriate defaults for every property (used to fill non-mutated fields).
        let defaults: HashMap<String, Value> = props
            .iter()
            .map(|(k, v)| (k.clone(), default_value(v)))
            .collect();

        // Per-property mutations: one mutation value applied per field at a time.
        for (field_name, field_schema) in props {
            let type_str = field_type(field_schema);
            for mutation in field_mutations(type_str, field_schema) {
                let mut args = defaults.clone();
                args.insert(field_name.clone(), mutation.value);
                cases.push(FuzzCase {
                    label: format!("{}:{}", field_name, mutation.label),
                    args: Value::Object(args.into_iter().collect()),
                });
            }
        }

        // Required field omissions: drop each required field individually.
        for req in &required {
            let args: serde_json::Map<_, _> = defaults
                .iter()
                .filter(|(k, _)| k.as_str() != *req)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            cases.push(FuzzCase {
                label: format!("missing_required:{req}"),
                args: Value::Object(args),
            });
        }

        // Extra unknown field — tests whether servers reject unexpected input.
        if !props.is_empty() {
            let mut extra: serde_json::Map<_, _> = defaults
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            extra.insert("__fuzz_unknown_field__".into(), json!("unexpected_value"));
            cases.push(FuzzCase {
                label: "extra_unknown_field".into(),
                args: Value::Object(extra),
            });
        }

        cases
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

struct Mutation {
    label: String,
    value: Value,
}

fn mutation(label: impl Into<String>, value: Value) -> Mutation {
    Mutation {
        label: label.into(),
        value,
    }
}

fn field_type(schema: &Value) -> &str {
    schema
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("string")
}

fn field_mutations(type_str: &str, schema: &Value) -> Vec<Mutation> {
    match type_str {
        "string" => string_mutations(schema),
        "integer" | "number" => integer_mutations(),
        "boolean" => boolean_mutations(),
        "array" => array_mutations(),
        "object" => object_mutations(),
        _ => vec![
            mutation("null", Value::Null),
            mutation("empty_string", json!("")),
        ],
    }
}

fn string_mutations(schema: &Value) -> Vec<Mutation> {
    let mut cases = vec![
        mutation("empty", json!("")),
        mutation("single_space", json!(" ")),
        mutation("null_byte", json!("\0")),
        mutation("unicode_rtl_override", json!("\u{202E}attack")),
        mutation("unicode_bom", json!("\u{FEFF}payload")),
        mutation("long_256", json!("A".repeat(256))),
        mutation("long_64k", json!("A".repeat(65536))),
        mutation("null_value", Value::Null),
        mutation("integer_value", json!(0)),
        mutation("array_value", json!([])),
    ];

    // Honour `enum` if present — test each declared value plus one invalid.
    if let Some(enum_vals) = schema.get("enum").and_then(|e| e.as_array()) {
        for (i, v) in enum_vals.iter().enumerate() {
            cases.push(mutation(format!("enum_valid:{i}"), v.clone()));
        }
        cases.push(mutation(
            "enum_invalid",
            json!("__fuzz_invalid_enum_value__"),
        ));
    }

    // Injection payloads from the library — applied to every string field.
    for cat in ALL_CATEGORIES {
        for (i, payload) in cat.payloads.iter().enumerate() {
            cases.push(mutation(format!("{}:{}", cat.name, i), json!(payload)));
        }
    }

    cases
}

fn integer_mutations() -> Vec<Mutation> {
    let mut cases: Vec<Mutation> = INTEGER_BOUNDARIES
        .iter()
        .map(|&n| mutation(format!("int:{n}"), json!(n)))
        .collect();
    cases.extend([
        mutation("float", json!(1.5)),
        mutation("nan_string", json!("NaN")),
        mutation("inf_string", json!("Infinity")),
        mutation("null_value", Value::Null),
        mutation("string_value", json!("not_a_number")),
        mutation("boolean_value", json!(true)),
    ]);
    cases
}

fn boolean_mutations() -> Vec<Mutation> {
    vec![
        mutation("true", json!(true)),
        mutation("false", json!(false)),
        mutation("string_true", json!("true")),
        mutation("string_false", json!("false")),
        mutation("integer_1", json!(1)),
        mutation("integer_0", json!(0)),
        mutation("null_value", Value::Null),
    ]
}

fn array_mutations() -> Vec<Mutation> {
    vec![
        mutation("empty", json!([])),
        mutation("single_null", json!([null])),
        mutation("large", Value::Array((0..1000).map(|i| json!(i)).collect())),
        mutation("deeply_nested", json!([[[[[]]]]])),
        mutation("null_value", Value::Null),
        mutation("string_value", json!("not_an_array")),
    ]
}

fn object_mutations() -> Vec<Mutation> {
    vec![
        mutation("empty", json!({})),
        mutation("extra_field", json!({"__fuzz_extra__": "unexpected"})),
        mutation("deeply_nested", json!({"a": {"b": {"c": {"d": "deep"}}}})),
        mutation("null_value", Value::Null),
        mutation("string_value", json!("not_an_object")),
        mutation("array_value", json!([])),
    ]
}

/// Returns a type-appropriate default value for a JSON Schema field definition.
fn default_value(schema: &Value) -> Value {
    // Prefer the first enum value if present.
    if let Some(first) = schema
        .get("enum")
        .and_then(|e| e.as_array())
        .and_then(|a| a.first())
    {
        return first.clone();
    }
    match field_type(schema) {
        "string" => json!("fuzz_default"),
        "integer" | "number" => json!(0),
        "boolean" => json!(false),
        "array" => json!([]),
        "object" => json!({}),
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(json: Value) -> Value {
        json
    }

    #[test]
    fn empty_schema_returns_at_least_empty_and_null_cases() {
        let cases = ArgumentFuzzer::fuzz(&json!({"type": "object"}));
        assert!(cases.iter().any(|c| c.label == "empty_args"));
        assert!(cases.iter().any(|c| c.label == "null_args"));
    }

    #[test]
    fn string_field_includes_path_traversal() {
        let cases = ArgumentFuzzer::fuzz(&json!({
            "type": "object",
            "properties": {"path": {"type": "string"}}
        }));
        assert!(cases.iter().any(|c| {
            c.label.contains("path_traversal")
                && c.args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s.contains(".."))
        }));
    }

    #[test]
    fn string_field_includes_command_injection() {
        let cases = ArgumentFuzzer::fuzz(&json!({
            "type": "object",
            "properties": {"cmd": {"type": "string"}}
        }));
        assert!(cases.iter().any(|c| c.label.contains("command_injection")));
    }

    #[test]
    fn string_field_includes_long_string() {
        let cases = ArgumentFuzzer::fuzz(&json!({
            "type": "object",
            "properties": {"name": {"type": "string"}}
        }));
        let long = cases.iter().find(|c| c.label == "name:long_64k").unwrap();
        assert_eq!(
            long.args
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap()
                .len(),
            65536
        );
    }

    #[test]
    fn integer_field_includes_boundary_values() {
        let cases = ArgumentFuzzer::fuzz(&json!({
            "type": "object",
            "properties": {"size": {"type": "integer"}}
        }));
        let labels: Vec<_> = cases.iter().map(|c| c.label.as_str()).collect();
        assert!(labels.iter().any(|l| l.contains("int:0")));
        assert!(labels.iter().any(|l| l.contains("int:-1")));
        assert!(labels.iter().any(|l| l.contains(&i64::MAX.to_string())));
        assert!(labels.iter().any(|l| l.contains(&i64::MIN.to_string())));
    }

    #[test]
    fn boolean_field_includes_type_confusion() {
        let cases = ArgumentFuzzer::fuzz(&json!({
            "type": "object",
            "properties": {"flag": {"type": "boolean"}}
        }));
        assert!(cases.iter().any(|c| c.label == "flag:string_true"
            && c.args.get("flag").and_then(|v| v.as_str()) == Some("true")));
        assert!(cases
            .iter()
            .any(|c| c.label == "flag:null_value" && c.args.get("flag") == Some(&Value::Null)));
    }

    #[test]
    fn required_field_produces_omission_cases() {
        let cases = ArgumentFuzzer::fuzz(&json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "mode": {"type": "string"}
            },
            "required": ["path"]
        }));
        assert!(cases
            .iter()
            .any(|c| c.label == "missing_required:path" && c.args.get("path").is_none()));
    }

    #[test]
    fn generates_extra_unknown_field_case() {
        let cases = ArgumentFuzzer::fuzz(&json!({
            "type": "object",
            "properties": {"name": {"type": "string"}}
        }));
        let extra = cases
            .iter()
            .find(|c| c.label == "extra_unknown_field")
            .unwrap();
        assert!(extra.args.get("__fuzz_unknown_field__").is_some());
    }

    #[test]
    fn non_mutated_fields_filled_with_defaults() {
        let cases = ArgumentFuzzer::fuzz(&json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "count": {"type": "integer"}
            }
        }));
        // When mutating `path`, `count` should have its default (0).
        let path_case = cases.iter().find(|c| c.label.starts_with("path:")).unwrap();
        assert_eq!(
            path_case.args.get("count").and_then(|v| v.as_i64()),
            Some(0)
        );
    }

    #[test]
    fn enum_field_generates_valid_and_invalid_values() {
        let cases = ArgumentFuzzer::fuzz(&json!({
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["read", "write", "append"]
                }
            }
        }));
        assert!(cases.iter().any(|c| c.label == "mode:enum_valid:0"
            && c.args.get("mode").and_then(|v| v.as_str()) == Some("read")));
        assert!(cases.iter().any(|c| c.label == "mode:enum_invalid"));
    }

    #[test]
    fn all_fuzz_cases_args_are_valid_json() {
        let cases = ArgumentFuzzer::fuzz(&json!({
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "count": {"type": "integer"},
                "recursive": {"type": "boolean"}
            },
            "required": ["path"]
        }));
        for case in &cases {
            // Round-trip through serde must not panic.
            let s = serde_json::to_string(&case.args).unwrap();
            serde_json::from_str::<Value>(&s).unwrap();
        }
    }

    #[test]
    fn schema_with_no_properties_returns_minimal_cases() {
        let cases = ArgumentFuzzer::fuzz(&json!({"type": "object"}));
        assert!(cases.iter().any(|c| c.label == "empty_args"));
        assert!(cases.iter().any(|c| c.label == "null_args"));
    }

    #[test]
    fn fuzz_case_count_is_reasonable() {
        // A schema with 3 string fields should not explode combinatorially.
        let cases = ArgumentFuzzer::fuzz(&json!({
            "type": "object",
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "string"},
                "c": {"type": "string"}
            },
            "required": ["a"]
        }));
        // 2 base + 3 * string_mutations + 1 required omission + 1 extra + 1 null
        // string_mutations ≈ 10 base + ~42 payload = ~52 per field → 3 * 52 = 156 + 5 ≈ 161
        assert!(cases.len() > 50);
        assert!(cases.len() < 1000, "too many cases: {}", cases.len());
    }
}

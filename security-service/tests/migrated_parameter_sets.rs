use std::{fs, path::PathBuf};

use lattice_security::{ExactDecimal, ParameterSetFile, PositiveInteger, Validate};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate is inside the repository")
        .to_path_buf()
}

fn assert_canonical_numeric_strings(value: &serde_json::Value, path: &str) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                let field_path = format!("{path}.{key}");
                if matches!(key.as_str(), "modulus" | "ciphertext_modulus") {
                    let source = value.as_str().expect("integer field is a string");
                    assert_eq!(
                        PositiveInteger::new(source)
                            .expect("valid positive integer")
                            .as_str(),
                        source,
                        "{field_path} must be canonical"
                    );
                } else if matches!(key.as_str(), "standard_deviation" | "length_bound") {
                    let source = value.as_str().expect("decimal field is a string");
                    assert_eq!(
                        ExactDecimal::new(source)
                            .expect("valid exact decimal")
                            .as_str(),
                        source,
                        "{field_path} must be canonical"
                    );
                }
                assert_canonical_numeric_strings(value, &field_path);
            }
        }
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                assert_canonical_numeric_strings(value, &format!("{path}[{index}]"));
            }
        }
        _ => {}
    }
}

#[test]
fn migrated_parameter_sets_follow_the_public_contract() {
    let directory = repository_root().join("parameter-sets");
    let mut paths = fs::read_dir(&directory)
        .expect("parameter-sets directory exists")
        .map(|entry| entry.expect("read directory entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".lattice-params.json"))
        })
        .collect::<Vec<_>>();
    paths.sort();

    assert!(
        !paths.is_empty(),
        "at least one migrated parameter set exists"
    );

    for path in paths {
        let source = fs::read_to_string(&path).expect("read migrated parameter set");
        let input: serde_json::Value = serde_json::from_str(&source)
            .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()));
        let parameter_set: ParameterSetFile = serde_json::from_value(input.clone())
            .unwrap_or_else(|error| panic!("{} violates the Rust shape: {error}", path.display()));
        parameter_set.validate().unwrap_or_else(|error| {
            panic!("{} fails semantic validation: {error}", path.display())
        });
        let round_trip: ParameterSetFile = serde_json::from_value(
            serde_json::to_value(&parameter_set).expect("serialize parameter set"),
        )
        .expect("deserialize serialized parameter set");
        assert_eq!(
            round_trip,
            parameter_set,
            "{} must round-trip",
            path.display()
        );
        assert_canonical_numeric_strings(&input, "$input");
    }
}

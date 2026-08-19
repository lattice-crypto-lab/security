use std::{env, fs, path::PathBuf, process::ExitCode};

use lattice_security::{ParameterSetFile, SecurityReportFile};
use schemars::{JsonSchema, schema_for};
use serde::Serialize;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("schema generation failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let check = env::args().skip(1).any(|argument| argument == "--check");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("security-service has no repository parent")?
        .to_path_buf();
    let schema_dir = root.join("schemas");
    if !check {
        fs::create_dir_all(&schema_dir).map_err(|error| error.to_string())?;
    }

    process::<ParameterSetFile>(&schema_dir, "parameter-set-v1.schema.json", check)?;
    process::<SecurityReportFile>(&schema_dir, "security-report-v1.schema.json", check)?;
    Ok(())
}

fn process<T: JsonSchema + Serialize>(
    directory: &std::path::Path,
    name: &str,
    check: bool,
) -> Result<(), String> {
    let schema = schema_for!(T);
    let mut generated = serde_json::to_string_pretty(&schema).map_err(|error| error.to_string())?;
    generated.push('\n');
    let path = directory.join(name);
    if check {
        let existing = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if existing != generated {
            return Err(format!("{} is out of date", path.display()));
        }
    } else {
        fs::write(&path, generated)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    }
    Ok(())
}

//! Small HTTP client for scripting the same use-cases exposed by the Web UI.

use std::{env, fs};

use reqwest::{Client, Method, Url};
use serde_json::Value;

pub async fn run(arguments: impl IntoIterator<Item = String>) -> Result<(), String> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let command = arguments.next().ok_or_else(usage)?;
    let base =
        env::var("LATTICE_SECURITY_URL").unwrap_or_else(|_| "http://127.0.0.1:8080/".to_owned());
    let base =
        Url::parse(&base).map_err(|error| format!("invalid LATTICE_SECURITY_URL: {error}"))?;
    let token = env::var("LATTICE_SECURITY_API_TOKEN")
        .ok()
        .filter(|value| !value.is_empty());
    let client = Client::new();

    let (method, path, body) = match command.as_str() {
        "health" => (Method::GET, "healthz".to_owned(), None),
        "batches" => (Method::GET, "v1/batches".to_owned(), None),
        "batch" => (
            Method::GET,
            resource("v1/batches", required(&mut arguments, "batch id")?),
            None,
        ),
        "cancel" => (
            Method::POST,
            resource_suffix(
                "v1/batches",
                required(&mut arguments, "batch id")?,
                "cancel",
            ),
            None,
        ),
        "rerun" => (
            Method::POST,
            resource_suffix("v1/batches", required(&mut arguments, "batch id")?, "rerun"),
            None,
        ),
        "delete-batch" => (
            Method::DELETE,
            resource("v1/batches", required(&mut arguments, "batch id")?),
            None,
        ),
        "report" => (
            Method::GET,
            resource_suffix(
                "v1/batches",
                required(&mut arguments, "batch id")?,
                "export",
            ),
            None,
        ),
        "estimate" => (
            Method::POST,
            "v1/estimates".to_owned(),
            Some(read_json(required(&mut arguments, "request file")?)?),
        ),
        "parameter-sets" => (Method::GET, "v1/parameter-sets".to_owned(), None),
        "parameter-set" => (
            Method::GET,
            resource(
                "v1/parameter-sets",
                required(&mut arguments, "parameter-set id")?,
            ),
            None,
        ),
        "delete-parameter-set" => (
            Method::DELETE,
            resource(
                "v1/parameter-sets",
                required(&mut arguments, "parameter-set id")?,
            ),
            None,
        ),
        "import" => {
            let file = required(&mut arguments, "parameter-set file")?;
            let replace = arguments.any(|value| value == "--replace");
            let path = format!(
                "v1/parameter-sets/import?conflict={}",
                if replace { "replace" } else { "reject" }
            );
            (Method::POST, path, Some(read_json(file)?))
        }
        _ => return Err(usage()),
    };
    if arguments.next().is_some() {
        return Err(usage());
    }

    let url = base.join(&path).map_err(|error| error.to_string())?;
    let mut request = client.request(method, url);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.map_err(|error| error.to_string())?;
    let status = response.status();
    let bytes = response.bytes().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!(
            "HTTP {status}: {}",
            String::from_utf8_lossy(&bytes)
        ));
    }
    if !bytes.is_empty() {
        let value: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?
        );
    }
    Ok(())
}

fn required(arguments: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("missing {name}\n{}", usage()))
}

fn resource(prefix: &str, id: String) -> String {
    format!("{prefix}/{}", encode(&id))
}
fn resource_suffix(prefix: &str, id: String, suffix: &str) -> String {
    format!("{prefix}/{}/{suffix}", encode(&id))
}
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}
fn read_json(path: String) -> Result<Value, String> {
    let text = fs::read_to_string(&path).map_err(|error| format!("cannot read {path}: {error}"))?;
    serde_json::from_str(&text).map_err(|error| format!("invalid JSON in {path}: {error}"))
}
fn usage() -> String {
    "usage: lattice-security-cli <health|batches|batch ID|cancel ID|rerun ID|delete-batch ID|report ID|estimate FILE|parameter-sets|parameter-set ID|delete-parameter-set ID|import FILE [--replace]>".to_owned()
}

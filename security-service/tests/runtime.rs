use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode, header},
    routing::{get, post},
};
use lattice_security::{
    EstimateMode, EstimateRequest, ExactDecimal, ParameterSetFile, SlowAttackPolicy, SweepAxis,
    SweepRequest, api,
    database::Database,
    service::{AppConfig, AppState},
    sweep,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

#[derive(Clone)]
struct MockState {
    calls: Arc<AtomicUsize>,
    slow_delay: Duration,
    security_bits: &'static str,
}

struct Harness {
    app: Router,
    state: Arc<AppState>,
    calls: Arc<AtomicUsize>,
    _directory: TempDir,
    worker: tokio::task::JoinHandle<()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn estimate_is_accepted_then_fully_cached_and_supports_etag() {
    let harness = harness(Duration::ZERO, "96").await;
    let request = estimate_request("256");

    let first = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    assert_eq!(first.0, StatusCode::ACCEPTED);
    let batch_id = first.1["batch_id"].as_str().unwrap().to_owned();
    let completed = wait_for_terminal(&harness.app, &batch_id).await;
    assert_eq!(completed["state"]["kind"], "completed");
    assert_eq!(
        completed["report"]["reports"][0]["summary"]["complete"],
        true
    );
    assert_eq!(harness.calls.load(Ordering::SeqCst), 2);

    let second = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    assert_eq!(second.0, StatusCode::OK);
    assert_eq!(second.1["state"]["kind"], "completed");
    assert_eq!(harness.calls.load(Ordering::SeqCst), 2);

    let revision = completed["revision"].as_u64().unwrap();
    let response = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/batches/{batch_id}"))
                .header(header::IF_NONE_MATCH, format!("\"{revision}\""))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn high_fast_estimate_cuts_off_slow_attacks_without_caching_them() {
    let harness = harness(Duration::from_secs(5), "192").await;
    let request = estimate_request("128");

    let first = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    assert_eq!(first.0, StatusCode::ACCEPTED);
    let batch_id = first.1["batch_id"].as_str().unwrap();
    let completed = wait_for_terminal(&harness.app, batch_id).await;
    assert_eq!(completed["state"]["kind"], "partial");
    let report = &completed["report"]["reports"][0];
    assert_eq!(report["summary"]["fast_estimate"], true);
    assert_eq!(report["summary"]["complete"], false);
    let attacks = report["attacks"].as_array().unwrap();
    for attack in ["arora_gb", "bkw"] {
        let result = attacks
            .iter()
            .find(|result| result["attack"] == attack)
            .unwrap();
        assert_eq!(result["outcome"]["kind"], "skipped");
    }

    let second = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    assert_eq!(second.0, StatusCode::ACCEPTED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rough_mode_uses_fast_cache_and_normal_mode_only_adds_slow_work() {
    let harness = harness(Duration::ZERO, "96").await;
    let mut rough = estimate_request("128");
    rough.mode = EstimateMode::Rough;
    rough.slow_attack_policy = None;

    let first = json_request(&harness.app, "POST", "/v1/estimates", &rough).await;
    assert_eq!(first.0, StatusCode::ACCEPTED);
    let batch_id = first.1["batch_id"].as_str().unwrap();
    let partial = wait_for_terminal(&harness.app, batch_id).await;
    assert_eq!(partial["state"]["kind"], "partial");
    assert_eq!(
        partial["report"]["reports"][0]["summary"]["fast_estimate"],
        true
    );
    assert_eq!(harness.calls.load(Ordering::SeqCst), 1);

    let cached_rough = json_request(&harness.app, "POST", "/v1/estimates", &rough).await;
    assert_eq!(cached_rough.0, StatusCode::OK);
    assert_eq!(cached_rough.1["state"]["kind"], "partial");
    assert_eq!(harness.calls.load(Ordering::SeqCst), 1);

    let normal = estimate_request("128");
    let submitted = json_request(&harness.app, "POST", "/v1/estimates", &normal).await;
    assert_eq!(submitted.0, StatusCode::ACCEPTED);
    let normal_batch_id = submitted.1["batch_id"].as_str().unwrap();
    assert_eq!(
        wait_for_terminal(&harness.app, normal_batch_id).await["state"]["kind"],
        "completed"
    );
    assert_eq!(harness.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_batches_share_the_per_attack_cache() {
    let harness = harness(Duration::from_millis(50), "96").await;
    let request = estimate_request("256");
    let (left, right) = tokio::join!(
        json_request(&harness.app, "POST", "/v1/estimates", &request),
        json_request(&harness.app, "POST", "/v1/estimates", &request),
    );
    assert_eq!(left.0, StatusCode::ACCEPTED);
    assert_eq!(right.0, StatusCode::ACCEPTED);
    let left_id = left.1["batch_id"].as_str().unwrap();
    let right_id = right.1["batch_id"].as_str().unwrap();
    assert_eq!(
        wait_for_terminal(&harness.app, left_id).await["state"]["kind"],
        "completed"
    );
    assert_eq!(
        wait_for_terminal(&harness.app, right_id).await["state"]["kind"],
        "completed"
    );
    assert_eq!(harness.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_is_idempotent_and_preserves_fast_results() {
    let harness = harness(Duration::from_secs(5), "96").await;
    let request = estimate_request("256");
    let submitted = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    let batch_id = submitted.1["batch_id"].as_str().unwrap();
    for _ in 0..100 {
        if harness.calls.load(Ordering::SeqCst) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let first = json_request::<Value>(
        &harness.app,
        "POST",
        &format!("/v1/batches/{batch_id}/cancel"),
        &Value::Null,
    )
    .await;
    assert_eq!(first.0, StatusCode::OK);
    let terminal = wait_for_terminal(&harness.app, batch_id).await;
    assert_eq!(terminal["state"]["kind"], "partial");
    assert_eq!(
        terminal["report"]["reports"][0]["summary"]["complete"],
        false
    );

    let second = json_request::<Value>(
        &harness.app,
        "POST",
        &format!("/v1/batches/{batch_id}/cancel"),
        &Value::Null,
    )
    .await;
    assert_eq!(second.0, StatusCode::OK);
    assert_eq!(second.1["state"]["kind"], "partial");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parameter_set_import_is_transactional_and_replace_creates_a_version() {
    let harness = harness(Duration::ZERO, "96").await;
    let parameter_set: ParameterSetFile = serde_json::from_str(include_str!(
        "../../fixtures/examples/demo-scheme.lattice-params.json"
    ))
    .unwrap();

    let created = json_request(
        &harness.app,
        "POST",
        "/v1/parameter-sets/import?conflict=reject",
        &parameter_set,
    )
    .await;
    assert_eq!(created.0, StatusCode::CREATED);
    assert_eq!(created.1["version"], 1);

    let conflict = json_request(
        &harness.app,
        "POST",
        "/v1/parameter-sets/import?conflict=reject",
        &parameter_set,
    )
    .await;
    assert_eq!(conflict.0, StatusCode::CONFLICT);

    let replaced = json_request(
        &harness.app,
        "POST",
        "/v1/parameter-sets/import?conflict=replace",
        &parameter_set,
    )
    .await;
    assert_eq!(replaced.0, StatusCode::CREATED);
    assert_eq!(replaced.1["version"], 2);

    let exported = json_request::<Value>(
        &harness.app,
        "GET",
        "/v1/parameter-sets/demo-scheme/export",
        &json!(null),
    )
    .await;
    assert_eq!(exported.0, StatusCode::OK);
    assert_eq!(exported.1["id"], "demo-scheme");
    assert_eq!(exported.1["cases"].as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_interrupts_an_attempt_and_retries_it_only_once() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("recovery.db");
    let database = Database::open(&path).unwrap();
    let batch = database
        .create_batch(estimate_request("256"))
        .await
        .unwrap();
    let job_id = batch.job_ids[0].clone();
    assert_eq!(
        database.claim_job(&job_id).await.unwrap().unwrap().attempts,
        1
    );
    drop(database);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let database = Database::open(&path).unwrap();
    assert_eq!(database.job(&job_id).await.unwrap().state.kind(), "queued");
    assert_eq!(
        database.claim_job(&job_id).await.unwrap().unwrap().attempts,
        2
    );
    drop(database);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let database = Database::open(&path).unwrap();
    assert_eq!(
        database.job(&job_id).await.unwrap().state.kind(),
        "interrupted"
    );
    assert_eq!(
        database
            .batch(&batch.batch_id, 1)
            .await
            .unwrap()
            .state
            .kind(),
        "interrupted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_token_and_json_errors_use_the_public_error_envelope() {
    let harness = harness_with_token(Duration::ZERO, "96", Some("secret".to_owned())).await;
    let unauthorized = json_request::<Value>(&harness.app, "GET", "/healthz", &Value::Null).await;
    assert_eq!(unauthorized.0, StatusCode::UNAUTHORIZED);
    assert_eq!(unauthorized.1["code"], "unauthorized");
    assert!(unauthorized.1["request_id"].as_str().is_some());

    let authorized = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header(header::AUTHORIZATION, "Bearer secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);

    let malformed = harness
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/estimates")
                .header(header::AUTHORIZATION, "Bearer secret")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&to_bytes(malformed.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(body["code"], "bad_request");
    assert!(body["request_id"].as_str().is_some());

    let browser_redirect = harness
        .app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(browser_redirect.status(), StatusCode::SEE_OTHER);
    assert_eq!(browser_redirect.headers()[header::LOCATION], "/login");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dashboard_renders_imported_sets_and_can_run_one_selected_case() {
    let harness = harness(Duration::ZERO, "96").await;
    let parameter_set: ParameterSetFile = serde_json::from_str(include_str!(
        "../../fixtures/examples/demo-scheme.lattice-params.json"
    ))
    .unwrap();
    assert_eq!(
        json_request(
            &harness.app,
            "POST",
            "/v1/parameter-sets/import?conflict=reject",
            &parameter_set,
        )
        .await
        .0,
        StatusCode::CREATED
    );

    let dashboard = text_request(&harness.app, "GET", "/", None).await;
    assert_eq!(dashboard.0, StatusCode::OK);
    assert!(dashboard.1.contains("Demo scheme"));
    assert!(dashboard.1.contains("htmx.org@2.0.10"));
    assert!(dashboard.1.contains("hx-get=\"/ui/batches\""));
    assert!(dashboard.1.contains("action=\"/ui/estimates\""));
    assert!(dashboard.1.contains("data-add-quick-case"));

    let detail = text_request(&harness.app, "GET", "/ui/parameter-sets/demo-scheme", None).await;
    assert_eq!(detail.0, StatusCode::OK);
    assert!(detail.1.contains("lwe-512"));
    assert!(detail.1.contains("ntru-1024"));

    let run = text_request(
        &harness.app,
        "POST",
        "/ui/parameter-sets/demo-scheme/run",
        Some("case_ids=lwe-512&timeout_seconds=10&decision_after_seconds=1&high_security_bits=256"),
    )
    .await;
    assert_eq!(run.0, StatusCode::SEE_OTHER);
    let batches = harness.state.database.list_batches(10, 0).await.unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(
        harness
            .state
            .database
            .batch_request(&batches[0].batch_id)
            .await
            .unwrap()
            .cases
            .len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quick_estimate_form_accepts_multiple_cases_in_rough_mode() {
    let harness = harness(Duration::ZERO, "96").await;
    let mut first = estimate_request("128").cases.remove(0);
    first.id = "quick-a".to_owned();
    first.name = "Quick A".to_owned();
    let mut second = first.clone();
    second.id = "quick-b".to_owned();
    second.name = "Quick B".to_owned();
    if let lattice_security::Problem::Lwe(problem) = &mut second.problem {
        problem.dimension = 512;
    }
    let cases_json = serde_json::to_string(&vec![first, second]).unwrap();
    let body = format!(
        "cases_json={cases_json}&mode=rough&timeout_seconds=10&decision_after_seconds=1&high_security_bits=128"
    );
    let submitted = text_request(&harness.app, "POST", "/ui/estimates", Some(&body)).await;
    assert_eq!(submitted.0, StatusCode::SEE_OTHER);

    let batches = harness.state.database.list_batches(10, 0).await.unwrap();
    assert_eq!(batches.len(), 1);
    let request = harness
        .state
        .database
        .batch_request(&batches[0].batch_id)
        .await
        .unwrap();
    assert_eq!(request.mode, EstimateMode::Rough);
    assert_eq!(request.cases.len(), 2);
    assert!(request.slow_attack_policy.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sweep_api_expands_cartesian_axes_and_stages_beyond_queue_capacity() {
    let harness = harness(Duration::ZERO, "96").await;
    let base_case = estimate_request("256").cases.remove(0);
    let sweep_request = SweepRequest {
        base_case: base_case.clone(),
        axes: vec![SweepAxis::Dimension {
            values: vec![256, 512, 768],
        }],
        timeout_seconds: 10,
        slow_attack_policy: Some(SlowAttackPolicy {
            decision_after_seconds: 1,
            high_security_bits: ExactDecimal::new("256").unwrap(),
        }),
    };
    let submitted = json_request(&harness.app, "POST", "/v1/sweeps", &sweep_request).await;
    assert_eq!(submitted.0, StatusCode::ACCEPTED);
    assert_eq!(submitted.1["case_count"], 3);
    assert_eq!(submitted.1["batch_ids"].as_array().unwrap().len(), 1);

    let expanded = sweep::expand(&SweepRequest {
        base_case,
        axes: vec![
            SweepAxis::Dimension {
                values: (1..=100).collect(),
            },
            SweepAxis::SampleCount {
                values: (1..=100).collect(),
            },
        ],
        timeout_seconds: 10,
        slow_attack_policy: Some(SlowAttackPolicy {
            decision_after_seconds: 1,
            high_security_bits: ExactDecimal::new("256").unwrap(),
        }),
    })
    .unwrap();
    assert_eq!(expanded.len(), 10_000);

    let directory = tempfile::tempdir().unwrap();
    let database = Database::open(&directory.path().join("staging.db")).unwrap();
    let template = estimate_request("256");
    let mut last = None;
    for batch_index in 0..5 {
        let mut cases = Vec::with_capacity(500);
        for case_index in 0..500 {
            let mut case = template.cases[0].clone();
            case.id = format!("staged-{batch_index}-{case_index}");
            cases.push(case);
        }
        last = Some(
            database
                .create_staged_batch(EstimateRequest {
                    cases,
                    mode: lattice_security::EstimateMode::Normal,
                    timeout_seconds: template.timeout_seconds,
                    slow_attack_policy: template.slow_attack_policy.clone(),
                })
                .await
                .unwrap(),
        );
    }
    assert_eq!(database.active_job_count().await.unwrap(), 2_000);
    let last = last.unwrap();
    assert_eq!(
        database.job(&last.job_ids[0]).await.unwrap().state.kind(),
        "pending"
    );
}

async fn harness(slow_delay: Duration, security_bits: &'static str) -> Harness {
    harness_with_token(slow_delay, security_bits, None).await
}

async fn harness_with_token(
    slow_delay: Duration,
    security_bits: &'static str,
    api_token: Option<String>,
) -> Harness {
    let calls = Arc::new(AtomicUsize::new(0));
    let mock_state = MockState {
        calls: calls.clone(),
        slow_delay,
        security_bits,
    };
    let worker_router = Router::new()
        .route("/v1/metadata", get(mock_metadata))
        .route("/v1/estimate", post(mock_estimate))
        .with_state(mock_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let worker = tokio::spawn(async move {
        axum::serve(listener, worker_router).await.unwrap();
    });
    let directory = tempfile::tempdir().unwrap();
    let config = AppConfig {
        bind: "127.0.0.1:0".to_owned(),
        database_path: directory.path().join("test.db"),
        estimator_url: format!("http://{address}/"),
        poll_after_seconds: 0,
        api_token,
    };
    let state = AppState::start(&config).await.unwrap();
    Harness {
        app: api::router(state.clone()),
        state,
        calls,
        _directory: directory,
        worker,
    }
}

async fn text_request(
    app: &Router,
    method: &str,
    uri: &str,
    form: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    let body = if let Some(form) = form {
        builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        Body::from(form.to_owned())
    } else {
        Body::empty()
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn mock_metadata() -> Json<Value> {
    Json(json!({
        "adapter_schema_version": 1,
        "dependency_graph_version": 1,
        "estimator_commit": "6019056011d10d7e9c30a0d5da2d2f729fbc2eec",
        "sage_version": "10.9",
        "adapter_version": "1",
        "worker_image": "mock-worker",
        "platform": "linux/amd64",
        "support_matrix": {},
        "dependency_graph": {},
        "adaptive_attacks": ["arora_gb", "bkw"]
    }))
}

async fn mock_estimate(State(state): State<MockState>, Json(request): Json<Value>) -> Json<Value> {
    state.calls.fetch_add(1, Ordering::SeqCst);
    let targets = request["target_attacks"].as_array().unwrap().clone();
    let slow = targets
        .iter()
        .any(|attack| matches!(attack.as_str(), Some("arora_gb" | "bkw")));
    if slow {
        tokio::time::sleep(state.slow_delay).await;
    }
    let results = targets
        .into_iter()
        .map(|attack| {
            json!({
                "attack": attack,
                "role": "target",
                "outcome": {
                    "kind": "computed",
                    "security_bits": state.security_bits,
                    "metrics": {}
                }
            })
        })
        .collect::<Vec<_>>();
    Json(json!({
        "schema_version": 1,
        "plan": {"dependency_graph_version": 1, "target": [], "support": [], "executed": []},
        "results": results,
        "duration_ms": 1,
        "provenance": {
            "estimator_commit": "6019056011d10d7e9c30a0d5da2d2f729fbc2eec",
            "sage_version": "10.9",
            "adapter_version": "1",
            "adapter_schema_version": 1,
            "dependency_graph_version": 1,
            "worker_image": "mock-worker"
        }
    }))
}

fn estimate_request(threshold: &str) -> EstimateRequest {
    let mut value: Value =
        serde_json::from_str(include_str!("../../fixtures/examples/demo-run.json")).unwrap();
    value["timeout_seconds"] = json!(10);
    value["slow_attack_policy"]["decision_after_seconds"] = json!(1);
    value["slow_attack_policy"]["high_security_bits"] = json!(threshold);
    serde_json::from_value(value).unwrap()
}

async fn json_request<T: serde::Serialize>(
    app: &Router,
    method: &str,
    uri: &str,
    value: &T,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    let body = if method == "GET" {
        Body::empty()
    } else {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(serde_json::to_vec(value).unwrap())
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

async fn wait_for_terminal(app: &Router, batch_id: &str) -> Value {
    for _ in 0..100 {
        let response =
            json_request::<Value>(app, "GET", &format!("/v1/batches/{batch_id}"), &Value::Null)
                .await;
        if matches!(
            response.1["state"]["kind"].as_str(),
            Some("completed" | "partial" | "cancelled" | "timed_out" | "failed")
        ) {
            return response.1;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("batch did not reach a terminal state");
}

use std::{
    sync::{
        Arc, Mutex as StdMutex,
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
    ApproximationModelFile, EstimateMode, EstimateRequest, ExactDecimal, ParameterSetFile,
    SlowAttackPolicy, SweepAxis, SweepRequest, api,
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
    plans: Arc<StdMutex<Vec<Vec<String>>>>,
    slow_delay: Duration,
    security_bits: &'static str,
}

struct Harness {
    app: Router,
    state: Arc<AppState>,
    calls: Arc<AtomicUsize>,
    plans: Arc<StdMutex<Vec<Vec<String>>>>,
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
    assert_eq!(harness.calls.load(Ordering::SeqCst), 3);

    let second = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    assert_eq!(second.0, StatusCode::OK);
    assert_eq!(second.1["state"]["kind"], "completed");
    assert_eq!(harness.calls.load(Ordering::SeqCst), 3);

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
async fn terminal_batches_can_be_deleted_without_evicting_attack_cache() {
    let harness = harness(Duration::ZERO, "96").await;
    let request = estimate_request("256");
    let submitted = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    let batch_id = submitted.1["batch_id"].as_str().unwrap().to_owned();
    wait_for_terminal(&harness.app, &batch_id).await;
    let calls = harness.calls.load(Ordering::SeqCst);

    let detail = text_request(
        &harness.app,
        "GET",
        &format!("/ui/batches/{batch_id}/detail"),
        None,
    )
    .await;
    assert!(detail.1.contains(&format!("/ui/batches/{batch_id}/delete")));

    let deleted = text_request(
        &harness.app,
        "POST",
        &format!("/ui/batches/{batch_id}/delete"),
        None,
    )
    .await;
    assert_eq!(deleted.0, StatusCode::SEE_OTHER);
    assert!(harness.state.database.batch(&batch_id, 0).await.is_err());

    let cached = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    assert_eq!(cached.0, StatusCode::OK);
    assert_eq!(harness.calls.load(Ordering::SeqCst), calls);
    let cached_batch_id = cached.1["batch_id"].as_str().unwrap();
    let bulk_deleted = text_request(
        &harness.app,
        "POST",
        "/ui/batches/bulk-delete",
        Some(&format!("ids={cached_batch_id}")),
    )
    .await;
    assert_eq!(bulk_deleted.0, StatusCode::SEE_OTHER);
    assert!(
        harness
            .state
            .database
            .list_batches(10, 0)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unfinished_batch_deletion_is_rejected() {
    let harness = harness(Duration::from_secs(1), "96").await;
    let request = estimate_request("256");
    let submitted = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    let batch_id = submitted.1["batch_id"].as_str().unwrap();

    let deleted = text_request(
        &harness.app,
        "POST",
        &format!("/ui/batches/{batch_id}/delete"),
        None,
    )
    .await;
    assert_eq!(deleted.0, StatusCode::CONFLICT);
    assert!(harness.state.database.batch(batch_id, 0).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_results_do_not_cutoff_slow_attacks_without_a_calibrated_approximation() {
    let harness = harness(Duration::from_millis(50), "192").await;
    let request = estimate_request("128");

    let first = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    assert_eq!(first.0, StatusCode::ACCEPTED);
    let batch_id = first.1["batch_id"].as_str().unwrap();
    let completed = wait_for_terminal(&harness.app, batch_id).await;
    assert_eq!(completed["state"]["kind"], "completed");
    let report = &completed["report"]["reports"][0];
    assert_eq!(report["summary"]["fast_estimate"], false);
    assert_eq!(report["summary"]["complete"], true);
    let attacks = report["attacks"].as_array().unwrap();
    for attack in ["arora_gb", "bkw"] {
        let result = attacks
            .iter()
            .find(|result| result["attack"] == attack)
            .unwrap();
        assert_eq!(result["outcome"]["kind"], "computed");
    }
    assert_eq!(harness.calls.load(Ordering::SeqCst), 3);

    let second = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    assert_eq!(second.0, StatusCode::OK);
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
    assert_eq!(harness.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rough_mode_uses_and_caches_calibrated_slow_attack_approximations() {
    let harness = harness_with_model(Duration::ZERO, "192", approximation_model()).await;
    let mut request = estimate_request("128");
    request.mode = EstimateMode::Rough;
    request.slow_attack_policy = None;

    let first = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    assert_eq!(first.0, StatusCode::ACCEPTED);
    let batch_id = first.1["batch_id"].as_str().unwrap();
    let first = wait_for_terminal(&harness.app, batch_id).await;
    let report = &first["report"]["reports"][0];
    assert_eq!(report["summary"]["approximate"], true);
    assert_eq!(report["summary"]["security_bits"], "88");
    for attack in ["arora_gb", "bkw"] {
        let result = report["attacks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|result| result["attack"] == attack)
            .unwrap();
        assert_eq!(result["outcome"]["kind"], "approximate");
        assert_eq!(result["outcome"]["provenance"]["holdout_samples"], 8);
        assert_eq!(result["cached"], false);
    }
    assert_eq!(harness.calls.load(Ordering::SeqCst), 1);

    let second = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    assert_eq!(second.0, StatusCode::OK);
    let report = &second.1["report"]["reports"][0];
    for attack in ["arora_gb", "bkw"] {
        let result = report["attacks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|result| result["attack"] == attack)
            .unwrap();
        assert_eq!(result["outcome"]["kind"], "approximate");
        assert_eq!(result["cached"], true);
    }
    assert_eq!(harness.calls.load(Ordering::SeqCst), 1);

    let metadata = json_request::<Value>(&harness.app, "GET", "/v1/metadata", &Value::Null).await;
    assert_eq!(metadata.1["approximation"]["available"], true);
    assert_eq!(metadata.1["approximation"]["group_count"], 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adaptive_cutoff_falls_back_to_calibrated_approximations() {
    let harness = harness_with_model(Duration::from_secs(5), "192", approximation_model()).await;
    let request = estimate_request("64");
    let submitted = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    assert_eq!(submitted.0, StatusCode::ACCEPTED);
    let batch_id = submitted.1["batch_id"].as_str().unwrap();
    let completed = wait_for_terminal(&harness.app, batch_id).await;
    assert_eq!(completed["state"]["kind"], "partial");
    let report = &completed["report"]["reports"][0];
    assert_eq!(report["summary"]["approximate"], true);
    assert_eq!(report["summary"]["security_bits"], "88");
    for attack in ["arora_gb", "bkw"] {
        let result = report["attacks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|result| result["attack"] == attack)
            .unwrap();
        assert_eq!(result["outcome"]["kind"], "approximate");
    }
    assert_eq!(harness.calls.load(Ordering::SeqCst), 3);
    let plans = harness.plans.lock().unwrap();
    assert_eq!(plans[1], ["arora_gb"]);
    assert_eq!(plans[2], ["bkw"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approximation_below_required_security_plus_margin_waits_for_real_results() {
    let harness = harness_with_model(Duration::from_millis(50), "192", approximation_model()).await;
    let request = estimate_request("80");
    let submitted = json_request(&harness.app, "POST", "/v1/estimates", &request).await;
    assert_eq!(submitted.0, StatusCode::ACCEPTED);
    let batch_id = submitted.1["batch_id"].as_str().unwrap();
    let completed = wait_for_terminal(&harness.app, batch_id).await;
    assert_eq!(completed["state"]["kind"], "completed");
    let report = &completed["report"]["reports"][0];
    assert_eq!(report["summary"]["approximate"], false);
    for attack in ["arora_gb", "bkw"] {
        let result = report["attacks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|result| result["attack"] == attack)
            .unwrap();
        assert_eq!(result["outcome"]["kind"], "computed");
    }
    assert_eq!(harness.calls.load(Ordering::SeqCst), 3);
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
    assert_eq!(harness.calls.load(Ordering::SeqCst), 3);
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
    assert!(dashboard.1.contains("value=\"save\">保存到方案库"));
    assert!(dashboard.1.contains("value=\"save_run\">保存并开始估算"));
    assert!(dashboard.1.contains("name=\"parameter_set_id\""));
    assert!(dashboard.1.contains("value=\"sparse_ternary\""));
    assert!(dashboard.1.contains("data-field=\"secret_positive_count\""));
    assert!(dashboard.1.contains("data-workspace-tabs"));
    assert!(dashboard.1.contains("冲突策略是什么意思？"));
    assert!(dashboard.1.contains("历史批次和报告仍保留原始参数快照"));
    assert!(dashboard.1.contains("慢攻击判断"));
    assert!(dashboard.1.contains("期望安全 + 停止余量"));
    assert!(
        dashboard
            .1
            .contains("name=\"stop_margin_bits\" value=\"16\"")
    );
    assert!(dashboard.1.contains("id=\"batch-list\""));
    assert!(dashboard.1.contains("id=\"detail-panel\""));
    assert!(dashboard.1.contains("/ui/batches/bulk-delete"));
    assert!(
        dashboard
            .1
            .contains("/ui/parameter-sets/demo-scheme/delete")
    );

    let detail = text_request(&harness.app, "GET", "/ui/parameter-sets/demo-scheme", None).await;
    assert_eq!(detail.0, StatusCode::OK);
    assert!(detail.1.contains("lwe-512"));
    assert!(detail.1.contains("ntru-1024"));

    let run = text_request(
        &harness.app,
        "POST",
        "/ui/parameter-sets/demo-scheme/run",
        Some("case_ids=lwe-512&timeout_seconds=10&decision_after_seconds=1&required_security_bits=256&stop_margin_bits=16"),
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

    let deleted = text_request(
        &harness.app,
        "POST",
        "/ui/parameter-sets/demo-scheme/delete",
        Some(""),
    )
    .await;
    assert_eq!(deleted.0, StatusCode::SEE_OTHER);
    assert!(
        harness
            .state
            .database
            .export_parameter_set("demo-scheme")
            .await
            .is_err()
    );
    assert!(
        harness
            .state
            .database
            .batch_request(&batches[0].batch_id)
            .await
            .is_ok(),
        "deleting a parameter set must not remove historical batch snapshots"
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
        "cases_json={cases_json}&mode=rough&timeout_seconds=10&decision_after_seconds=1&required_security_bits=128&stop_margin_bits=16"
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

    let table = text_request(&harness.app, "GET", "/ui/batches", None).await;
    assert!(table.1.contains("Quick A"));
    assert!(table.1.contains("LWE · n=512 · q=65536"));
    assert!(table.1.contains("2 cases"));

    let detail = text_request(
        &harness.app,
        "GET",
        &format!("/ui/batches/{}/detail", batches[0].batch_id),
        None,
    )
    .await;
    assert!(detail.1.contains("本批次参数"));
    assert!(detail.1.contains("secret: uniform binary"));
    assert!(detail.1.contains("error: discrete Gaussian (σ=3.2)"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quick_estimate_form_can_save_cases_with_or_without_running_them() {
    let harness = harness(Duration::ZERO, "96").await;
    let mut case = estimate_request("128").cases.remove(0);
    case.id = "saved-case".to_owned();
    case.name = "Saved case".to_owned();
    let cases_json = serde_json::to_string(&vec![case.clone()]).unwrap();
    let body = format!(
        "cases_json={cases_json}&action=save&parameter_set_id=quick-saved&parameter_set_name=Quick+Saved&parameter_set_description=Created+from+the+form&conflict=reject&mode=normal&timeout_seconds=10&decision_after_seconds=1&required_security_bits=128&stop_margin_bits=16"
    );
    let saved = text_request(&harness.app, "POST", "/ui/estimates", Some(&body)).await;
    assert_eq!(saved.0, StatusCode::SEE_OTHER);

    let parameter_set = harness
        .state
        .database
        .export_parameter_set("quick-saved")
        .await
        .unwrap();
    assert_eq!(parameter_set.name, "Quick Saved");
    assert_eq!(
        parameter_set.description.as_deref(),
        Some("Created from the form")
    );
    assert_eq!(parameter_set.cases, vec![case]);
    assert!(
        harness
            .state
            .database
            .list_batches(10, 0)
            .await
            .unwrap()
            .is_empty()
    );

    let save_and_run_body = format!(
        "cases_json={cases_json}&action=save_run&parameter_set_id=quick-saved-run&parameter_set_name=Quick+Saved+Run&conflict=reject&mode=rough&timeout_seconds=10&decision_after_seconds=1&required_security_bits=128&stop_margin_bits=16"
    );
    let saved_and_run = text_request(
        &harness.app,
        "POST",
        "/ui/estimates",
        Some(&save_and_run_body),
    )
    .await;
    assert_eq!(saved_and_run.0, StatusCode::SEE_OTHER);
    assert!(
        harness
            .state
            .database
            .export_parameter_set("quick-saved-run")
            .await
            .is_ok()
    );
    assert_eq!(
        harness
            .state
            .database
            .list_batches(10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
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
            required_security_bits: ExactDecimal::new("256").unwrap(),
            stop_margin_bits: ExactDecimal::new("16").unwrap(),
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
            required_security_bits: ExactDecimal::new("256").unwrap(),
            stop_margin_bits: ExactDecimal::new("16").unwrap(),
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
    harness_with_optional_model(slow_delay, security_bits, api_token, None).await
}

async fn harness_with_model(
    slow_delay: Duration,
    security_bits: &'static str,
    model: ApproximationModelFile,
) -> Harness {
    harness_with_optional_model(slow_delay, security_bits, None, Some(model)).await
}

async fn harness_with_optional_model(
    slow_delay: Duration,
    security_bits: &'static str,
    api_token: Option<String>,
    model: Option<ApproximationModelFile>,
) -> Harness {
    let calls = Arc::new(AtomicUsize::new(0));
    let plans = Arc::new(StdMutex::new(Vec::new()));
    let mock_state = MockState {
        calls: calls.clone(),
        plans: plans.clone(),
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
    let approximation_model_path = model.map(|model| {
        let path = directory.path().join("approximation.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&model).unwrap()).unwrap();
        path
    });
    let config = AppConfig {
        bind: "127.0.0.1:0".to_owned(),
        database_path: directory.path().join("test.db"),
        estimator_url: format!("http://{address}/"),
        poll_after_seconds: 0,
        api_token,
        approximation_model_path,
    };
    let state = AppState::start(&config).await.unwrap();
    Harness {
        app: api::router(state.clone()),
        state,
        calls,
        plans,
        _directory: directory,
        worker,
    }
}

fn approximation_model() -> ApproximationModelFile {
    serde_json::from_value(json!({
        "format": "lattice-security/slow-attack-model",
        "version": 1,
        "model_id": "runtime-test-v1",
        "generated_at": "2026-08-18T00:00:00Z",
        "feature_schema": "lwe-log2-v1",
        "provenance": {
            "estimator_commit": "6019056011d10d7e9c30a0d5da2d2f729fbc2eec",
            "sage_version": "10.9",
            "adapter_version": "1",
            "worker_image": "mock-worker",
            "platform": "linux/amd64",
            "dataset_hash": format!("sha256:{}", "d".repeat(64))
        },
        "groups": (["arora_gb", "bkw"].into_iter().map(|attack| json!({
            "id": format!("{attack}-test"),
            "attack": attack,
            "security_model": "classical",
            "cost_model": "BDGL16",
            "shape_model": "GSA",
            "secret": {"kind": "uniform_binary"},
            "sample_mode": "unlimited",
            "domain": {
                "log2_dimension": {"min": "9", "max": "9"},
                "log2_modulus": {"min": "16", "max": "16"},
                "log2_error_standard_deviation": {"min": "1.67", "max": "1.69"}
            },
            "neighbor_count": 1,
            "max_normalized_distance": "0.1",
            "safety_margin_bits": "2",
            "holdout": {
                "samples": 8,
                "mean_absolute_error_bits": "1.25",
                "p95_absolute_error_bits": "2",
                "max_overestimate_bits": "0.75"
            },
            "points": [{
                "log2_dimension": "9",
                "log2_modulus": "16",
                "log2_error_standard_deviation": "1.678071905",
                "security_bits": "90"
            }]
        })).collect::<Vec<_>>())
    }))
    .unwrap()
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
    state.plans.lock().unwrap().push(
        targets
            .iter()
            .filter_map(|attack| attack.as_str().map(ToOwned::to_owned))
            .collect(),
    );
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

fn estimate_request(required_security: &str) -> EstimateRequest {
    let mut value: Value =
        serde_json::from_str(include_str!("../../fixtures/examples/demo-run.json")).unwrap();
    value["timeout_seconds"] = json!(10);
    value["slow_attack_policy"]["decision_after_seconds"] = json!(1);
    value["slow_attack_policy"]["required_security_bits"] = json!(required_security);
    value["slow_attack_policy"]["stop_margin_bits"] = json!("16");
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

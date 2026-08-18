use std::sync::Arc;

use askama::Template;
use axum::{
    Form, Router,
    body::Body,
    extract::{Path, Query, State, rejection::FormRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;

use crate::{
    AttackOutcome, EstimateMode, EstimateRequest, ExactDecimal, ParameterCase, ParameterSetFile,
    PositiveInteger, SlowAttackPolicy, SweepAxis, SweepRequest, Validate,
    database::ParameterSetSummary,
    error::ServiceError,
    service::{AppState, BatchSnapshot, JobSnapshot},
};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(dashboard))
        .route("/login", get(login_page).post(login))
        .route("/assets/app.css", get(css))
        .route("/assets/app.js", get(javascript))
        .route("/ui/batches", get(batch_table))
        .route("/ui/batches/{batch_id}/row", get(batch_row))
        .route("/ui/batches/{batch_id}/detail", get(batch_detail))
        .route("/ui/batches/bulk-cancel", post(bulk_cancel))
        .route("/ui/batches/bulk-rerun", post(bulk_rerun))
        .route("/ui/batches/bulk-export", post(bulk_export))
        .route("/ui/estimates", post(create_quick_estimate))
        .route("/ui/import", post(import_parameter_set))
        .route("/ui/parameter-sets/{parameter_set_id}", get(parameter_set))
        .route(
            "/ui/parameter-sets/{parameter_set_id}/run",
            post(run_parameter_set),
        )
        .route(
            "/ui/parameter-sets/{parameter_set_id}/delete",
            post(delete_parameter_set),
        )
        .route("/ui/sweeps", post(create_sweep))
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    parameter_sets: Vec<UiParameterSet>,
    batches: Vec<UiBatch>,
    active_tab: String,
    initial_batch_id: String,
    message: String,
}

#[derive(Template)]
#[template(path = "batch_table.html")]
struct BatchTableTemplate {
    batches: Vec<UiBatch>,
}

#[derive(Template)]
#[template(path = "batch_row.html")]
struct BatchRowTemplate {
    batch: UiBatch,
}

#[derive(Template)]
#[template(path = "batch_detail.html")]
struct BatchDetailTemplate {
    batch: UiBatch,
    jobs: Vec<UiJob>,
    reports: Vec<UiReport>,
}

#[derive(Template)]
#[template(path = "parameter_set.html")]
struct ParameterSetTemplate {
    id: String,
    name: String,
    description: String,
    cases: Vec<UiCase>,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate;

#[derive(Clone)]
struct UiParameterSet {
    id: String,
    name: String,
    version: u64,
    case_count: usize,
    created_at: String,
}

impl From<ParameterSetSummary> for UiParameterSet {
    fn from(value: ParameterSetSummary) -> Self {
        Self {
            id: value.id,
            name: value.name,
            version: value.version,
            case_count: value.case_count,
            created_at: value.created_at,
        }
    }
}

#[derive(Clone)]
struct UiBatch {
    id: String,
    state: String,
    revision: u64,
    updated_at: String,
    terminal: bool,
    report_count: usize,
    security: String,
}

impl From<BatchSnapshot> for UiBatch {
    fn from(value: BatchSnapshot) -> Self {
        let report_count = value
            .report
            .as_ref()
            .map_or(0, |report| report.reports.len());
        let security = value
            .report
            .as_ref()
            .and_then(|report| {
                report
                    .reports
                    .iter()
                    .filter_map(|entry| entry.summary.security_bits.as_ref())
                    .min_by(|left, right| left.as_big_decimal().cmp(&right.as_big_decimal()))
            })
            .map(format_security_bits)
            .unwrap_or_else(|| "—".to_owned());
        Self {
            id: value.batch_id,
            state: value.state.kind().to_owned(),
            revision: value.revision,
            updated_at: value.updated_at,
            terminal: value.state.terminal(),
            report_count,
            security,
        }
    }
}

struct UiJob {
    id: String,
    case_id: String,
    state: String,
    attempts: u32,
}

impl From<JobSnapshot> for UiJob {
    fn from(value: JobSnapshot) -> Self {
        Self {
            id: value.job_id,
            case_id: value.case_id,
            state: value.state.kind().to_owned(),
            attempts: value.attempts,
        }
    }
}

struct UiReport {
    case_id: String,
    case_name: String,
    security: String,
    complete: bool,
    fast_estimate: bool,
    attacks: Vec<UiAttack>,
}

struct UiAttack {
    name: String,
    outcome: String,
    security: String,
    detail: String,
    cached: bool,
}

struct UiCase {
    id: String,
    name: String,
    problem: String,
}

#[derive(Default, Deserialize)]
struct DashboardQuery {
    #[serde(default)]
    message: String,
    #[serde(default)]
    tab: String,
}

async fn dashboard(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DashboardQuery>,
) -> Result<Html<String>, ServiceError> {
    let parameter_sets = state
        .database
        .list_parameter_sets()
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    let batches: Vec<UiBatch> = state
        .database
        .list_batches(100, state.poll_after_seconds)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    let initial_batch_id = batches
        .first()
        .map(|batch: &UiBatch| batch.id.clone())
        .unwrap_or_default();
    let active_tab = match query.tab.as_str() {
        "schemes" | "runs" | "sweep" => query.tab,
        _ => "estimate".to_owned(),
    };
    render(DashboardTemplate {
        parameter_sets,
        batches,
        active_tab,
        initial_batch_id,
        message: query.message,
    })
}

#[derive(Default, Deserialize)]
struct BatchFilter {
    #[serde(default)]
    q: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    sort: String,
}

async fn batch_table(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<BatchFilter>,
) -> Result<Html<String>, ServiceError> {
    let mut batches = state
        .database
        .list_batches(200, state.poll_after_seconds)
        .await?
        .into_iter()
        .map(UiBatch::from)
        .filter(|batch| {
            (filter.q.is_empty() || batch.id.contains(&filter.q))
                && (filter.state.is_empty() || batch.state == filter.state)
        })
        .collect::<Vec<_>>();
    match filter.sort.as_str() {
        "created_asc" => batches.reverse(),
        "security_asc" => batches.sort_by(|left, right| left.security.cmp(&right.security)),
        _ => {}
    }
    render(BatchTableTemplate { batches })
}

async fn batch_row(
    State(state): State<Arc<AppState>>,
    Path(batch_id): Path<String>,
) -> Result<Html<String>, ServiceError> {
    let batch = state
        .database
        .batch(&batch_id, state.poll_after_seconds)
        .await?
        .into();
    render(BatchRowTemplate { batch })
}

async fn batch_detail(
    State(state): State<Arc<AppState>>,
    Path(batch_id): Path<String>,
) -> Result<Html<String>, ServiceError> {
    let snapshot = state
        .database
        .batch(&batch_id, state.poll_after_seconds)
        .await?;
    let mut jobs = Vec::with_capacity(snapshot.job_ids.len());
    for job_id in &snapshot.job_ids {
        jobs.push(state.database.job(job_id).await?.into());
    }
    let reports = snapshot
        .report
        .as_ref()
        .map(|report| {
            report
                .reports
                .iter()
                .map(|entry| UiReport {
                    case_id: entry.case.id.clone(),
                    case_name: entry.case.name.clone(),
                    security: entry
                        .summary
                        .security_bits
                        .as_ref()
                        .map(format_security_bits)
                        .unwrap_or_else(|| "—".to_owned()),
                    complete: entry.summary.complete,
                    fast_estimate: entry.summary.fast_estimate,
                    attacks: entry
                        .attacks
                        .iter()
                        .map(|result| UiAttack {
                            name: serde_json::to_value(result.attack)
                                .ok()
                                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                                .unwrap_or_else(|| "unknown".to_owned()),
                            outcome: outcome_name(&result.outcome).to_owned(),
                            security: outcome_security(&result.outcome),
                            detail: outcome_detail(&result.outcome),
                            cached: result.cached,
                        })
                        .collect(),
                })
                .collect()
        })
        .unwrap_or_default();
    render(BatchDetailTemplate {
        batch: snapshot.into(),
        jobs,
        reports,
    })
}

async fn parameter_set(
    State(state): State<Arc<AppState>>,
    Path(parameter_set_id): Path<String>,
) -> Result<Html<String>, ServiceError> {
    let parameter_set = state
        .database
        .export_parameter_set(&parameter_set_id)
        .await?;
    let cases = parameter_set
        .cases
        .iter()
        .map(|case| UiCase {
            id: case.id.clone(),
            name: case.name.clone(),
            problem: serde_json::to_string(&case.problem)
                .unwrap_or_else(|_| "invalid problem".to_owned()),
        })
        .collect();
    render(ParameterSetTemplate {
        id: parameter_set.id,
        name: parameter_set.name,
        description: parameter_set.description.unwrap_or_default(),
        cases,
    })
}

#[derive(Deserialize)]
struct ImportForm {
    document: String,
    #[serde(default)]
    conflict: String,
    #[serde(default)]
    run_all: Option<String>,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    #[serde(default = "default_decision")]
    decision_after_seconds: u64,
    #[serde(default = "default_threshold")]
    high_security_bits: String,
}

#[derive(Deserialize)]
struct QuickEstimateForm {
    cases_json: String,
    mode: String,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    #[serde(default = "default_decision")]
    decision_after_seconds: u64,
    #[serde(default = "default_threshold")]
    high_security_bits: String,
}

async fn create_quick_estimate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<QuickEstimateForm>,
) -> Result<Response, ServiceError> {
    let cases: Vec<ParameterCase> = serde_json::from_str(&form.cases_json).map_err(|error| {
        ServiceError::BadRequest(format!("invalid quick-estimate cases: {error}"))
    })?;
    let mode = match form.mode.as_str() {
        "rough" => EstimateMode::Rough,
        "normal" => EstimateMode::Normal,
        _ => return Err(ServiceError::BadRequest("unknown estimate mode".to_owned())),
    };
    let request = estimate_from_cases(
        cases,
        mode,
        form.timeout_seconds,
        form.decision_after_seconds,
        &form.high_security_bits,
    )?;
    let (fully_cached, _) = state
        .scheduler
        .submit(request, state.poll_after_seconds)
        .await?;
    let location = if fully_cached {
        "/?tab=runs&message=Security+estimate+completed+from+cache"
    } else {
        "/?tab=runs&message=Security+estimate+queued"
    };
    redirect(&headers, location)
}

async fn import_parameter_set(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    form: Result<Form<ImportForm>, FormRejection>,
) -> Result<Response, ServiceError> {
    let Form(form) = form.map_err(|error| ServiceError::BadRequest(error.to_string()))?;
    let parameter_set: ParameterSetFile =
        serde_json::from_str(&form.document).map_err(|error| {
            ServiceError::BadRequest(format!("invalid parameter-set JSON: {error}"))
        })?;
    parameter_set.validate()?;
    state
        .database
        .import_parameter_set(parameter_set.clone(), form.conflict == "replace")
        .await?;
    if form.run_all.is_some() {
        let request = estimate_from_cases(
            parameter_set.cases,
            EstimateMode::Normal,
            form.timeout_seconds,
            form.decision_after_seconds,
            &form.high_security_bits,
        )?;
        state
            .scheduler
            .submit(request, state.poll_after_seconds)
            .await?;
    }
    redirect(&headers, "/?tab=schemes&message=Parameter+set+imported")
}

#[derive(Deserialize)]
struct RunForm {
    #[serde(default)]
    case_ids: String,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    #[serde(default = "default_decision")]
    decision_after_seconds: u64,
    #[serde(default = "default_threshold")]
    high_security_bits: String,
}

async fn run_parameter_set(
    State(state): State<Arc<AppState>>,
    Path(parameter_set_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<RunForm>,
) -> Result<Response, ServiceError> {
    let parameter_set = state
        .database
        .export_parameter_set(&parameter_set_id)
        .await?;
    let selected = split_ids(&form.case_ids);
    let cases = if selected.is_empty() {
        parameter_set.cases
    } else {
        parameter_set
            .cases
            .into_iter()
            .filter(|case| selected.iter().any(|id| id == &case.id))
            .collect()
    };
    if cases.is_empty() {
        return Err(ServiceError::BadRequest(
            "no matching cases selected".to_owned(),
        ));
    }
    let request = estimate_from_cases(
        cases,
        EstimateMode::Normal,
        form.timeout_seconds,
        form.decision_after_seconds,
        &form.high_security_bits,
    )?;
    state
        .scheduler
        .submit(request, state.poll_after_seconds)
        .await?;
    redirect(&headers, "/?tab=runs&message=Run+queued")
}

async fn delete_parameter_set(
    State(state): State<Arc<AppState>>,
    Path(parameter_set_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ServiceError> {
    state
        .database
        .delete_parameter_set(&parameter_set_id)
        .await?;
    redirect(&headers, "/?tab=schemes&message=Parameter+set+deleted")
}

#[derive(Deserialize)]
struct BulkForm {
    ids: String,
}

async fn bulk_cancel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<BulkForm>,
) -> Result<Response, ServiceError> {
    for id in required_ids(&form.ids)? {
        state
            .scheduler
            .cancel(&id, state.poll_after_seconds)
            .await?;
    }
    redirect(&headers, "/?tab=runs&message=Selected+runs+cancelled")
}

async fn bulk_rerun(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<BulkForm>,
) -> Result<Response, ServiceError> {
    for id in required_ids(&form.ids)? {
        let request = state.database.batch_request(&id).await?;
        state
            .scheduler
            .submit(request, state.poll_after_seconds)
            .await?;
    }
    redirect(&headers, "/?tab=runs&message=Selected+runs+queued")
}

async fn bulk_export(
    State(state): State<Arc<AppState>>,
    Form(form): Form<BulkForm>,
) -> Result<Response, ServiceError> {
    let mut reports = Vec::new();
    for id in required_ids(&form.ids)? {
        let batch = state.database.batch(&id, state.poll_after_seconds).await?;
        if let Some(report) = batch.report {
            reports.push(report);
        }
    }
    if reports.is_empty() {
        return Err(ServiceError::Conflict(
            "selected batches do not have exportable reports".to_owned(),
        ));
    }
    let body = serde_json::to_vec_pretty(&serde_json::json!({
        "format": "lattice-security/report-bundle",
        "version": 1,
        "reports": reports,
    }))
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=security-reports.json"),
    );
    Ok(response)
}

#[derive(Deserialize)]
struct SweepForm {
    base_case: String,
    axis: String,
    values: String,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    #[serde(default = "default_decision")]
    decision_after_seconds: u64,
    #[serde(default = "default_threshold")]
    high_security_bits: String,
}

async fn create_sweep(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<SweepForm>,
) -> Result<Response, ServiceError> {
    let base_case: ParameterCase = serde_json::from_str(&form.base_case)
        .map_err(|error| ServiceError::BadRequest(format!("invalid base case JSON: {error}")))?;
    let values = form
        .values
        .split([',', '\n', '\r', ' '])
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let axis = match form.axis.as_str() {
        "dimension" => SweepAxis::Dimension {
            values: values
                .iter()
                .map(|value| value.parse::<u64>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| ServiceError::BadRequest(error.to_string()))?,
        },
        "modulus" => SweepAxis::Modulus {
            values: values
                .iter()
                .map(PositiveInteger::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(ServiceError::BadRequest)?,
        },
        "error_standard_deviation" => SweepAxis::ErrorStandardDeviation {
            values: values
                .iter()
                .map(ExactDecimal::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(ServiceError::BadRequest)?,
        },
        "sample_count" => SweepAxis::SampleCount {
            values: values
                .iter()
                .map(|value| value.parse::<u64>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| ServiceError::BadRequest(error.to_string()))?,
        },
        _ => return Err(ServiceError::BadRequest("unknown sweep axis".to_owned())),
    };
    let threshold =
        ExactDecimal::new(&form.high_security_bits).map_err(ServiceError::BadRequest)?;
    let request = SweepRequest {
        base_case,
        axes: vec![axis],
        timeout_seconds: form.timeout_seconds,
        slow_attack_policy: Some(SlowAttackPolicy {
            decision_after_seconds: form.decision_after_seconds,
            high_security_bits: threshold,
        }),
    };
    let cases = crate::sweep::expand(&request)?;
    for chunk in cases.chunks(500) {
        state
            .scheduler
            .submit_staged(
                EstimateRequest {
                    cases: chunk.to_vec(),
                    mode: crate::EstimateMode::Normal,
                    timeout_seconds: request.timeout_seconds,
                    slow_attack_policy: request.slow_attack_policy.clone(),
                },
                state.poll_after_seconds,
            )
            .await?;
    }
    redirect(&headers, "/?tab=runs&message=Sweep+queued")
}

async fn login_page() -> Result<Html<String>, ServiceError> {
    render(LoginTemplate)
}

#[derive(Deserialize)]
struct LoginForm {
    token: String,
}

async fn login(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Result<Response, ServiceError> {
    if state.api_token.as_deref() != Some(form.token.as_str()) {
        return Err(ServiceError::Unauthorized);
    }
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/"));
    let cookie = format!(
        "lattice_security_token={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400",
        form.token
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .map_err(|error| ServiceError::BadRequest(error.to_string()))?,
    );
    Ok(response)
}

async fn css() -> Response {
    asset("text/css; charset=utf-8", include_str!("../assets/app.css"))
}

async fn javascript() -> Response {
    asset(
        "application/javascript; charset=utf-8",
        include_str!("../assets/app.js"),
    )
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    let mut response = Response::new(Body::from(body));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

fn render(template: impl Template) -> Result<Html<String>, ServiceError> {
    template
        .render()
        .map(Html)
        .map_err(|error| ServiceError::Internal(error.to_string()))
}

fn redirect(headers: &HeaderMap, location: &'static str) -> Result<Response, ServiceError> {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if headers.contains_key("hx-request") {
        response
            .headers_mut()
            .insert("hx-redirect", HeaderValue::from_static(location));
    } else {
        response
            .headers_mut()
            .insert(header::LOCATION, HeaderValue::from_static(location));
    }
    Ok(response)
}

fn estimate_from_cases(
    cases: Vec<ParameterCase>,
    mode: EstimateMode,
    timeout_seconds: u64,
    decision_after_seconds: u64,
    high_security_bits: &str,
) -> Result<EstimateRequest, ServiceError> {
    let request = EstimateRequest {
        cases,
        mode,
        timeout_seconds,
        slow_attack_policy: if mode == EstimateMode::Normal {
            Some(SlowAttackPolicy {
                decision_after_seconds,
                high_security_bits: ExactDecimal::new(high_security_bits)
                    .map_err(ServiceError::BadRequest)?,
            })
        } else {
            None
        },
    };
    request.validate()?;
    Ok(request)
}

fn required_ids(value: &str) -> Result<Vec<String>, ServiceError> {
    let ids = split_ids(value);
    if ids.is_empty() {
        Err(ServiceError::BadRequest(
            "select at least one batch".to_owned(),
        ))
    } else {
        Ok(ids)
    }
}

fn split_ids(value: &str) -> Vec<String> {
    value
        .split([',', '\n', '\r', ' '])
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn outcome_name(outcome: &AttackOutcome) -> &'static str {
    match outcome {
        AttackOutcome::Computed { .. } => "computed",
        AttackOutcome::Timeout { .. } => "timeout",
        AttackOutcome::Unsupported { .. } => "unsupported",
        AttackOutcome::Failed { .. } => "failed",
        AttackOutcome::Skipped { .. } => "skipped",
    }
}

fn outcome_security(outcome: &AttackOutcome) -> String {
    match outcome {
        AttackOutcome::Computed { security_bits, .. } => format_security_bits(security_bits),
        _ => "—".to_owned(),
    }
}

fn outcome_detail(outcome: &AttackOutcome) -> String {
    match outcome {
        AttackOutcome::Computed { .. } => "computed".to_owned(),
        AttackOutcome::Timeout { timeout_seconds } => {
            format!("timeout after {timeout_seconds}s")
        }
        AttackOutcome::Unsupported { code, reason } => {
            format!("unsupported · {code}: {reason}")
        }
        AttackOutcome::Failed {
            code,
            message,
            retryable,
        } => format!("failed · {code}: {message} · retryable={retryable}"),
        AttackOutcome::Skipped { reason } => format!("skipped · {reason}"),
    }
}

fn format_security_bits(value: &ExactDecimal) -> String {
    value.as_big_decimal().round(2).normalized().to_string()
}

const fn default_timeout() -> u64 {
    3_600
}

const fn default_decision() -> u64 {
    60
}

fn default_threshold() -> String {
    "128".to_owned()
}

#[cfg(test)]
mod tests {
    use super::{format_security_bits, outcome_detail};
    use crate::{AttackOutcome, ExactDecimal};

    #[test]
    fn security_bits_are_rounded_only_for_ui_display() {
        assert_eq!(
            format_security_bits(&ExactDecimal::new("214.105577393628").unwrap()),
            "214.11"
        );
        assert_eq!(
            format_security_bits(&ExactDecimal::new("128.0001").unwrap()),
            "128"
        );
    }

    #[test]
    fn unsupported_reason_is_visible_in_ui_detail() {
        let detail = outcome_detail(&AttackOutcome::Unsupported {
            code: "no_finite_rop".to_owned(),
            reason: "dual_hybrid returned no finite positive rop".to_owned(),
        });
        assert_eq!(
            detail,
            "unsupported · no_finite_rop: dual_hybrid returned no finite positive rop"
        );
    }
}

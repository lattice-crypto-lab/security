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
    AttackOutcome, ErrorDistribution, EstimateMode, EstimateRequest, ExactDecimal,
    FILE_FORMAT_VERSION, ParameterCase, ParameterSetFile, PositiveInteger, Problem, SampleCount,
    SecretDistribution, SlowAttackPolicy, SweepAxis, SweepRequest, Validate,
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
        .route("/ui/batches/bulk-delete", post(bulk_delete))
        .route("/ui/batches/{batch_id}/delete", post(delete_batch))
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
    approximation_status: String,
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
    case_summary: String,
}

impl UiBatch {
    fn new(value: BatchSnapshot, request: &EstimateRequest) -> Self {
        let report_count = request.cases.len();
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
            case_summary: batch_case_summary(&request.cases),
        }
    }
}

struct UiJob {
    id: String,
    case_id: String,
    state: String,
    attempts: u32,
    case_name: String,
    parameters: UiProblem,
}

impl UiJob {
    fn new(value: JobSnapshot, case: Option<&ParameterCase>) -> Self {
        Self {
            id: value.job_id,
            case_id: value.case_id,
            state: value.state.kind().to_owned(),
            attempts: value.attempts,
            case_name: case.map_or_else(|| "Unknown case".to_owned(), |case| case.name.clone()),
            parameters: case.map_or_else(UiProblem::unknown, |case| problem_view(&case.problem)),
        }
    }
}

struct UiReport {
    case_id: String,
    case_name: String,
    security: String,
    complete: bool,
    fast_estimate: bool,
    approximate: bool,
    parameters: UiProblem,
    attacks: Vec<UiAttack>,
}

#[derive(Clone)]
struct UiProblem {
    primary: String,
    secret: String,
    error: String,
}

impl UiProblem {
    fn unknown() -> Self {
        Self {
            primary: "参数快照不可用".to_owned(),
            secret: String::new(),
            error: String::new(),
        }
    }
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

async fn load_ui_batches(
    state: &Arc<AppState>,
    limit: usize,
) -> Result<Vec<UiBatch>, ServiceError> {
    let snapshots = state
        .database
        .list_batches_with_requests(limit, state.poll_after_seconds)
        .await?;
    let mut batches = Vec::with_capacity(snapshots.len());
    for (snapshot, request) in snapshots {
        batches.push(UiBatch::new(snapshot, &request));
    }
    Ok(batches)
}

fn batch_case_summary(cases: &[ParameterCase]) -> String {
    let Some(first) = cases.first() else {
        return "没有 case".to_owned();
    };
    let first_problem = problem_view(&first.problem);
    if cases.len() == 1 {
        format!("{} · {}", first.name, first_problem.primary)
    } else {
        format!(
            "{} · {} · 另有 {} 个 case",
            first.name,
            first_problem.primary,
            cases.len() - 1
        )
    }
}

fn problem_view(problem: &Problem) -> UiProblem {
    match problem {
        Problem::Lwe(problem) => UiProblem {
            primary: format!(
                "LWE · n={} · q={} · samples={}",
                problem.dimension,
                problem.modulus,
                sample_count(&problem.samples)
            ),
            secret: secret_distribution(&problem.secret),
            error: error_distribution(&problem.error),
        },
        Problem::Rlwe(problem) => UiProblem {
            primary: format!(
                "RLWE · N={} · q={} · ring samples={}",
                problem.negacyclic_ring.polynomial_degree,
                problem.negacyclic_ring.ciphertext_modulus,
                sample_count(&problem.samples)
            ),
            secret: secret_distribution(&problem.secret),
            error: error_distribution(&problem.error),
        },
        Problem::Glwe(problem) => UiProblem {
            primary: format!(
                "GLWE · k={} · N={} · q={} · ring samples={}",
                problem.dimension,
                problem.negacyclic_ring.polynomial_degree,
                problem.negacyclic_ring.ciphertext_modulus,
                sample_count(&problem.samples)
            ),
            secret: secret_distribution(&problem.secret),
            error: error_distribution(&problem.error),
        },
        Problem::Ntru(problem) => UiProblem {
            primary: format!(
                "NTRU · n={} · q={} · structure={}",
                problem.dimension,
                problem.modulus,
                enum_name(&problem.structure)
            ),
            secret: secret_distribution(&problem.secret),
            error: error_distribution(&problem.error),
        },
        Problem::Sis(problem) => UiProblem {
            primary: format!(
                "SIS · n={} · q={} · columns={} · bound={} · norm={}",
                problem.dimension,
                problem.modulus,
                problem.columns,
                problem.length_bound,
                enum_name(&problem.norm)
            ),
            secret: String::new(),
            error: String::new(),
        },
    }
}

fn sample_count(samples: &SampleCount) -> String {
    match samples {
        SampleCount::Finite { count } => count.to_string(),
        SampleCount::Unlimited => "unlimited".to_owned(),
    }
}

fn secret_distribution(distribution: &SecretDistribution) -> String {
    match distribution {
        SecretDistribution::UniformBinary => "secret: uniform binary".to_owned(),
        SecretDistribution::UniformTernary => "secret: uniform ternary".to_owned(),
        SecretDistribution::SparseTernary {
            positive_count,
            negative_count,
        } => format!("secret: sparse ternary (+1={positive_count}, -1={negative_count})"),
        SecretDistribution::FixedWeightBinary { hamming_weight } => {
            format!("secret: fixed-weight binary (weight={hamming_weight})")
        }
        SecretDistribution::FixedWeightTernary {
            positive_weight,
            negative_weight,
        } => format!("secret: fixed-weight ternary (+1={positive_weight}, -1={negative_weight})"),
        SecretDistribution::DiscreteGaussian { standard_deviation } => {
            format!("secret: discrete Gaussian (σ={standard_deviation})")
        }
        SecretDistribution::CenteredBinomial { eta } => {
            format!("secret: centered binomial (η={eta})")
        }
        SecretDistribution::UniformInteger { lower, upper } => format!(
            "secret: bounded integer [{}..{}]",
            lower.as_bigint(),
            upper.as_bigint()
        ),
    }
}

fn error_distribution(distribution: &ErrorDistribution) -> String {
    match distribution {
        ErrorDistribution::DiscreteGaussian { standard_deviation } => {
            format!("error: discrete Gaussian (σ={standard_deviation})")
        }
        ErrorDistribution::CenteredBinomial { eta } => {
            format!("error: centered binomial (η={eta})")
        }
        ErrorDistribution::UniformInteger { lower, upper } => format!(
            "error: bounded integer [{}..{}]",
            lower.as_bigint(),
            upper.as_bigint()
        ),
    }
}

fn enum_name<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
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
    let batches = load_ui_batches(&state, 100).await?;
    let initial_batch_id = batches
        .first()
        .map(|batch: &UiBatch| batch.id.clone())
        .unwrap_or_default();
    let active_tab = match query.tab.as_str() {
        "schemes" | "runs" | "sweep" => query.tab,
        _ => "estimate".to_owned(),
    };
    let approximation_status = if state.metadata.approximation.available {
        format!(
            "近似模型 {} v{}",
            state
                .metadata
                .approximation
                .model_id
                .as_deref()
                .unwrap_or("unknown"),
            state
                .metadata
                .approximation
                .model_version
                .unwrap_or_default()
        )
    } else {
        "近似模型未启用".to_owned()
    };
    render(DashboardTemplate {
        parameter_sets,
        batches,
        active_tab,
        initial_batch_id,
        approximation_status,
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
    let mut batches = load_ui_batches(&state, 200)
        .await?
        .into_iter()
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
    let snapshot = state
        .database
        .batch(&batch_id, state.poll_after_seconds)
        .await?;
    let request = state.database.batch_request(&batch_id).await?;
    let batch = UiBatch::new(snapshot, &request);
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
    let request = state.database.batch_request(&batch_id).await?;
    let mut jobs = Vec::with_capacity(snapshot.job_ids.len());
    for job_id in &snapshot.job_ids {
        let job = state.database.job(job_id).await?;
        let case = request.cases.iter().find(|case| case.id == job.case_id);
        jobs.push(UiJob::new(job, case));
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
                    approximate: entry.summary.approximate,
                    parameters: problem_view(&entry.case.problem),
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
        batch: UiBatch::new(snapshot, &request),
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
    #[serde(default = "default_required_security")]
    required_security_bits: String,
    #[serde(default = "default_stop_margin")]
    stop_margin_bits: String,
}

#[derive(Deserialize)]
struct QuickEstimateForm {
    cases_json: String,
    #[serde(default = "default_quick_action")]
    action: String,
    #[serde(default)]
    parameter_set_id: String,
    #[serde(default)]
    parameter_set_name: String,
    #[serde(default)]
    parameter_set_description: String,
    #[serde(default)]
    conflict: String,
    mode: String,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    #[serde(default = "default_decision")]
    decision_after_seconds: u64,
    #[serde(default = "default_required_security")]
    required_security_bits: String,
    #[serde(default = "default_stop_margin")]
    stop_margin_bits: String,
}

async fn create_quick_estimate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<QuickEstimateForm>,
) -> Result<Response, ServiceError> {
    let cases: Vec<ParameterCase> = serde_json::from_str(&form.cases_json).map_err(|error| {
        ServiceError::BadRequest(format!("invalid quick-estimate cases: {error}"))
    })?;
    let save = matches!(form.action.as_str(), "save" | "save_run");
    let run = matches!(form.action.as_str(), "run" | "save_run");
    if !save && !run {
        return Err(ServiceError::BadRequest(
            "unknown quick-estimate action".to_owned(),
        ));
    }
    if save {
        let parameter_set = ParameterSetFile {
            format: "lattice-security/parameter-set".to_owned(),
            version: FILE_FORMAT_VERSION,
            id: form.parameter_set_id,
            name: form.parameter_set_name,
            description: (!form.parameter_set_description.trim().is_empty())
                .then_some(form.parameter_set_description),
            tags: vec!["web".to_owned()],
            cases: cases.clone(),
        };
        parameter_set.validate()?;
        state
            .database
            .import_parameter_set(parameter_set, form.conflict == "replace")
            .await?;
    }
    if !run {
        return redirect(&headers, "/?tab=schemes&message=Parameter+set+saved");
    }
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
        &form.required_security_bits,
        &form.stop_margin_bits,
    )?;
    let (fully_cached, _) = state
        .scheduler
        .submit(request, state.poll_after_seconds)
        .await?;
    let location = if fully_cached && save {
        "/?tab=runs&message=Parameter+set+saved+and+estimate+completed+from+cache"
    } else if fully_cached {
        "/?tab=runs&message=Security+estimate+completed+from+cache"
    } else if save {
        "/?tab=runs&message=Parameter+set+saved+and+estimate+queued"
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
            &form.required_security_bits,
            &form.stop_margin_bits,
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
    #[serde(default = "default_required_security")]
    required_security_bits: String,
    #[serde(default = "default_stop_margin")]
    stop_margin_bits: String,
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
        &form.required_security_bits,
        &form.stop_margin_bits,
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

async fn delete_batch(
    State(state): State<Arc<AppState>>,
    Path(batch_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ServiceError> {
    state.database.delete_batches(vec![batch_id]).await?;
    redirect(&headers, "/?tab=runs&message=Run+deleted")
}

async fn bulk_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<BulkForm>,
) -> Result<Response, ServiceError> {
    state
        .database
        .delete_batches(required_ids(&form.ids)?)
        .await?;
    redirect(&headers, "/?tab=runs&message=Selected+runs+deleted")
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
    #[serde(default = "default_required_security")]
    required_security_bits: String,
    #[serde(default = "default_stop_margin")]
    stop_margin_bits: String,
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
    let required_security =
        ExactDecimal::new(&form.required_security_bits).map_err(ServiceError::BadRequest)?;
    let stop_margin =
        ExactDecimal::new(&form.stop_margin_bits).map_err(ServiceError::BadRequest)?;
    let request = SweepRequest {
        base_case,
        axes: vec![axis],
        timeout_seconds: form.timeout_seconds,
        slow_attack_policy: Some(SlowAttackPolicy {
            decision_after_seconds: form.decision_after_seconds,
            required_security_bits: required_security,
            stop_margin_bits: stop_margin,
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
    required_security_bits: &str,
    stop_margin_bits: &str,
) -> Result<EstimateRequest, ServiceError> {
    let request = EstimateRequest {
        cases,
        mode,
        timeout_seconds,
        slow_attack_policy: if mode == EstimateMode::Normal {
            Some(SlowAttackPolicy {
                decision_after_seconds,
                required_security_bits: ExactDecimal::new(required_security_bits)
                    .map_err(ServiceError::BadRequest)?,
                stop_margin_bits: ExactDecimal::new(stop_margin_bits)
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
        AttackOutcome::Approximate { .. } => "approximate",
        AttackOutcome::Timeout { .. } => "timeout",
        AttackOutcome::Unsupported { .. } => "unsupported",
        AttackOutcome::Failed { .. } => "failed",
        AttackOutcome::Skipped { .. } => "skipped",
    }
}

fn outcome_security(outcome: &AttackOutcome) -> String {
    match outcome {
        AttackOutcome::Computed { security_bits, .. }
        | AttackOutcome::Approximate { security_bits, .. } => format_security_bits(security_bits),
        _ => "—".to_owned(),
    }
}

fn outcome_detail(outcome: &AttackOutcome) -> String {
    match outcome {
        AttackOutcome::Computed { .. } => "computed".to_owned(),
        AttackOutcome::Approximate { provenance, .. } => format!(
            "approximate · {} v{} · {} · holdout MAE {} bit · p95 {} bit · max overestimate {} bit · safety margin {} bit",
            provenance.model_id,
            provenance.model_version,
            provenance.platform,
            provenance.holdout_mean_absolute_error_bits,
            provenance.holdout_p95_absolute_error_bits,
            provenance.holdout_max_overestimate_bits,
            provenance.safety_margin_bits
        ),
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
    300
}

fn default_required_security() -> String {
    "128".to_owned()
}

fn default_stop_margin() -> String {
    "16".to_owned()
}

fn default_quick_action() -> String {
    "run".to_owned()
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

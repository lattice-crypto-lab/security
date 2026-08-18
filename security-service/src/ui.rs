use std::sync::Arc;

mod view;

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

use view::{UiBatch, UiCase, UiJob, UiParameterSet, UiReport, load_ui_batches};

use crate::{
    EstimateMode, EstimateRequest, ExactDecimal, FILE_FORMAT_VERSION, ParameterCase,
    ParameterSetFile, PositiveInteger, SlowAttackPolicy, SweepAxis, SweepRequest, Validate,
    error::ServiceError, service::AppState,
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
            "/ui/parameter-sets/{parameter_set_id}/edit",
            post(edit_parameter_set),
        )
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
    cases_json: String,
    message: String,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate;

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
        .map(|report| report.reports.iter().map(UiReport::new).collect())
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
    Query(query): Query<DashboardQuery>,
) -> Result<Html<String>, ServiceError> {
    let parameter_set = state
        .database
        .export_parameter_set(&parameter_set_id)
        .await?;
    let cases_json = serde_json::to_string(&parameter_set.cases)
        .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let cases = parameter_set.cases.iter().map(UiCase::new).collect();
    render(ParameterSetTemplate {
        id: parameter_set.id,
        name: parameter_set.name,
        description: parameter_set.description.unwrap_or_default(),
        cases,
        cases_json,
        message: query.message,
    })
}

#[derive(Deserialize)]
struct EditParameterSetForm {
    parameter_set_name: String,
    #[serde(default)]
    parameter_set_description: String,
    cases_json: String,
}

async fn edit_parameter_set(
    State(state): State<Arc<AppState>>,
    Path(parameter_set_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<EditParameterSetForm>,
) -> Result<Response, ServiceError> {
    let current = state
        .database
        .export_parameter_set(&parameter_set_id)
        .await?;
    let cases: Vec<ParameterCase> = serde_json::from_str(&form.cases_json)
        .map_err(|error| ServiceError::BadRequest(format!("invalid edited cases: {error}")))?;
    let parameter_set = ParameterSetFile {
        format: "lattice-security/parameter-set".to_owned(),
        version: FILE_FORMAT_VERSION,
        id: current.id,
        name: form.parameter_set_name,
        description: (!form.parameter_set_description.trim().is_empty())
            .then_some(form.parameter_set_description),
        tags: current.tags,
        cases,
    };
    parameter_set.validate()?;
    state
        .database
        .import_parameter_set(parameter_set, true)
        .await?;
    redirect(
        &headers,
        &format!(
            "/ui/parameter-sets/{parameter_set_id}?message=Parameter+set+updated+as+a+new+version"
        ),
    )
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

fn redirect(headers: &HeaderMap, location: &str) -> Result<Response, ServiceError> {
    let mut response = StatusCode::SEE_OTHER.into_response();
    let location = HeaderValue::from_str(location)
        .map_err(|error| ServiceError::BadRequest(error.to_string()))?;
    if headers.contains_key("hx-request") {
        response.headers_mut().insert("hx-redirect", location);
    } else {
        response.headers_mut().insert(header::LOCATION, location);
    }
    Ok(response)
}

fn estimate_from_cases(
    cases: Vec<ParameterCase>,
    mode: EstimateMode,
    timeout_seconds: u64,
    required_security_bits: &str,
    stop_margin_bits: &str,
) -> Result<EstimateRequest, ServiceError> {
    let request = EstimateRequest {
        cases,
        mode,
        timeout_seconds,
        slow_attack_policy: if mode == EstimateMode::Normal {
            Some(SlowAttackPolicy {
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

const fn default_timeout() -> u64 {
    3_600
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

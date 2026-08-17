use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{
        DefaultBodyLimit, Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::{
    EstimateRequest, ParameterSetFile, SweepRequest, Validate,
    error::ServiceError,
    service::{AppState, BatchSnapshot},
};

const REQUEST_BODY_LIMIT: usize = 8 * 1024 * 1024;

pub fn router(state: Arc<AppState>) -> Router {
    let token = state.api_token.clone();
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/metadata", get(metadata))
        .route("/v1/estimates", post(estimate))
        .route("/v1/sweeps", post(sweep))
        .route("/v1/batches/{batch_id}", get(batch))
        .route("/v1/batches/{batch_id}/cancel", post(cancel))
        .route("/v1/batches/{batch_id}/rerun", post(rerun))
        .route("/v1/batches/{batch_id}/export", get(export_report))
        .route("/v1/results/{batch_id}", get(export_report))
        .route("/v1/jobs/{job_id}", get(job))
        .route("/v1/parameter-sets/import", post(import_parameter_set))
        .route(
            "/v1/parameter-sets/{parameter_set_id}/export",
            get(export_parameter_set),
        )
        .merge(crate::ui::routes())
        .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT))
        .with_state(state)
        .layer(middleware::from_fn_with_state(token, authenticate))
}

async fn authenticate(
    State(token): State<Option<String>>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Result<Response, ServiceError> {
    let Some(expected) = token else {
        return Ok(next.run(request).await);
    };
    let path = request.uri().path();
    if path == "/login" || path.starts_with("/assets/") {
        return Ok(next.run(request).await);
    }
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (name, value) = cookie.trim().split_once('=')?;
                (name == "lattice_security_token").then_some(value)
            })
        });
    if supplied != Some(expected.as_str()) && cookie != Some(expected.as_str()) {
        if path.starts_with("/v1/") || path == "/healthz" {
            return Err(ServiceError::Unauthorized);
        }
        let mut response = StatusCode::SEE_OTHER.into_response();
        response
            .headers_mut()
            .insert(header::LOCATION, HeaderValue::from_static("/login"));
        return Ok(response);
    }
    Ok(next.run(request).await)
}

#[derive(Serialize)]
struct Health<'a> {
    status: &'a str,
}

async fn health() -> Json<Health<'static>> {
    Json(Health { status: "ok" })
}

async fn metadata(State(state): State<Arc<AppState>>) -> Json<crate::upstream::Metadata> {
    Json(state.metadata.clone())
}

async fn estimate(
    State(state): State<Arc<AppState>>,
    payload: Result<Json<EstimateRequest>, JsonRejection>,
) -> Result<Response, ServiceError> {
    let request = json_payload(payload)?;
    submit(&state, request).await
}

async fn sweep(
    State(state): State<Arc<AppState>>,
    payload: Result<Json<SweepRequest>, JsonRejection>,
) -> Result<Response, ServiceError> {
    let request = json_payload(payload)?;
    let cases = crate::sweep::expand(&request)?;
    let case_count = cases.len();
    let mut batches = Vec::with_capacity(case_count.div_ceil(500));
    for chunk in cases.chunks(500) {
        let estimate = EstimateRequest {
            cases: chunk.to_vec(),
            timeout_seconds: request.timeout_seconds,
            slow_attack_policy: request.slow_attack_policy.clone(),
        };
        batches.push(
            state
                .scheduler
                .submit_staged(estimate, state.poll_after_seconds)
                .await?,
        );
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(crate::sweep::response(batches, case_count)),
    )
        .into_response())
}

async fn submit(state: &AppState, request: EstimateRequest) -> Result<Response, ServiceError> {
    request.validate()?;
    let (cached, snapshot) = state
        .scheduler
        .submit(request, state.poll_after_seconds)
        .await?;
    let status = if cached {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    snapshot_response(status, snapshot)
}

async fn batch(
    State(state): State<Arc<AppState>>,
    Path(batch_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ServiceError> {
    let snapshot = state
        .database
        .batch(&batch_id, state.poll_after_seconds)
        .await?;
    let etag = format!("\"{}\"", snapshot.revision);
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        == Some(etag.as_str())
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        response.headers_mut().insert(
            header::ETAG,
            HeaderValue::from_str(&etag)
                .map_err(|error| ServiceError::Internal(error.to_string()))?,
        );
        return Ok(response);
    }
    snapshot_response(StatusCode::OK, snapshot)
}

fn snapshot_response(
    status: StatusCode,
    snapshot: BatchSnapshot,
) -> Result<Response, ServiceError> {
    let etag = format!("\"{}\"", snapshot.revision);
    let mut response = (status, Json(snapshot)).into_response();
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&etag).map_err(|error| ServiceError::Internal(error.to_string()))?,
    );
    Ok(response)
}

async fn job(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<String>,
) -> Result<impl IntoResponse, ServiceError> {
    Ok(Json(state.database.job(&job_id).await?))
}

async fn cancel(
    State(state): State<Arc<AppState>>,
    Path(batch_id): Path<String>,
) -> Result<Response, ServiceError> {
    let snapshot = state
        .scheduler
        .cancel(&batch_id, state.poll_after_seconds)
        .await?;
    snapshot_response(StatusCode::OK, snapshot)
}

async fn rerun(
    State(state): State<Arc<AppState>>,
    Path(batch_id): Path<String>,
) -> Result<Response, ServiceError> {
    let request = state.database.batch_request(&batch_id).await?;
    submit(&state, request).await
}

async fn export_report(
    State(state): State<Arc<AppState>>,
    Path(batch_id): Path<String>,
) -> Result<Response, ServiceError> {
    let snapshot = state
        .database
        .batch(&batch_id, state.poll_after_seconds)
        .await?;
    match snapshot.report {
        Some(report) => Ok(Json(report).into_response()),
        None => Err(ServiceError::Conflict(
            "batch does not have an exportable report yet".to_owned(),
        )),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ConflictPolicy {
    Reject,
    Replace,
}

#[derive(Deserialize)]
struct ImportQuery {
    #[serde(default = "reject")]
    conflict: ConflictPolicy,
}

const fn reject() -> ConflictPolicy {
    ConflictPolicy::Reject
}

async fn import_parameter_set(
    State(state): State<Arc<AppState>>,
    query: Result<Query<ImportQuery>, QueryRejection>,
    payload: Result<Json<ParameterSetFile>, JsonRejection>,
) -> Result<Response, ServiceError> {
    let Query(query) = query.map_err(|error| ServiceError::BadRequest(error.to_string()))?;
    let parameter_set = json_payload(payload)?;
    parameter_set.validate()?;
    let imported = state
        .database
        .import_parameter_set(
            parameter_set,
            matches!(query.conflict, ConflictPolicy::Replace),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(imported)).into_response())
}

fn json_payload<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, ServiceError> {
    match payload {
        Ok(Json(value)) => Ok(value),
        Err(error) if error.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            Err(ServiceError::PayloadTooLarge)
        }
        Err(error) => Err(ServiceError::BadRequest(error.body_text())),
    }
}

async fn export_parameter_set(
    State(state): State<Arc<AppState>>,
    Path(parameter_set_id): Path<String>,
) -> Result<impl IntoResponse, ServiceError> {
    Ok(Json(
        state
            .database
            .export_parameter_set(&parameter_set_id)
            .await?,
    ))
}

pub async fn serve(listener: tokio::net::TcpListener, state: Arc<AppState>) -> std::io::Result<()> {
    axum::serve(listener, router(state).into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
}

async fn shutdown_signal() {
    let control_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl+C handler");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "failed to install SIGTERM handler"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = control_c => {}
        () = terminate => {}
    }
}

#[allow(dead_code)]
fn empty_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("static response")
}

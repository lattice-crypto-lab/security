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
    EstimateRequest, ParameterSetFile,
    error::ServiceError,
    service::{AppState, BatchSnapshot},
};

const REQUEST_BODY_LIMIT: usize = 8 * 1024 * 1024;

pub fn router(state: Arc<AppState>) -> Router {
    let token = state.api_token.clone();
    let api = Router::new()
        .route("/healthz", get(health))
        .route("/v1/metadata", get(metadata))
        .route("/v1/estimates", post(estimate))
        .route("/v1/batches", get(batches))
        .route("/v1/batches/{batch_id}", get(batch).delete(delete_batch))
        .route("/v1/batches/{batch_id}/cancel", post(cancel))
        .route("/v1/batches/{batch_id}/rerun", post(rerun))
        .route("/v1/batches/{batch_id}/export", get(export_report))
        .route("/v1/parameter-sets", get(parameter_sets))
        .route("/v1/parameter-sets/import", post(import_parameter_set))
        .route(
            "/v1/parameter-sets/{parameter_set_id}",
            get(export_parameter_set).delete(delete_parameter_set),
        )
        .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(token, authenticate));
    api.merge(crate::web::routes(&state.web_dir))
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
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if supplied != Some(expected.as_str()) {
        return Err(ServiceError::Unauthorized);
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
    Json(state.application.metadata().clone())
}

async fn estimate(
    State(state): State<Arc<AppState>>,
    payload: Result<Json<EstimateRequest>, JsonRejection>,
) -> Result<Response, ServiceError> {
    let request = json_payload(payload)?;
    submit(&state, request).await
}

async fn submit(state: &AppState, request: EstimateRequest) -> Result<Response, ServiceError> {
    let submission = state.application.estimate(request).await?;
    let status = if submission.fully_cached {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    snapshot_response(status, submission.snapshot)
}

async fn batch(
    State(state): State<Arc<AppState>>,
    Path(batch_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ServiceError> {
    let snapshot = state.application.batch(&batch_id).await?;
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

async fn batches(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<crate::application::BatchRecord>>, ServiceError> {
    Ok(Json(state.application.batches().await?))
}

async fn delete_batch(
    State(state): State<Arc<AppState>>,
    Path(batch_id): Path<String>,
) -> Result<StatusCode, ServiceError> {
    state.application.delete_batch(batch_id).await?;
    Ok(StatusCode::NO_CONTENT)
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

async fn cancel(
    State(state): State<Arc<AppState>>,
    Path(batch_id): Path<String>,
) -> Result<Response, ServiceError> {
    let snapshot = state.application.cancel(&batch_id).await?;
    snapshot_response(StatusCode::OK, snapshot)
}

async fn rerun(
    State(state): State<Arc<AppState>>,
    Path(batch_id): Path<String>,
) -> Result<Response, ServiceError> {
    let submission = state.application.rerun(&batch_id).await?;
    let status = if submission.fully_cached {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    snapshot_response(status, submission.snapshot)
}

async fn export_report(
    State(state): State<Arc<AppState>>,
    Path(batch_id): Path<String>,
) -> Result<Response, ServiceError> {
    Ok(Json(state.application.report(&batch_id).await?).into_response())
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
    let imported = state
        .application
        .import_parameter_set(
            parameter_set,
            matches!(query.conflict, ConflictPolicy::Replace),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(imported)).into_response())
}

async fn parameter_sets(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<crate::application::ParameterSetSummary>>, ServiceError> {
    Ok(Json(state.application.parameter_sets().await?))
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
        state.application.parameter_set(&parameter_set_id).await?,
    ))
}

async fn delete_parameter_set(
    State(state): State<Arc<AppState>>,
    Path(parameter_set_id): Path<String>,
) -> Result<StatusCode, ServiceError> {
    state
        .application
        .delete_parameter_set(&parameter_set_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
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

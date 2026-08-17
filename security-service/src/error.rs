use std::collections::BTreeMap;

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::Value;
use uuid::Uuid;

use crate::{ErrorEnvelope, ValidationError};

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("{0}")]
    Invalid(ValidationError),
    #[error("{0}")]
    BadRequest(String),
    #[error("request body exceeds 8388608 bytes")]
    PayloadTooLarge,
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("authentication required")]
    Unauthorized,
    #[error("job queue is full")]
    QueueFull,
    #[error("estimator unavailable: {0}")]
    Upstream(String),
    #[error("estimator timed out: {0}")]
    UpstreamTimeout(String),
    #[error("database failure: {0}")]
    Database(String),
    #[error("internal failure: {0}")]
    Internal(String),
}

impl ServiceError {
    pub fn database(error: impl std::fmt::Display) -> Self {
        Self::Database(error.to_string())
    }

    fn response_parts(&self) -> (StatusCode, &'static str, Option<String>) {
        match self {
            Self::Invalid(error) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_request",
                Some(error.path.clone()),
            ),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request", None),
            Self::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_body_too_large",
                None,
            ),
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "not_found", None),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict", None),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", None),
            Self::QueueFull => (StatusCode::SERVICE_UNAVAILABLE, "queue_full", None),
            Self::Upstream(_) => (StatusCode::BAD_GATEWAY, "estimator_unavailable", None),
            Self::UpstreamTimeout(_) => (StatusCode::GATEWAY_TIMEOUT, "estimator_timeout", None),
            Self::Database(_) | Self::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", None)
            }
        }
    }
}

impl From<ValidationError> for ServiceError {
    fn from(value: ValidationError) -> Self {
        Self::Invalid(value)
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> axum::response::Response {
        let (status, code, path) = self.response_parts();
        let message = if matches!(self, Self::Database(_) | Self::Internal(_)) {
            "internal service failure".to_owned()
        } else {
            self.to_string()
        };
        let envelope = ErrorEnvelope {
            code: code.to_owned(),
            message,
            path,
            request_id: Uuid::new_v4().to_string(),
            details: BTreeMap::<String, Value>::new(),
        };
        (status, Json(envelope)).into_response()
    }
}

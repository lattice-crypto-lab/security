use std::time::Duration;

use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::{
    ApproximationMetadata, Attack, EstimatorContext, EstimatorProblem, ExactDecimal,
    NormalizedMetric, ReductionCostModel, ReductionShapeModel, ResolvedAnalysisSettings,
    error::ServiceError,
};

#[derive(Clone)]
pub struct EstimatorClient {
    client: reqwest::Client,
    base_url: Url,
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Metadata {
    pub adapter_schema_version: u64,
    pub dependency_graph_version: u64,
    pub estimator_commit: String,
    pub sage_version: String,
    pub adapter_version: String,
    pub worker_image: String,
    pub platform: String,
    pub support_matrix: serde_json::Value,
    pub dependency_graph: serde_json::Value,
    pub adaptive_attacks: Vec<Attack>,
    #[serde(default)]
    pub slow_attack_applicability_rule_version: u32,
    #[serde(default)]
    pub approximation: ApproximationMetadata,
}

impl Metadata {
    pub fn context(&self) -> EstimatorContext {
        EstimatorContext {
            estimator_commit: self.estimator_commit.clone(),
            sage_version: self.sage_version.clone(),
            adapter_version: self.adapter_version.clone(),
            worker_image: self.worker_image.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub schema_version: u32,
    pub problem: EstimatorProblem,
    pub models: WorkerModels,
    pub target_attacks: Vec<Attack>,
    pub timeout_seconds: u64,
}

impl WorkerRequest {
    pub fn new(
        problem: EstimatorProblem,
        analysis: &ResolvedAnalysisSettings,
        target_attacks: Vec<Attack>,
        timeout_seconds: u64,
    ) -> Self {
        Self {
            schema_version: 2,
            problem,
            models: WorkerModels {
                cost_model: analysis.cost_model,
                shape_model: analysis.shape_model,
            },
            target_attacks,
            timeout_seconds,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct WorkerModels {
    pub cost_model: ReductionCostModel,
    pub shape_model: ReductionShapeModel,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WorkerResponse {
    pub results: Vec<WorkerAttackExecution>,
    pub duration_ms: u64,
    pub provenance: WorkerProvenance,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WorkerProvenance {
    pub estimator_commit: String,
    pub sage_version: String,
    pub adapter_version: String,
    pub worker_image: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WorkerAttackExecution {
    pub attack: Attack,
    pub role: ResultRole,
    pub outcome: WorkerOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultRole {
    Target,
    Support,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkerOutcome {
    Computed {
        security_bits: ExactDecimal,
        #[serde(default)]
        metrics: std::collections::BTreeMap<String, NormalizedMetric>,
    },
    NoFiniteEstimate {
        code: String,
        reason: String,
        #[serde(default)]
        raw_result: Option<serde_json::Value>,
    },
    Unsupported {
        code: String,
        reason: String,
    },
    Failed {
        code: String,
        message: String,
        retryable: bool,
    },
}

impl EstimatorClient {
    pub fn new(base_url: &str) -> Result<Self, ServiceError> {
        let base_url = Url::parse(base_url)
            .map_err(|error| ServiceError::BadRequest(format!("invalid estimator URL: {error}")))?;
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        Ok(Self { client, base_url })
    }

    pub async fn metadata(&self) -> Result<Metadata, ServiceError> {
        let url = self
            .base_url
            .join("v1/metadata")
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| ServiceError::Upstream(error.to_string()))?;
        decode(response).await
    }

    pub async fn estimate(&self, request: &WorkerRequest) -> Result<WorkerResponse, ServiceError> {
        let url = self
            .base_url
            .join("v1/estimate")
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        let response = self
            .client
            .post(url)
            .json(request)
            .send()
            .await
            .map_err(|error| ServiceError::Upstream(error.to_string()))?;
        decode(response).await
    }
}

async fn decode<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, ServiceError> {
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|error| ServiceError::Upstream(error.to_string()))?;
    if !status.is_success() {
        let detail = String::from_utf8_lossy(&bytes);
        if status == reqwest::StatusCode::GATEWAY_TIMEOUT {
            return Err(ServiceError::UpstreamTimeout(detail.into_owned()));
        }
        return Err(ServiceError::Upstream(format!(
            "worker returned {status}: {}",
            &detail[..detail.len().min(2_048)]
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| ServiceError::Upstream(format!("invalid worker response: {error}")))
}

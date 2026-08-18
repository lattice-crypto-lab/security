use std::{path::PathBuf, sync::Arc};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ApproximationEngine, SecurityReportFile,
    database::Database,
    error::ServiceError,
    scheduler::{Scheduler, SchedulerHandle},
    upstream::{EstimatorClient, Metadata},
};

pub const MAX_QUEUED_JOBS: usize = 2_000;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind: String,
    pub database_path: PathBuf,
    pub estimator_url: String,
    pub poll_after_seconds: u64,
    pub api_token: Option<String>,
    pub approximation_model_path: Option<PathBuf>,
}

impl AppConfig {
    pub fn from_environment() -> Result<Self, ServiceError> {
        Ok(Self {
            bind: std::env::var("LATTICE_SECURITY_BIND")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_owned()),
            database_path: std::env::var_os("LATTICE_SECURITY_DATABASE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib/lattice-security/lattice-security.db")),
            estimator_url: std::env::var("ESTIMATOR_API_URL")
                .unwrap_or_else(|_| "http://estimator-api:8000/".to_owned()),
            poll_after_seconds: 1,
            api_token: std::env::var("LATTICE_SECURITY_API_TOKEN")
                .ok()
                .filter(|value| !value.is_empty()),
            approximation_model_path: std::env::var_os("LATTICE_SECURITY_APPROXIMATION_MODEL")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunState {
    Pending {
        staged_at: String,
    },
    Queued {
        queued_at: String,
    },
    Running {
        started_at: String,
        heartbeat_at: String,
    },
    CancelRequested {
        requested_at: String,
    },
    Cancelled {
        finished_at: String,
    },
    Completed {
        finished_at: String,
    },
    Partial {
        finished_at: String,
    },
    TimedOut {
        finished_at: String,
    },
    Interrupted {
        interrupted_at: String,
    },
    Failed {
        finished_at: String,
        code: String,
        message: String,
    },
}

impl RunState {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Pending { .. } => "pending",
            Self::Queued { .. } => "queued",
            Self::Running { .. } => "running",
            Self::CancelRequested { .. } => "cancel_requested",
            Self::Cancelled { .. } => "cancelled",
            Self::Completed { .. } => "completed",
            Self::Partial { .. } => "partial",
            Self::TimedOut { .. } => "timed_out",
            Self::Interrupted { .. } => "interrupted",
            Self::Failed { .. } => "failed",
        }
    }

    pub fn terminal(&self) -> bool {
        matches!(
            self,
            Self::Cancelled { .. }
                | Self::Completed { .. }
                | Self::Partial { .. }
                | Self::TimedOut { .. }
                | Self::Failed { .. }
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BatchSnapshot {
    pub batch_id: String,
    pub state: RunState,
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
    pub poll_after_seconds: u64,
    pub job_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<SecurityReportFile>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct JobSnapshot {
    pub job_id: String,
    pub batch_id: String,
    pub case_id: String,
    pub case_index: usize,
    pub state: RunState,
    pub revision: u64,
    pub attempts: u32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone)]
pub struct AppState {
    pub database: Database,
    pub scheduler: SchedulerHandle,
    pub metadata: Metadata,
    pub poll_after_seconds: u64,
    pub api_token: Option<String>,
}

impl AppState {
    pub async fn start(config: &AppConfig) -> Result<Arc<Self>, ServiceError> {
        let database = Database::open(&config.database_path)?;
        let upstream = EstimatorClient::new(&config.estimator_url)?;
        let mut metadata = upstream.metadata().await?;
        let approximation = ApproximationEngine::load(
            config.approximation_model_path.as_deref(),
            &metadata.context(),
        )?;
        metadata.approximation = approximation.metadata();
        let (scheduler, handle) =
            Scheduler::new(database.clone(), upstream, metadata.clone(), approximation);
        let state = Arc::new(Self {
            database,
            scheduler: handle,
            metadata,
            poll_after_seconds: config.poll_after_seconds,
            api_token: config.api_token.clone(),
        });
        scheduler.start().await?;
        Ok(state)
    }
}

pub fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC3339 formatting cannot fail")
}

//! Application use-cases shared by the HTTP API and other transports.
//!
//! This is intentionally a concrete facade, not a framework of repository
//! traits. Domain rules stay in the core types; SQLite and the scheduler stay
//! implementation details behind these operations.

use crate::{
    EstimateRequest, ParameterSetFile, SecurityReportFile, Validate, database::Database,
    error::ServiceError, scheduler::SchedulerHandle, service::BatchSnapshot, upstream::Metadata,
};

#[derive(Clone)]
pub struct Application {
    database: Database,
    scheduler: SchedulerHandle,
    metadata: Metadata,
    poll_after_seconds: u64,
}

pub struct Submission {
    pub fully_cached: bool,
    pub snapshot: BatchSnapshot,
}

#[derive(serde::Serialize)]
pub struct BatchRecord {
    pub snapshot: BatchSnapshot,
    pub request: EstimateRequest,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ImportedParameterSet {
    pub id: String,
    pub version: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ParameterSetSummary {
    pub id: String,
    pub name: String,
    pub version: u64,
    pub case_count: usize,
    pub created_at: String,
}

impl Application {
    pub(crate) fn new(
        database: Database,
        scheduler: SchedulerHandle,
        metadata: Metadata,
        poll_after_seconds: u64,
    ) -> Self {
        Self {
            database,
            scheduler,
            metadata,
            poll_after_seconds,
        }
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub async fn estimate(&self, request: EstimateRequest) -> Result<Submission, ServiceError> {
        request.validate()?;
        let (fully_cached, snapshot) = self
            .scheduler
            .submit(request, self.poll_after_seconds)
            .await?;
        Ok(Submission {
            fully_cached,
            snapshot,
        })
    }

    pub async fn batch(&self, id: &str) -> Result<BatchSnapshot, ServiceError> {
        self.database.batch(id, self.poll_after_seconds).await
    }

    pub async fn batches(&self) -> Result<Vec<BatchRecord>, ServiceError> {
        Ok(self
            .database
            .list_batches_with_requests(200, self.poll_after_seconds)
            .await?
            .into_iter()
            .map(|(snapshot, request)| BatchRecord { snapshot, request })
            .collect())
    }

    pub async fn cancel(&self, id: &str) -> Result<BatchSnapshot, ServiceError> {
        self.scheduler.cancel(id, self.poll_after_seconds).await
    }

    pub async fn rerun(&self, id: &str) -> Result<Submission, ServiceError> {
        self.estimate(self.database.batch_request(id).await?).await
    }

    pub async fn report(&self, id: &str) -> Result<SecurityReportFile, ServiceError> {
        self.batch(id).await?.report.ok_or_else(|| {
            ServiceError::Conflict("batch does not have an exportable report yet".to_owned())
        })
    }

    pub async fn delete_batch(&self, id: String) -> Result<(), ServiceError> {
        self.database.delete_batches(vec![id]).await
    }

    pub async fn parameter_sets(&self) -> Result<Vec<ParameterSetSummary>, ServiceError> {
        self.database.list_parameter_sets().await
    }

    pub async fn parameter_set(&self, id: &str) -> Result<ParameterSetFile, ServiceError> {
        self.database.export_parameter_set(id).await
    }

    pub async fn import_parameter_set(
        &self,
        value: ParameterSetFile,
        replace: bool,
    ) -> Result<ImportedParameterSet, ServiceError> {
        value.validate()?;
        self.database.import_parameter_set(value, replace).await
    }

    pub async fn delete_parameter_set(&self, id: &str) -> Result<(), ServiceError> {
        self.database.delete_parameter_set(id).await
    }
}

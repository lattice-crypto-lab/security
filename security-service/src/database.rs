use std::{
    path::Path,
    sync::mpsc::{self, Sender},
    thread,
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::{
    AttackOutcome, EstimateRequest, ParameterCase, ParameterSetFile, SecurityReportEntry,
    SecurityReportFile,
    error::ServiceError,
    service::{BatchSnapshot, JobSnapshot, MAX_QUEUED_JOBS, RunState, now},
};

type DbResult<T> = Result<T, ServiceError>;
type Command = Box<dyn FnOnce(&mut Connection) + Send + 'static>;

#[derive(Clone)]
pub struct Database {
    sender: Sender<Command>,
}

#[derive(Clone, Debug)]
pub struct JobWork {
    pub job_id: String,
    pub batch_id: String,
    pub case_index: usize,
    pub case: ParameterCase,
    pub request: EstimateRequest,
    pub attempts: u32,
}

#[derive(Clone, Debug)]
pub struct CachedOutcome {
    pub outcome: AttackOutcome,
}

#[derive(Clone, Debug, serde::Serialize, schemars::JsonSchema)]
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

impl Database {
    pub fn open(path: &Path) -> DbResult<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(ServiceError::database)?;
        }
        let path = path.to_owned();
        let (sender, receiver) = mpsc::channel::<Command>();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("lattice-security-sqlite".to_owned())
            .spawn(move || {
                let connection = Connection::open(path)
                    .map_err(ServiceError::database)
                    .and_then(initialize);
                match connection {
                    Ok(mut connection) => {
                        let _ = ready_sender.send(Ok(()));
                        while let Ok(command) = receiver.recv() {
                            command(&mut connection);
                        }
                    }
                    Err(error) => {
                        let _ = ready_sender.send(Err(error));
                    }
                }
            })
            .map_err(ServiceError::database)?;
        ready_receiver.recv().map_err(ServiceError::database)??;
        Ok(Self { sender })
    }

    async fn call<T, F>(&self, operation: F) -> DbResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> DbResult<T> + Send + 'static,
    {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Box::new(move |connection| {
                let _ = sender.send(operation(connection));
            }))
            .map_err(|_| ServiceError::Database("database thread stopped".to_owned()))?;
        receiver
            .await
            .map_err(|_| ServiceError::Database("database response dropped".to_owned()))?
    }

    pub async fn active_job_count(&self) -> DbResult<usize> {
        self.call(|connection| {
            let count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM jobs WHERE state_kind IN ('queued','running','cancel_requested')",
                    [],
                    |row| row.get(0),
                )
                .map_err(ServiceError::database)?;
            usize::try_from(count).map_err(ServiceError::database)
        })
        .await
    }

    pub async fn create_batch(&self, request: EstimateRequest) -> DbResult<BatchSnapshot> {
        self.create_batch_mode(request, false).await
    }

    pub async fn create_staged_batch(&self, request: EstimateRequest) -> DbResult<BatchSnapshot> {
        self.create_batch_mode(request, true).await
    }

    async fn create_batch_mode(
        &self,
        request: EstimateRequest,
        allow_staging: bool,
    ) -> DbResult<BatchSnapshot> {
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(ServiceError::database)?;
            let active: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM jobs WHERE state_kind IN ('queued','running','cancel_requested')",
                    [],
                    |row| row.get(0),
                )
                .map_err(ServiceError::database)?;
            let active = usize::try_from(active).unwrap_or(usize::MAX);
            if !allow_staging && active + request.cases.len() > MAX_QUEUED_JOBS {
                return Err(ServiceError::QueueFull);
            }
            let queue_slots = MAX_QUEUED_JOBS.saturating_sub(active);

            let batch_id = Uuid::new_v4().to_string();
            let timestamp = now();
            let state = RunState::Queued {
                queued_at: timestamp.clone(),
            };
            let state_json = json(&state)?;
            let request_json = json(&request)?;
            transaction
                .execute(
                    "INSERT INTO batches (id,state_kind,state_json,revision,request_json,created_at,updated_at) VALUES (?1,?2,?3,1,?4,?5,?5)",
                    params![batch_id, state.kind(), state_json, request_json, timestamp],
                )
                .map_err(ServiceError::database)?;

            let mut job_ids = Vec::with_capacity(request.cases.len());
            for (case_index, case) in request.cases.iter().enumerate() {
                let job_id = Uuid::new_v4().to_string();
                let job_state = if allow_staging && case_index >= queue_slots {
                    RunState::Pending {
                        staged_at: timestamp.clone(),
                    }
                } else {
                    state.clone()
                };
                transaction
                    .execute(
                        "INSERT INTO jobs (id,batch_id,case_index,case_id,state_kind,state_json,revision,attempts,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,1,0,?7,?7)",
                        params![
                            job_id,
                            batch_id,
                            i64::try_from(case_index).map_err(ServiceError::database)?,
                            case.id,
                            job_state.kind(),
                            json(&job_state)?,
                            timestamp,
                        ],
                    )
                    .map_err(ServiceError::database)?;
                job_ids.push(job_id);
            }
            transaction.commit().map_err(ServiceError::database)?;
            Ok(BatchSnapshot {
                batch_id,
                state,
                revision: 1,
                created_at: timestamp.clone(),
                updated_at: timestamp,
                poll_after_seconds: 1,
                job_ids,
                report: None,
            })
        })
        .await
    }

    pub async fn batch(&self, batch_id: &str, poll_after_seconds: u64) -> DbResult<BatchSnapshot> {
        let batch_id = batch_id.to_owned();
        self.call(move |connection| load_batch(connection, &batch_id, poll_after_seconds))
            .await
    }

    pub async fn list_batches(
        &self,
        limit: usize,
        poll_after_seconds: u64,
    ) -> DbResult<Vec<BatchSnapshot>> {
        self.call(move |connection| {
            let mut statement = connection
                .prepare("SELECT id FROM batches ORDER BY updated_at DESC LIMIT ?1")
                .map_err(ServiceError::database)?;
            let ids = statement
                .query_map(
                    [i64::try_from(limit).map_err(ServiceError::database)?],
                    |row| row.get::<_, String>(0),
                )
                .map_err(ServiceError::database)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(ServiceError::database)?;
            drop(statement);
            ids.into_iter()
                .map(|id| load_batch(connection, &id, poll_after_seconds))
                .collect()
        })
        .await
    }

    pub async fn list_batches_with_requests(
        &self,
        limit: usize,
        poll_after_seconds: u64,
    ) -> DbResult<Vec<(BatchSnapshot, EstimateRequest)>> {
        self.call(move |connection| {
            let mut statement = connection
                .prepare("SELECT id,request_json FROM batches ORDER BY updated_at DESC LIMIT ?1")
                .map_err(ServiceError::database)?;
            let rows = statement
                .query_map(
                    [i64::try_from(limit).map_err(ServiceError::database)?],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .map_err(ServiceError::database)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(ServiceError::database)?;
            drop(statement);
            rows.into_iter()
                .map(|(id, request)| {
                    Ok((
                        load_batch(connection, &id, poll_after_seconds)?,
                        from_json(&request)?,
                    ))
                })
                .collect()
        })
        .await
    }

    pub async fn job(&self, job_id: &str) -> DbResult<JobSnapshot> {
        let job_id = job_id.to_owned();
        self.call(move |connection| load_job(connection, &job_id))
            .await
    }

    pub async fn queued_jobs(&self) -> DbResult<Vec<String>> {
        self.call(|connection| {
            let mut statement = connection
                .prepare(
                    "SELECT id FROM jobs WHERE state_kind='queued' ORDER BY created_at,case_index",
                )
                .map_err(ServiceError::database)?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(ServiceError::database)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(ServiceError::database)
        })
        .await
    }

    pub async fn promote_pending_jobs(&self) -> DbResult<Vec<String>> {
        self.call(|connection| {
            let transaction = connection.transaction().map_err(ServiceError::database)?;
            let active: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM jobs WHERE state_kind IN ('queued','running','cancel_requested')",
                    [],
                    |row| row.get(0),
                )
                .map_err(ServiceError::database)?;
            let slots = MAX_QUEUED_JOBS
                .saturating_sub(usize::try_from(active).unwrap_or(usize::MAX));
            if slots == 0 {
                return Ok(Vec::new());
            }
            let mut statement = transaction
                .prepare(
                    "SELECT id FROM jobs WHERE state_kind='pending' ORDER BY created_at,case_index LIMIT ?1",
                )
                .map_err(ServiceError::database)?;
            let ids = statement
                .query_map(
                    [i64::try_from(slots).map_err(ServiceError::database)?],
                    |row| row.get::<_, String>(0),
                )
                .map_err(ServiceError::database)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(ServiceError::database)?;
            drop(statement);
            let timestamp = now();
            let state = RunState::Queued {
                queued_at: timestamp.clone(),
            };
            for id in &ids {
                transaction
                    .execute(
                        "UPDATE jobs SET state_kind='queued',state_json=?2,revision=revision+1,updated_at=?3 WHERE id=?1 AND state_kind='pending'",
                        params![id, json(&state)?, timestamp],
                    )
                    .map_err(ServiceError::database)?;
            }
            transaction.commit().map_err(ServiceError::database)?;
            Ok(ids)
        })
        .await
    }

    pub async fn claim_job(&self, job_id: &str) -> DbResult<Option<JobWork>> {
        let job_id = job_id.to_owned();
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(ServiceError::database)?;
            let row = transaction
                .query_row(
                    "SELECT batch_id,case_index,state_kind,attempts FROM jobs WHERE id=?1",
                    [&job_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .optional()
                .map_err(ServiceError::database)?;
            let Some((batch_id, case_index, state_kind, attempts)) = row else {
                return Ok(None);
            };
            if state_kind != "queued" {
                return Ok(None);
            }
            let request_json: String = transaction
                .query_row(
                    "SELECT request_json FROM batches WHERE id=?1",
                    [&batch_id],
                    |row| row.get(0),
                )
                .map_err(ServiceError::database)?;
            let request: EstimateRequest = from_json(&request_json)?;
            let index = usize::try_from(case_index).map_err(ServiceError::database)?;
            let case = request
                .cases
                .get(index)
                .cloned()
                .ok_or_else(|| ServiceError::Database("stored case index is invalid".to_owned()))?;
            let timestamp = now();
            let state = RunState::Running {
                started_at: timestamp.clone(),
                heartbeat_at: timestamp.clone(),
            };
            transaction
                .execute(
                    "UPDATE jobs SET state_kind='running',state_json=?2,revision=revision+1,attempts=attempts+1,updated_at=?3 WHERE id=?1",
                    params![job_id, json(&state)?, timestamp],
                )
                .map_err(ServiceError::database)?;
            transaction
                .execute(
                    "UPDATE batches SET state_kind='running',state_json=?2,revision=revision+1,updated_at=?3 WHERE id=?1 AND state_kind='queued'",
                    params![batch_id, json(&state)?, timestamp],
                )
                .map_err(ServiceError::database)?;
            transaction
                .execute(
                    "INSERT INTO execution_attempts (id,job_id,attempt,state_kind,started_at,heartbeat_at) VALUES (?1,?2,?3,'running',?4,?4)",
                    params![Uuid::new_v4().to_string(), job_id, attempts + 1, timestamp],
                )
                .map_err(ServiceError::database)?;
            transaction.commit().map_err(ServiceError::database)?;
            Ok(Some(JobWork {
                job_id,
                batch_id,
                case_index: index,
                case,
                request,
                attempts: u32::try_from(attempts + 1).map_err(ServiceError::database)?,
            }))
        })
        .await
    }

    pub async fn finish_job(
        &self,
        job_id: &str,
        state: RunState,
        result: Option<SecurityReportEntry>,
    ) -> DbResult<()> {
        let job_id = job_id.to_owned();
        self.call(move |connection| {
            let timestamp = now();
            connection
                .execute(
                    "UPDATE jobs SET state_kind=?2,state_json=?3,result_json=?4,revision=revision+1,updated_at=?5 WHERE id=?1",
                    params![job_id, state.kind(), json(&state)?, result.as_ref().map(json).transpose()?, timestamp],
                )
                .map_err(ServiceError::database)?;
            connection
                .execute(
                    "UPDATE execution_attempts SET state_kind=?2,finished_at=?3 WHERE job_id=?1 AND finished_at IS NULL",
                    params![job_id, state.kind(), timestamp],
                )
                .map_err(ServiceError::database)?;
            Ok(())
        })
        .await
    }

    pub async fn requeue_job(&self, job_id: &str, reason: &str) -> DbResult<()> {
        let job_id = job_id.to_owned();
        let reason = reason.to_owned();
        self.call(move |connection| {
            let timestamp = now();
            let state = RunState::Queued {
                queued_at: timestamp.clone(),
            };
            connection
                .execute(
                    "UPDATE jobs SET state_kind='queued',state_json=?2,revision=revision+1,updated_at=?3 WHERE id=?1",
                    params![job_id, json(&state)?, timestamp],
                )
                .map_err(ServiceError::database)?;
            connection
                .execute(
                    "UPDATE execution_attempts SET state_kind='interrupted',finished_at=?2,error_json=?3 WHERE job_id=?1 AND finished_at IS NULL",
                    params![job_id, timestamp, json(&serde_json::json!({"reason": reason}))?],
                )
                .map_err(ServiceError::database)?;
            Ok(())
        })
        .await
    }

    pub async fn heartbeat_job(&self, job_id: &str) -> DbResult<()> {
        let job_id = job_id.to_owned();
        self.call(move |connection| {
            let timestamp = now();
            let current = connection
                .query_row(
                    "SELECT state_json FROM jobs WHERE id=?1 AND state_kind='running'",
                    [&job_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(ServiceError::database)?;
            if let Some(current) = current {
                let RunState::Running { started_at, .. } = from_json(&current)? else {
                    return Err(ServiceError::Database(
                        "running job has inconsistent state payload".to_owned(),
                    ));
                };
                let state = RunState::Running {
                    started_at,
                    heartbeat_at: timestamp.clone(),
                };
                connection
                    .execute(
                        "UPDATE jobs SET state_json=?2,updated_at=?3 WHERE id=?1 AND state_kind='running'",
                        params![job_id, json(&state)?, timestamp],
                    )
                    .map_err(ServiceError::database)?;
                connection
                    .execute(
                        "UPDATE execution_attempts SET heartbeat_at=?2 WHERE job_id=?1 AND state_kind='running' AND finished_at IS NULL",
                        params![job_id, timestamp],
                    )
                    .map_err(ServiceError::database)?;
            }
            Ok(())
        })
        .await
    }

    pub async fn finalize_batch(
        &self,
        batch_id: &str,
        state: RunState,
        report: Option<SecurityReportFile>,
    ) -> DbResult<()> {
        let batch_id = batch_id.to_owned();
        self.call(move |connection| {
            let timestamp = now();
            connection
                .execute(
                    "UPDATE batches SET state_kind=?2,state_json=?3,report_json=?4,revision=revision+1,updated_at=?5 WHERE id=?1",
                    params![batch_id, state.kind(), json(&state)?, report.as_ref().map(json).transpose()?, timestamp],
                )
                .map_err(ServiceError::database)?;
            Ok(())
        })
        .await
    }

    pub async fn batch_results(&self, batch_id: &str) -> DbResult<Vec<SecurityReportEntry>> {
        let batch_id = batch_id.to_owned();
        self.call(move |connection| {
            let mut statement = connection
                .prepare("SELECT result_json FROM jobs WHERE batch_id=?1 AND result_json IS NOT NULL ORDER BY case_index")
                .map_err(ServiceError::database)?;
            let rows = statement
                .query_map([batch_id], |row| row.get::<_, String>(0))
                .map_err(ServiceError::database)?;
            rows.map(|row| row.map_err(ServiceError::database).and_then(|value| from_json(&value)))
                .collect()
        })
        .await
    }

    pub async fn batch_request(&self, batch_id: &str) -> DbResult<EstimateRequest> {
        let batch_id = batch_id.to_owned();
        self.call(move |connection| {
            let value = connection
                .query_row(
                    "SELECT request_json FROM batches WHERE id=?1",
                    [batch_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(ServiceError::database)?
                .ok_or_else(|| ServiceError::NotFound("batch not found".to_owned()))?;
            from_json(&value)
        })
        .await
    }

    pub async fn delete_batches(&self, batch_ids: Vec<String>) -> DbResult<()> {
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(ServiceError::database)?;
            for batch_id in &batch_ids {
                let state = transaction
                    .query_row(
                        "SELECT state_kind FROM batches WHERE id=?1",
                        [batch_id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(ServiceError::database)?
                    .ok_or_else(|| ServiceError::NotFound("batch not found".to_owned()))?;
                if !matches!(
                    state.as_str(),
                    "completed" | "partial" | "timed_out" | "cancelled" | "failed"
                ) {
                    return Err(ServiceError::Conflict(format!(
                        "batch '{batch_id}' is not finished; cancel it before deleting"
                    )));
                }
            }
            for batch_id in &batch_ids {
                transaction
                    .execute(
                        "DELETE FROM execution_attempts WHERE job_id IN (SELECT id FROM jobs WHERE batch_id=?1)",
                        [batch_id],
                    )
                    .map_err(ServiceError::database)?;
                transaction
                    .execute("DELETE FROM jobs WHERE batch_id=?1", [batch_id])
                    .map_err(ServiceError::database)?;
                transaction
                    .execute("DELETE FROM batches WHERE id=?1", [batch_id])
                    .map_err(ServiceError::database)?;
            }
            transaction.commit().map_err(ServiceError::database)?;
            Ok(())
        })
        .await
    }

    pub async fn request_cancel(&self, batch_id: &str) -> DbResult<BatchSnapshot> {
        let batch_id = batch_id.to_owned();
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(ServiceError::database)?;
            let current: Option<String> = transaction
                .query_row("SELECT state_kind FROM batches WHERE id=?1", [&batch_id], |row| row.get(0))
                .optional()
                .map_err(ServiceError::database)?;
            let Some(current) = current else {
                return Err(ServiceError::NotFound("batch not found".to_owned()));
            };
            if !matches!(current.as_str(), "completed" | "partial" | "cancelled" | "timed_out" | "failed") {
                let timestamp = now();
                let requested = RunState::CancelRequested { requested_at: timestamp.clone() };
                let cancelled = RunState::Cancelled { finished_at: timestamp.clone() };
                transaction.execute(
                    "UPDATE batches SET state_kind='cancel_requested',state_json=?2,revision=revision+1,updated_at=?3 WHERE id=?1",
                    params![batch_id, json(&requested)?, timestamp],
                ).map_err(ServiceError::database)?;
                transaction.execute(
                    "UPDATE jobs SET state_kind='cancelled',state_json=?2,revision=revision+1,updated_at=?3 WHERE batch_id=?1 AND state_kind IN ('pending','queued','interrupted')",
                    params![batch_id, json(&cancelled)?, timestamp],
                ).map_err(ServiceError::database)?;
                transaction.execute(
                    "UPDATE jobs SET state_kind='cancel_requested',state_json=?2,revision=revision+1,updated_at=?3 WHERE batch_id=?1 AND state_kind='running'",
                    params![batch_id, json(&requested)?, timestamp],
                ).map_err(ServiceError::database)?;
            }
            transaction.commit().map_err(ServiceError::database)?;
            load_batch(connection, &batch_id, 1)
        }).await
    }

    pub async fn is_cancel_requested(&self, batch_id: &str) -> DbResult<bool> {
        let batch_id = batch_id.to_owned();
        self.call(move |connection| {
            let state: String = connection
                .query_row(
                    "SELECT state_kind FROM batches WHERE id=?1",
                    [batch_id],
                    |row| row.get(0),
                )
                .map_err(ServiceError::database)?;
            Ok(state == "cancel_requested")
        })
        .await
    }

    pub async fn cached_outcome(&self, key: &str) -> DbResult<Option<CachedOutcome>> {
        let key = key.to_owned();
        self.call(move |connection| {
            let value = connection
                .query_row(
                    "SELECT outcome_json FROM attack_cache WHERE cache_key=?1",
                    [key],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(ServiceError::database)?;
            value
                .map(|value| from_json(&value).map(|outcome| CachedOutcome { outcome }))
                .transpose()
        })
        .await
    }

    pub async fn put_cached_outcome(
        &self,
        key: String,
        attack: crate::Attack,
        outcome: AttackOutcome,
        context_json: String,
    ) -> DbResult<()> {
        self.call(move |connection| {
            connection.execute(
                "INSERT OR IGNORE INTO attack_cache (cache_key,attack,outcome_json,estimator_context_json,created_at) VALUES (?1,?2,?3,?4,?5)",
                params![key, json(&attack)?, json(&outcome)?, context_json, now()],
            ).map_err(ServiceError::database)?;
            Ok(())
        }).await
    }

    pub async fn cached_approximation(&self, key: &str) -> DbResult<Option<CachedOutcome>> {
        let key = key.to_owned();
        self.call(move |connection| {
            let value = connection
                .query_row(
                    "SELECT outcome_json FROM approximation_cache WHERE cache_key=?1",
                    [key],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(ServiceError::database)?;
            value
                .map(|value| from_json(&value).map(|outcome| CachedOutcome { outcome }))
                .transpose()
        })
        .await
    }

    pub async fn put_cached_approximation(
        &self,
        key: String,
        attack: crate::Attack,
        outcome: AttackOutcome,
        model_hash: String,
    ) -> DbResult<()> {
        self.call(move |connection| {
            connection
                .execute(
                    "INSERT OR IGNORE INTO approximation_cache (cache_key,attack,outcome_json,model_hash,created_at) VALUES (?1,?2,?3,?4,?5)",
                    params![key, json(&attack)?, json(&outcome)?, model_hash, now()],
                )
                .map_err(ServiceError::database)?;
            Ok(())
        })
        .await
    }

    pub async fn import_parameter_set(
        &self,
        parameter_set: ParameterSetFile,
        replace: bool,
    ) -> DbResult<ImportedParameterSet> {
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(ServiceError::database)?;
            let current: Option<(String, i64)> = transaction.query_row(
                "SELECT h.internal_id,p.version FROM parameter_set_heads h JOIN parameter_sets p ON p.internal_id=h.internal_id WHERE h.external_id=?1",
                [&parameter_set.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional().map_err(ServiceError::database)?;
            if current.is_some() && !replace {
                return Err(ServiceError::Conflict(format!("parameter set '{}' already exists", parameter_set.id)));
            }
            let version = current.map_or(1, |(_, version)| version + 1);
            let internal_id = Uuid::new_v4().to_string();
            let timestamp = now();
            transaction.execute(
                "INSERT INTO parameter_sets (internal_id,external_id,version,name,document_json,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
                params![internal_id, parameter_set.id, version, parameter_set.name, json(&parameter_set)?, timestamp],
            ).map_err(ServiceError::database)?;
            transaction.execute(
                "INSERT INTO parameter_set_heads (external_id,internal_id) VALUES (?1,?2) ON CONFLICT(external_id) DO UPDATE SET internal_id=excluded.internal_id",
                params![parameter_set.id, internal_id],
            ).map_err(ServiceError::database)?;
            transaction.commit().map_err(ServiceError::database)?;
            Ok(ImportedParameterSet { id: parameter_set.id, version: u64::try_from(version).map_err(ServiceError::database)? })
        }).await
    }

    pub async fn export_parameter_set(&self, external_id: &str) -> DbResult<ParameterSetFile> {
        let external_id = external_id.to_owned();
        self.call(move |connection| {
            let value = connection.query_row(
                "SELECT p.document_json FROM parameter_set_heads h JOIN parameter_sets p ON p.internal_id=h.internal_id WHERE h.external_id=?1",
                [external_id],
                |row| row.get::<_, String>(0),
            ).optional().map_err(ServiceError::database)?
                .ok_or_else(|| ServiceError::NotFound("parameter set not found".to_owned()))?;
            from_json(&value)
        }).await
    }

    pub async fn delete_parameter_set(&self, external_id: &str) -> DbResult<()> {
        let external_id = external_id.to_owned();
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(ServiceError::database)?;
            let deleted = transaction
                .execute(
                    "DELETE FROM parameter_set_heads WHERE external_id=?1",
                    [&external_id],
                )
                .map_err(ServiceError::database)?;
            if deleted == 0 {
                return Err(ServiceError::NotFound("parameter set not found".to_owned()));
            }
            transaction
                .execute(
                    "DELETE FROM parameter_sets WHERE external_id=?1",
                    [&external_id],
                )
                .map_err(ServiceError::database)?;
            transaction.commit().map_err(ServiceError::database)?;
            Ok(())
        })
        .await
    }

    pub async fn list_parameter_sets(&self) -> DbResult<Vec<ParameterSetSummary>> {
        self.call(|connection| {
            let mut statement = connection
                .prepare(
                    "SELECT p.external_id,p.name,p.version,p.document_json,p.created_at FROM parameter_set_heads h JOIN parameter_sets p ON p.internal_id=h.internal_id ORDER BY p.created_at DESC",
                )
                .map_err(ServiceError::database)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(ServiceError::database)?;
            rows.map(|row| {
                let (id, name, version, document, created_at) =
                    row.map_err(ServiceError::database)?;
                let parameter_set: ParameterSetFile = from_json(&document)?;
                Ok(ParameterSetSummary {
                    id,
                    name,
                    version: u64::try_from(version).map_err(ServiceError::database)?,
                    case_count: parameter_set.cases.len(),
                    created_at,
                })
            })
            .collect()
        })
        .await
    }
}

fn initialize(connection: Connection) -> DbResult<Connection> {
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(ServiceError::database)?;
    connection.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA foreign_keys=ON;
         PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);
         CREATE TABLE IF NOT EXISTS parameter_sets (
            internal_id TEXT PRIMARY KEY, external_id TEXT NOT NULL, version INTEGER NOT NULL,
            name TEXT NOT NULL, document_json TEXT NOT NULL, created_at TEXT NOT NULL,
            UNIQUE(external_id,version));
         CREATE TABLE IF NOT EXISTS parameter_set_heads (
            external_id TEXT PRIMARY KEY, internal_id TEXT NOT NULL REFERENCES parameter_sets(internal_id));
         CREATE TABLE IF NOT EXISTS batches (
            id TEXT PRIMARY KEY, state_kind TEXT NOT NULL, state_json TEXT NOT NULL,
            revision INTEGER NOT NULL, request_json TEXT NOT NULL, report_json TEXT,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES batches(id),
            case_index INTEGER NOT NULL, case_id TEXT NOT NULL, state_kind TEXT NOT NULL,
            state_json TEXT NOT NULL, revision INTEGER NOT NULL, attempts INTEGER NOT NULL,
            result_json TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            UNIQUE(batch_id,case_index));
         CREATE INDEX IF NOT EXISTS jobs_state_index ON jobs(state_kind,created_at);
         CREATE TABLE IF NOT EXISTS attack_cache (
            cache_key TEXT PRIMARY KEY, attack TEXT NOT NULL, outcome_json TEXT NOT NULL,
            estimator_context_json TEXT NOT NULL, created_at TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS approximation_cache (
            cache_key TEXT PRIMARY KEY, attack TEXT NOT NULL, outcome_json TEXT NOT NULL,
            model_hash TEXT NOT NULL, created_at TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS execution_attempts (
            id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id), attempt INTEGER NOT NULL,
            state_kind TEXT NOT NULL, started_at TEXT NOT NULL, heartbeat_at TEXT,
            finished_at TEXT, error_json TEXT);
         INSERT OR IGNORE INTO schema_migrations(version) VALUES (1);",
    ).map_err(ServiceError::database)?;

    let has_heartbeat: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('execution_attempts') WHERE name='heartbeat_at')",
            [],
            |row| row.get(0),
        )
        .map_err(ServiceError::database)?;
    if !has_heartbeat {
        connection
            .execute_batch("ALTER TABLE execution_attempts ADD COLUMN heartbeat_at TEXT;")
            .map_err(ServiceError::database)?;
    }
    connection
        .execute(
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES (2)",
            [],
        )
        .map_err(ServiceError::database)?;
    connection
        .execute(
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES (3)",
            [],
        )
        .map_err(ServiceError::database)?;

    let timestamp = now();
    let queued = RunState::Queued {
        queued_at: timestamp.clone(),
    };
    let interrupted = RunState::Interrupted {
        interrupted_at: timestamp.clone(),
    };
    let cancelled = RunState::Cancelled {
        finished_at: timestamp.clone(),
    };
    connection.execute(
        "UPDATE execution_attempts SET state_kind='interrupted',finished_at=?1,error_json=?2 WHERE state_kind='running' AND finished_at IS NULL",
        params![timestamp, json(&serde_json::json!({"reason":"service_restart"}))?],
    ).map_err(ServiceError::database)?;
    connection.execute(
        "UPDATE jobs SET state_kind='cancelled',state_json=?1,revision=revision+1,updated_at=?2 WHERE state_kind='cancel_requested'",
        params![json(&cancelled)?, timestamp],
    ).map_err(ServiceError::database)?;
    connection.execute(
        "UPDATE batches SET state_kind='cancelled',state_json=?1,revision=revision+1,updated_at=?2 WHERE state_kind='cancel_requested'",
        params![json(&cancelled)?, timestamp],
    ).map_err(ServiceError::database)?;
    connection.execute(
        "UPDATE jobs SET state_kind='queued',state_json=?1,revision=revision+1,updated_at=?2 WHERE state_kind='running' AND attempts < 2",
        params![json(&queued)?, timestamp],
    ).map_err(ServiceError::database)?;
    connection.execute(
        "UPDATE jobs SET state_kind='interrupted',state_json=?1,revision=revision+1,updated_at=?2 WHERE state_kind='running'",
        params![json(&interrupted)?, timestamp],
    ).map_err(ServiceError::database)?;
    connection.execute(
        "UPDATE batches SET state_kind='queued',state_json=?1,revision=revision+1,updated_at=?2 WHERE state_kind='running' AND EXISTS (SELECT 1 FROM jobs WHERE jobs.batch_id=batches.id AND jobs.state_kind='queued')",
        params![json(&queued)?, timestamp],
    ).map_err(ServiceError::database)?;
    connection.execute(
        "UPDATE batches SET state_kind='interrupted',state_json=?1,revision=revision+1,updated_at=?2 WHERE state_kind='running'",
        params![json(&interrupted)?, timestamp],
    ).map_err(ServiceError::database)?;
    Ok(connection)
}

fn load_batch(
    connection: &Connection,
    batch_id: &str,
    poll_after_seconds: u64,
) -> DbResult<BatchSnapshot> {
    let row = connection
        .query_row(
            "SELECT state_json,revision,created_at,updated_at,report_json FROM batches WHERE id=?1",
            [batch_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(ServiceError::database)?
        .ok_or_else(|| ServiceError::NotFound("batch not found".to_owned()))?;
    let mut statement = connection
        .prepare("SELECT id FROM jobs WHERE batch_id=?1 ORDER BY case_index")
        .map_err(ServiceError::database)?;
    let job_ids = statement
        .query_map([batch_id], |row| row.get::<_, String>(0))
        .map_err(ServiceError::database)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(ServiceError::database)?;
    Ok(BatchSnapshot {
        batch_id: batch_id.to_owned(),
        state: from_json(&row.0)?,
        revision: u64::try_from(row.1).map_err(ServiceError::database)?,
        created_at: row.2,
        updated_at: row.3,
        poll_after_seconds,
        job_ids,
        report: row.4.map(|value| from_json(&value)).transpose()?,
    })
}

fn load_job(connection: &Connection, job_id: &str) -> DbResult<JobSnapshot> {
    let row = connection.query_row(
        "SELECT batch_id,case_id,case_index,state_json,revision,attempts,created_at,updated_at FROM jobs WHERE id=?1",
        [job_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, String>(3)?, row.get::<_, i64>(4)?, row.get::<_, i64>(5)?, row.get::<_, String>(6)?, row.get::<_, String>(7)?)),
    ).optional().map_err(ServiceError::database)?
        .ok_or_else(|| ServiceError::NotFound("job not found".to_owned()))?;
    Ok(JobSnapshot {
        job_id: job_id.to_owned(),
        batch_id: row.0,
        case_id: row.1,
        case_index: usize::try_from(row.2).map_err(ServiceError::database)?,
        state: from_json(&row.3)?,
        revision: u64::try_from(row.4).map_err(ServiceError::database)?,
        attempts: u32::try_from(row.5).map_err(ServiceError::database)?,
        created_at: row.6,
        updated_at: row.7,
    })
}

fn json<T: serde::Serialize>(value: &T) -> DbResult<String> {
    serde_json::to_string(value).map_err(ServiceError::database)
}

fn from_json<T: serde::de::DeserializeOwned>(value: &str) -> DbResult<T> {
    serde_json::from_str(value).map_err(ServiceError::database)
}

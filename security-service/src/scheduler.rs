use std::{collections::BTreeMap, sync::Arc, time::Duration};

use tokio::sync::{Mutex, Notify, mpsc};

use crate::{
    AnalysisModel, Attack, AttackCacheIdentity, AttackOutcome, AttackResult, EstimateRequest,
    EstimatorProblem, ExactDecimal, ParameterCase, Provenance, SecurityReportEntry,
    SecurityReportFile, SecuritySummary, Validate, analysis_model_for, attacks_for_problem,
    canonical_json,
    database::{Database, JobWork},
    error::ServiceError,
    fast_attacks_for_problem,
    service::{BatchSnapshot, MAX_QUEUED_JOBS, RunState, now},
    slow_attacks_for_problem, stable_hash,
    upstream::{EstimatorClient, Metadata, ResultRole, WorkerOutcome, WorkerRequest},
};

pub struct Scheduler {
    receiver: mpsc::Receiver<String>,
    handle: SchedulerHandle,
}

#[derive(Clone)]
pub struct SchedulerHandle {
    sender: mpsc::Sender<String>,
    runner: Arc<Runner>,
    cancellation: Arc<Notify>,
}

struct Runner {
    database: Database,
    upstream: EstimatorClient,
    metadata: Metadata,
    execution_lock: Mutex<()>,
}

enum WorkerControl {
    Completed,
    PolicySkipped,
    Cancelled,
    TimedOut,
}

struct PlanOptions {
    targets: Vec<Attack>,
    slow: bool,
    high_security: bool,
    deadline: tokio::time::Instant,
}

impl Scheduler {
    pub fn new(
        database: Database,
        upstream: EstimatorClient,
        metadata: Metadata,
    ) -> (Self, SchedulerHandle) {
        let (sender, receiver) = mpsc::channel(MAX_QUEUED_JOBS);
        let runner = Arc::new(Runner {
            database,
            upstream,
            metadata,
            execution_lock: Mutex::new(()),
        });
        let handle = SchedulerHandle {
            sender,
            runner,
            cancellation: Arc::new(Notify::new()),
        };
        (
            Self {
                receiver,
                handle: handle.clone(),
            },
            handle,
        )
    }

    pub async fn start(mut self) -> Result<(), ServiceError> {
        self.handle.runner.database.promote_pending_jobs().await?;
        for job_id in self.handle.runner.database.queued_jobs().await? {
            self.handle.enqueue(job_id).await?;
        }
        tokio::spawn(async move {
            while let Some(job_id) = self.receiver.recv().await {
                if let Err(error) = self.handle.process(job_id).await {
                    tracing::error!(%error, "scheduler job failed");
                }
            }
        });
        Ok(())
    }
}

impl SchedulerHandle {
    pub async fn submit(
        &self,
        request: EstimateRequest,
        poll_after_seconds: u64,
    ) -> Result<(bool, BatchSnapshot), ServiceError> {
        request.validate()?;
        let fully_cached = self.runner.fully_cached(&request).await?;
        let mut batch = self.runner.database.create_batch(request).await?;
        batch.poll_after_seconds = poll_after_seconds;
        if fully_cached {
            for job_id in &batch.job_ids {
                self.process(job_id.clone()).await?;
            }
            return Ok((
                true,
                self.runner
                    .database
                    .batch(&batch.batch_id, poll_after_seconds)
                    .await?,
            ));
        }
        for job_id in &batch.job_ids {
            self.enqueue(job_id.clone()).await?;
        }
        Ok((false, batch))
    }

    pub async fn submit_staged(
        &self,
        request: EstimateRequest,
        poll_after_seconds: u64,
    ) -> Result<BatchSnapshot, ServiceError> {
        request.validate()?;
        let mut batch = self.runner.database.create_staged_batch(request).await?;
        batch.poll_after_seconds = poll_after_seconds;
        for job_id in &batch.job_ids {
            if self.runner.database.job(job_id).await?.state.kind() == "queued" {
                self.enqueue(job_id.clone()).await?;
            }
        }
        Ok(batch)
    }

    pub async fn cancel(
        &self,
        batch_id: &str,
        poll_after_seconds: u64,
    ) -> Result<BatchSnapshot, ServiceError> {
        self.runner.database.request_cancel(batch_id).await?;
        self.cancellation.notify_waiters();
        self.runner.refresh_batch(batch_id).await?;
        self.runner
            .database
            .batch(batch_id, poll_after_seconds)
            .await
    }

    async fn enqueue(&self, job_id: String) -> Result<(), ServiceError> {
        self.sender
            .send(job_id)
            .await
            .map_err(|_| ServiceError::Internal("scheduler stopped".to_owned()))
    }

    async fn process(&self, job_id: String) -> Result<(), ServiceError> {
        let _guard = self.runner.execution_lock.lock().await;
        let Some(work) = self.runner.database.claim_job(&job_id).await? else {
            for promoted in self.runner.database.promote_pending_jobs().await? {
                self.enqueue(promoted).await?;
            }
            return Ok(());
        };
        match self.runner.process_work(&work, &self.cancellation).await {
            Ok((state, report)) => {
                self.runner
                    .database
                    .finish_job(&job_id, state, report)
                    .await?;
            }
            Err(error) if matches!(error, ServiceError::Upstream(_)) && work.attempts < 2 => {
                self.runner
                    .database
                    .requeue_job(&job_id, &error.to_string())
                    .await?;
                self.enqueue(job_id.clone()).await?;
                return Ok(());
            }
            Err(error) => {
                let timestamp = now();
                let state = RunState::Failed {
                    finished_at: timestamp,
                    code: "estimation_failed".to_owned(),
                    message: error.to_string(),
                };
                self.runner
                    .database
                    .finish_job(&job_id, state, None)
                    .await?;
            }
        }
        self.runner.refresh_batch(&work.batch_id).await?;
        for promoted in self.runner.database.promote_pending_jobs().await? {
            self.enqueue(promoted).await?;
        }
        Ok(())
    }
}

impl Runner {
    async fn fully_cached(&self, request: &EstimateRequest) -> Result<bool, ServiceError> {
        for case in &request.cases {
            let context = self.case_context(case)?;
            for attack in attacks_for_problem(&case.problem) {
                let key = context.cache_identity(*attack).hash();
                if self.database.cached_outcome(&key).await?.is_none() {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    async fn process_work(
        &self,
        work: &JobWork,
        cancellation: &Notify,
    ) -> Result<(RunState, Option<SecurityReportEntry>), ServiceError> {
        let context = self.case_context(&work.case)?;
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(work.request.timeout_seconds);
        let mut results = BTreeMap::<Attack, AttackResult>::new();
        for attack in attacks_for_problem(&work.case.problem) {
            let key = context.cache_identity(*attack).hash();
            if let Some(cached) = self.database.cached_outcome(&key).await? {
                results.insert(
                    *attack,
                    AttackResult {
                        attack: *attack,
                        cached: true,
                        outcome: cached.outcome,
                    },
                );
            }
        }

        let missing_fast = fast_attacks_for_problem(&work.case.problem)
            .iter()
            .copied()
            .filter(|attack| !results.contains_key(attack))
            .collect::<Vec<_>>();
        if !missing_fast.is_empty() {
            match self
                .run_plan(
                    work,
                    &context,
                    PlanOptions {
                        targets: missing_fast.clone(),
                        slow: false,
                        high_security: false,
                        deadline,
                    },
                    cancellation,
                    &mut results,
                )
                .await?
            {
                WorkerControl::Cancelled => {
                    return Ok(self.cancelled_completion(work, &context, results));
                }
                WorkerControl::TimedOut => {
                    return Ok(self.timed_out_completion(work, &context, results));
                }
                WorkerControl::Completed | WorkerControl::PolicySkipped => {}
            }
        }

        let fast_bits =
            minimum_security_bits(fast_attacks_for_problem(&work.case.problem), &results);
        let fast_complete = fast_attacks_for_problem(&work.case.problem)
            .iter()
            .all(|attack| {
                results
                    .get(attack)
                    .is_some_and(|result| matches!(result.outcome, AttackOutcome::Computed { .. }))
            });
        let high_security = work
            .request
            .slow_attack_policy
            .as_ref()
            .zip(fast_bits.as_ref())
            .is_some_and(|(policy, bits)| {
                fast_complete && {
                    bits.as_big_decimal() >= policy.high_security_bits.as_big_decimal()
                }
            });

        let missing_slow = slow_attacks_for_problem(&work.case.problem)
            .iter()
            .copied()
            .filter(|attack| !results.contains_key(attack))
            .collect::<Vec<_>>();
        let mut fast_estimate = false;
        if !missing_slow.is_empty() {
            match self
                .run_plan(
                    work,
                    &context,
                    PlanOptions {
                        targets: missing_slow.clone(),
                        slow: true,
                        high_security,
                        deadline,
                    },
                    cancellation,
                    &mut results,
                )
                .await?
            {
                WorkerControl::PolicySkipped => {
                    fast_estimate = true;
                    for attack in missing_slow {
                        results.insert(
                            attack,
                            AttackResult {
                                attack,
                                cached: false,
                                outcome: AttackOutcome::Skipped {
                                    reason: "adaptive high-security cutoff".to_owned(),
                                },
                            },
                        );
                    }
                }
                WorkerControl::Cancelled => {
                    return Ok(self.cancelled_completion(work, &context, results));
                }
                WorkerControl::TimedOut => {
                    return Ok(self.timed_out_completion(work, &context, results));
                }
                WorkerControl::Completed => {}
            }
        }

        let entry = self.report_entry(work, &context, results, fast_estimate);
        let state = if entry.summary.complete {
            RunState::Completed { finished_at: now() }
        } else {
            RunState::Partial { finished_at: now() }
        };
        Ok((state, Some(entry)))
    }

    async fn run_plan(
        &self,
        work: &JobWork,
        context: &CaseContext,
        options: PlanOptions,
        cancellation: &Notify,
        results: &mut BTreeMap<Attack, AttackResult>,
    ) -> Result<WorkerControl, ServiceError> {
        let PlanOptions {
            targets,
            slow,
            high_security,
            deadline,
        } = options;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            insert_timeouts(&targets, work.request.timeout_seconds, results);
            return Ok(WorkerControl::TimedOut);
        }
        let worker_timeout = remaining.as_secs().max(1).min(work.request.timeout_seconds);
        let request = WorkerRequest::new(
            context.estimator_problem.clone(),
            &context.resolved_analysis,
            targets.clone(),
            worker_timeout,
        );
        let worker = self.upstream.estimate(&request);
        tokio::pin!(worker);
        let cancel = wait_for_cancel(&self.database, &work.batch_id, &work.job_id, cancellation);
        tokio::pin!(cancel);

        let response = if slow && high_security {
            let policy = work.request.slow_attack_policy.as_ref().ok_or_else(|| {
                ServiceError::Internal("missing validated slow attack policy".to_owned())
            })?;
            tokio::select! {
                response = &mut worker => response,
                () = tokio::time::sleep(Duration::from_secs(policy.decision_after_seconds)) => {
                    return Ok(WorkerControl::PolicySkipped);
                }
                () = tokio::time::sleep_until(deadline) => {
                    insert_timeouts(&targets, work.request.timeout_seconds, results);
                    return Ok(WorkerControl::TimedOut);
                }
                () = &mut cancel => return Ok(WorkerControl::Cancelled),
            }
        } else {
            tokio::select! {
                response = &mut worker => response,
                () = tokio::time::sleep_until(deadline) => {
                    insert_timeouts(&targets, work.request.timeout_seconds, results);
                    return Ok(WorkerControl::TimedOut);
                }
                () = &mut cancel => return Ok(WorkerControl::Cancelled),
            }
        };
        let response = match response {
            Ok(response) => response,
            Err(ServiceError::UpstreamTimeout(_)) => {
                insert_timeouts(&targets, work.request.timeout_seconds, results);
                return Ok(WorkerControl::TimedOut);
            }
            Err(error) => return Err(error),
        };
        if response.provenance.estimator_commit != self.metadata.estimator_commit
            || response.provenance.sage_version != self.metadata.sage_version
            || response.provenance.adapter_version != self.metadata.adapter_version
            || response.provenance.worker_image != self.metadata.worker_image
        {
            return Err(ServiceError::Upstream(
                "worker provenance changed after metadata discovery".to_owned(),
            ));
        }

        let mut retryable_failure = false;
        for execution in response.results {
            if execution.role != ResultRole::Target || !targets.contains(&execution.attack) {
                continue;
            }
            let outcome = match execution.outcome {
                WorkerOutcome::Computed {
                    security_bits,
                    metrics,
                } => AttackOutcome::Computed {
                    security_bits,
                    duration_ms: response.duration_ms,
                    metrics,
                },
                WorkerOutcome::Unsupported { code, reason } => {
                    AttackOutcome::Unsupported { code, reason }
                }
                WorkerOutcome::Failed {
                    code,
                    message,
                    retryable,
                } => {
                    retryable_failure |= retryable;
                    AttackOutcome::Failed {
                        code,
                        message,
                        retryable,
                    }
                }
            };
            if matches!(outcome, AttackOutcome::Computed { .. }) {
                let identity = context.cache_identity(execution.attack);
                self.database
                    .put_cached_outcome(
                        identity.hash(),
                        execution.attack,
                        outcome.clone(),
                        canonical_json(&self.metadata.context()),
                    )
                    .await?;
            }
            results.insert(
                execution.attack,
                AttackResult {
                    attack: execution.attack,
                    cached: false,
                    outcome,
                },
            );
        }
        for attack in targets {
            results.entry(attack).or_insert_with(|| AttackResult {
                attack,
                cached: false,
                outcome: AttackOutcome::Failed {
                    code: "missing_worker_result".to_owned(),
                    message: "worker omitted a target result".to_owned(),
                    retryable: false,
                },
            });
        }
        if retryable_failure && work.attempts < 2 {
            return Err(ServiceError::Upstream(
                "worker reported a retryable attack failure".to_owned(),
            ));
        }
        Ok(WorkerControl::Completed)
    }

    fn cancelled_completion(
        &self,
        work: &JobWork,
        context: &CaseContext,
        results: BTreeMap<Attack, AttackResult>,
    ) -> (RunState, Option<SecurityReportEntry>) {
        let timestamp = now();
        if results.is_empty() {
            return (
                RunState::Cancelled {
                    finished_at: timestamp,
                },
                None,
            );
        }
        let entry = self.report_entry(work, context, results, false);
        (
            RunState::Partial {
                finished_at: timestamp,
            },
            Some(entry),
        )
    }

    fn timed_out_completion(
        &self,
        work: &JobWork,
        context: &CaseContext,
        results: BTreeMap<Attack, AttackResult>,
    ) -> (RunState, Option<SecurityReportEntry>) {
        let entry = self.report_entry(work, context, results, false);
        (RunState::TimedOut { finished_at: now() }, Some(entry))
    }

    fn report_entry(
        &self,
        work: &JobWork,
        context: &CaseContext,
        results: BTreeMap<Attack, AttackResult>,
        fast_estimate: bool,
    ) -> SecurityReportEntry {
        let ordered = attacks_for_problem(&work.case.problem)
            .iter()
            .filter_map(|attack| results.get(attack).cloned())
            .collect::<Vec<_>>();
        let computed = ordered.iter().filter_map(|result| match &result.outcome {
            AttackOutcome::Computed { security_bits, .. } => Some((result.attack, security_bits)),
            _ => None,
        });
        let best =
            computed.min_by(|left, right| left.1.as_big_decimal().cmp(&right.1.as_big_decimal()));
        let complete = ordered.len() == attacks_for_problem(&work.case.problem).len()
            && ordered
                .iter()
                .all(|result| matches!(result.outcome, AttackOutcome::Computed { .. }));
        let request_hash = stable_hash(
            &attacks_for_problem(&work.case.problem)
                .iter()
                .map(|attack| context.cache_identity(*attack))
                .collect::<Vec<_>>(),
        );
        SecurityReportEntry {
            case: work.case.clone(),
            request_hash,
            provenance: Provenance {
                estimator_commit: self.metadata.estimator_commit.clone(),
                sage_version: self.metadata.sage_version.clone(),
                adapter_version: self.metadata.adapter_version.clone(),
                worker_image: self.metadata.worker_image.clone(),
                analysis_model: context.analysis_model.clone(),
                resolved_analysis: context.resolved_analysis.clone(),
                created_at: now(),
            },
            summary: SecuritySummary {
                security_bits: best.map(|(_, bits)| bits.clone()),
                best_attack: best.map(|(attack, _)| attack),
                complete,
                fast_estimate,
                warnings: analysis_warnings(&context.analysis_model),
            },
            attacks: ordered,
        }
    }

    fn case_context(&self, case: &ParameterCase) -> Result<CaseContext, ServiceError> {
        let analysis_model = analysis_model_for(&case.problem, &case.analysis)?;
        let estimator_problem = match (&case.problem, &analysis_model) {
            (crate::Problem::Lwe(problem), _) => EstimatorProblem::Lwe(problem.clone()),
            (crate::Problem::Ntru(problem), _) => EstimatorProblem::Ntru(problem.clone()),
            (crate::Problem::Sis(problem), _) => EstimatorProblem::Sis(problem.clone()),
            (_, AnalysisModel::CoefficientEmbeddingV1 { derived_lwe, .. }) => {
                EstimatorProblem::Lwe((**derived_lwe).clone())
            }
            _ => {
                return Err(ServiceError::Internal(
                    "problem and analysis model disagree".to_owned(),
                ));
            }
        };
        Ok(CaseContext {
            estimator_problem,
            analysis_model,
            resolved_analysis: case.analysis.resolve(),
            estimator_context: self.metadata.context(),
        })
    }

    async fn refresh_batch(&self, batch_id: &str) -> Result<(), ServiceError> {
        let batch = self.database.batch(batch_id, 1).await?;
        let mut states = Vec::with_capacity(batch.job_ids.len());
        for job_id in &batch.job_ids {
            states.push(self.database.job(job_id).await?.state);
        }
        if states
            .iter()
            .any(|state| !state.terminal() && !matches!(state, RunState::Interrupted { .. }))
        {
            return Ok(());
        }
        let reports = self.database.batch_results(batch_id).await?;
        let timestamp = now();
        let state = if states
            .iter()
            .all(|state| matches!(state, RunState::Completed { .. }))
        {
            RunState::Completed {
                finished_at: timestamp,
            }
        } else if states
            .iter()
            .any(|state| matches!(state, RunState::TimedOut { .. }))
        {
            RunState::TimedOut {
                finished_at: timestamp,
            }
        } else if !reports.is_empty() {
            RunState::Partial {
                finished_at: timestamp,
            }
        } else if states
            .iter()
            .any(|state| matches!(state, RunState::Cancelled { .. }))
        {
            RunState::Cancelled {
                finished_at: timestamp,
            }
        } else {
            RunState::Failed {
                finished_at: timestamp,
                code: "batch_failed".to_owned(),
                message: "no case produced a report".to_owned(),
            }
        };
        let report = SecurityReportFile {
            format: "lattice-security/security-report".to_owned(),
            version: 1,
            id: format!("{batch_id}-report"),
            name: format!("Security report {batch_id}"),
            parameter_set_id: None,
            reports,
        };
        let report = (!report.reports.is_empty()).then_some(report);
        self.database.finalize_batch(batch_id, state, report).await
    }
}

struct CaseContext {
    estimator_problem: EstimatorProblem,
    analysis_model: AnalysisModel,
    resolved_analysis: crate::ResolvedAnalysisSettings,
    estimator_context: crate::EstimatorContext,
}

impl CaseContext {
    fn cache_identity(&self, attack: Attack) -> AttackCacheIdentity {
        AttackCacheIdentity::new(
            self.estimator_problem.clone(),
            self.analysis_model.clone(),
            self.resolved_analysis.clone(),
            attack,
            self.estimator_context.clone(),
        )
    }
}

async fn wait_for_cancel(database: &Database, batch_id: &str, job_id: &str, notify: &Notify) {
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if database.is_cancel_requested(batch_id).await.unwrap_or(true) {
            return;
        }
        tokio::select! {
            () = notify.notified() => {}
            _ = heartbeat.tick() => {
                if database.heartbeat_job(job_id).await.is_err() {
                    return;
                }
            }
            () = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
    }
}

fn minimum_security_bits(
    attacks: &[Attack],
    results: &BTreeMap<Attack, AttackResult>,
) -> Option<ExactDecimal> {
    attacks
        .iter()
        .filter_map(|attack| results.get(attack))
        .filter_map(|result| match &result.outcome {
            AttackOutcome::Computed { security_bits, .. } => Some(security_bits),
            _ => None,
        })
        .min_by(|left, right| left.as_big_decimal().cmp(&right.as_big_decimal()))
        .cloned()
}

fn insert_timeouts(
    attacks: &[Attack],
    timeout_seconds: u64,
    results: &mut BTreeMap<Attack, AttackResult>,
) {
    for attack in attacks {
        results.insert(
            *attack,
            AttackResult {
                attack: *attack,
                cached: false,
                outcome: AttackOutcome::Timeout { timeout_seconds },
            },
        );
    }
}

fn analysis_warnings(model: &AnalysisModel) -> Vec<String> {
    match model {
        AnalysisModel::CoefficientEmbeddingV1 { warnings, .. } => warnings.clone(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Zero;

    #[test]
    fn empty_security_minimum_is_none() {
        assert!(minimum_security_bits(&Attack::LWE_FAST, &BTreeMap::new()).is_none());
        assert!(num_bigint::BigInt::zero().is_zero());
    }
}

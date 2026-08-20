use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Weak},
    time::Duration,
};

use tokio::{
    sync::{Mutex, Notify, OwnedMutexGuard, Semaphore, mpsc},
    task::JoinSet,
};

use crate::{
    AnalysisModel, ApplicabilityLevel, Attack, AttackCacheIdentity, AttackOutcome, AttackResult,
    EstimateMode, EstimateRequest, EstimatorProblem, ParameterCase, Provenance,
    SLOW_ATTACK_APPLICABILITY_RULE_VERSION, SecurityReportEntry, SecurityReportFile,
    SecuritySummary, Validate, analysis_model_for, attacks_for_problem, canonical_json,
    database::{Database, JobWork},
    error::ServiceError,
    fast_attacks_for_problem,
    service::{BatchSnapshot, MAX_QUEUED_JOBS, RunState, now},
    slow_attack_applicability, slow_attacks_for_problem, stable_hash,
    upstream::{EstimatorClient, Metadata, WorkerOutcome, WorkerRequest},
};

pub struct Scheduler {
    receiver: mpsc::Receiver<String>,
    handle: SchedulerHandle,
    case_slots: Arc<Semaphore>,
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
    estimator_slots: Arc<Semaphore>,
    single_flight: Mutex<HashMap<String, Weak<Mutex<()>>>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkerControl {
    Completed,
    Cancelled,
    TimedOut,
}

struct PlanOptions {
    targets: Vec<Attack>,
    deadline: tokio::time::Instant,
}

struct PlanExecution {
    control: WorkerControl,
    results: BTreeMap<Attack, AttackResult>,
}

impl Scheduler {
    pub fn new(
        database: Database,
        upstream: EstimatorClient,
        metadata: Metadata,
        case_concurrency: usize,
        estimator_concurrency: usize,
    ) -> (Self, SchedulerHandle) {
        let (sender, receiver) = mpsc::channel(MAX_QUEUED_JOBS);
        let runner = Arc::new(Runner {
            database,
            upstream,
            metadata,
            estimator_slots: Arc::new(Semaphore::new(estimator_concurrency)),
            single_flight: Mutex::new(HashMap::new()),
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
                case_slots: Arc::new(Semaphore::new(case_concurrency)),
            },
            handle,
        )
    }

    pub async fn start(mut self) -> Result<(), ServiceError> {
        for job_id in self.handle.runner.database.queued_jobs().await? {
            self.handle.enqueue(job_id).await?;
        }
        tokio::spawn(async move {
            while let Some(job_id) = self.receiver.recv().await {
                let Ok(permit) = self.case_slots.clone().acquire_owned().await else {
                    break;
                };
                let handle = self.handle.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle.process(job_id).await {
                        tracing::error!(%error, "scheduler job failed");
                    }
                });
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
        let Some(work) = self.runner.database.claim_job(&job_id).await? else {
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
        Ok(())
    }
}

impl Runner {
    async fn fully_cached(&self, request: &EstimateRequest) -> Result<bool, ServiceError> {
        for case in &request.cases {
            let context = self.case_context(case)?;
            let mut cached = BTreeMap::new();
            for attack in fast_attacks_for_problem(&case.problem) {
                let key = context.cache_identity(*attack).hash();
                let Some(outcome) = self.database.cached_outcome(&key).await? else {
                    return Ok(false);
                };
                cached.insert(
                    *attack,
                    AttackResult {
                        attack: *attack,
                        cached: true,
                        outcome: outcome.outcome,
                    },
                );
            }
            if request.mode == EstimateMode::Rough {
                continue;
            }
            let policy = request.slow_attack_policy.as_ref().ok_or_else(|| {
                ServiceError::Internal("missing validated slow attack policy".to_owned())
            })?;
            for attack in slow_attacks_for_problem(&case.problem) {
                let key = context.cache_identity(*attack).hash();
                if self.database.cached_outcome(&key).await?.is_some() {
                    continue;
                }
                if !policy.forces(*attack)
                    && (context.applicability(*attack)?.level == ApplicabilityLevel::Inapplicable
                        || fast_results_meet_stop_threshold(&cached, policy))
                {
                    continue;
                }
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn process_work(
        self: &Arc<Self>,
        work: &JobWork,
        cancellation: &Arc<Notify>,
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

        let fast_plans = fast_attack_groups(&work.case.problem, &results);
        let mut fast_estimate = false;
        if !fast_plans.is_empty() {
            let execution = self
                .run_plans(work, &context, fast_plans, deadline, cancellation)
                .await?;
            results.extend(execution.results);
            match execution.control {
                WorkerControl::Cancelled => {
                    return Ok(self.cancelled_completion(work, &context, results));
                }
                WorkerControl::TimedOut => {
                    return Ok(self.timed_out_completion(work, &context, results));
                }
                WorkerControl::Completed => {}
            }
        }

        let missing_slow = slow_attacks_for_problem(&work.case.problem)
            .iter()
            .copied()
            .filter(|attack| !results.contains_key(attack))
            .collect::<Vec<_>>();

        let control = if work.request.mode == EstimateMode::Rough {
            let slow_candidates =
                self.apply_applicability_skips(&context, &missing_slow, &mut results)?;
            for attack in slow_candidates {
                results.entry(attack).or_insert_with(|| AttackResult {
                    attack,
                    cached: false,
                    outcome: AttackOutcome::Skipped {
                        reason: "rough mode runs fast attacks only".to_owned(),
                    },
                });
            }
            fast_estimate = true;
            WorkerControl::Completed
        } else {
            let policy = work.request.slow_attack_policy.as_ref().ok_or_else(|| {
                ServiceError::Internal("missing validated slow attack policy".to_owned())
            })?;
            let (forced, automatic): (Vec<_>, Vec<_>) = missing_slow
                .into_iter()
                .partition(|attack| policy.forces(*attack));
            let automatic_candidates =
                self.apply_applicability_skips(&context, &automatic, &mut results)?;
            let mut slow_candidates = forced;
            if fast_results_meet_stop_threshold(&results, policy) {
                for attack in automatic_candidates {
                    results.insert(
                        attack,
                        AttackResult {
                            attack,
                            cached: false,
                            outcome: AttackOutcome::PolicySkipped {
                                code: "fast_estimate_above_threshold".to_owned(),
                                reason: format!(
                                    "the lowest fast-attack estimate is at least the required security plus the configured {}-bit margin",
                                    policy.stop_margin_bits
                                ),
                                applicability_rule_version:
                                    SLOW_ATTACK_APPLICABILITY_RULE_VERSION,
                            },
                        },
                    );
                }
            } else {
                slow_candidates.extend(automatic_candidates);
            }
            if slow_candidates.is_empty() {
                WorkerControl::Completed
            } else {
                let plans = slow_candidates
                    .into_iter()
                    .map(|attack| vec![attack])
                    .collect();
                let execution = self
                    .run_plans(work, &context, plans, deadline, cancellation)
                    .await?;
                results.extend(execution.results);
                execution.control
            }
        };

        match control {
            WorkerControl::Cancelled => {
                return Ok(self.cancelled_completion(work, &context, results));
            }
            WorkerControl::TimedOut => {
                return Ok(self.timed_out_completion(work, &context, results));
            }
            WorkerControl::Completed => {}
        }

        let entry = self.report_entry(work, &context, results, fast_estimate);
        let state = if entry.summary.complete {
            RunState::Completed { finished_at: now() }
        } else {
            RunState::Partial { finished_at: now() }
        };
        Ok((state, Some(entry)))
    }

    async fn run_plans(
        self: &Arc<Self>,
        work: &JobWork,
        context: &CaseContext,
        plans: Vec<Vec<Attack>>,
        deadline: tokio::time::Instant,
        cancellation: &Arc<Notify>,
    ) -> Result<PlanExecution, ServiceError> {
        let mut tasks = JoinSet::new();
        for targets in plans {
            let plan_targets = targets.clone();
            let runner = Arc::clone(self);
            let work = work.clone();
            let context = context.clone();
            let cancellation = Arc::clone(cancellation);
            tasks.spawn(async move {
                let execution = runner
                    .run_plan(
                        &work,
                        &context,
                        PlanOptions { targets, deadline },
                        &cancellation,
                    )
                    .await;
                (plan_targets, execution)
            });
        }

        let mut control = WorkerControl::Completed;
        let mut results = BTreeMap::new();
        while let Some(joined) = tasks.join_next().await {
            let execution = match joined {
                Ok((_, Ok(execution))) => execution,
                Ok((targets, Err(error)))
                    if matches!(error, ServiceError::Upstream(_)) && work.attempts >= 2 =>
                {
                    tracing::warn!(
                        %error,
                        attacks = ?targets,
                        "estimator plan failed after retry"
                    );
                    insert_plan_failures(&targets, &error, &mut results);
                    continue;
                }
                Ok((_, Err(error))) => {
                    tasks.shutdown().await;
                    return Err(error);
                }
                Err(error) => {
                    tasks.shutdown().await;
                    return Err(ServiceError::Internal(format!(
                        "estimator plan task failed: {error}"
                    )));
                }
            };
            results.extend(execution.results);
            control = match (control, execution.control) {
                (WorkerControl::Cancelled, _) | (_, WorkerControl::Cancelled) => {
                    WorkerControl::Cancelled
                }
                (WorkerControl::TimedOut, _) | (_, WorkerControl::TimedOut) => {
                    WorkerControl::TimedOut
                }
                _ => WorkerControl::Completed,
            };
        }
        Ok(PlanExecution { control, results })
    }

    fn apply_applicability_skips(
        &self,
        context: &CaseContext,
        attacks: &[Attack],
        results: &mut BTreeMap<Attack, AttackResult>,
    ) -> Result<Vec<Attack>, ServiceError> {
        let mut candidates = Vec::with_capacity(attacks.len());
        for attack in attacks {
            let applicability = context.applicability(*attack)?;
            if applicability.level == ApplicabilityLevel::Inapplicable {
                results.insert(
                    *attack,
                    AttackResult {
                        attack: *attack,
                        cached: false,
                        outcome: AttackOutcome::PolicySkipped {
                            code: applicability.code.to_owned(),
                            reason: applicability.reason,
                            applicability_rule_version: SLOW_ATTACK_APPLICABILITY_RULE_VERSION,
                        },
                    },
                );
            } else {
                candidates.push(*attack);
            }
        }
        Ok(candidates)
    }

    async fn acquire_flight_locks(
        &self,
        work: &JobWork,
        context: &CaseContext,
        targets: &[Attack],
        deadline: tokio::time::Instant,
        cancellation: &Notify,
    ) -> Result<Vec<OwnedMutexGuard<()>>, WorkerControl> {
        let mut keyed_locks = {
            let mut in_flight = self.single_flight.lock().await;
            in_flight.retain(|_, lock| lock.strong_count() > 0);
            targets
                .iter()
                .map(|attack| {
                    let key = context.cache_identity(*attack).hash();
                    let lock = in_flight
                        .get(&key)
                        .and_then(Weak::upgrade)
                        .unwrap_or_else(|| {
                            let lock = Arc::new(Mutex::new(()));
                            in_flight.insert(key.clone(), Arc::downgrade(&lock));
                            lock
                        });
                    (key, lock)
                })
                .collect::<Vec<_>>()
        };
        keyed_locks.sort_by(|left, right| left.0.cmp(&right.0));

        let mut guards = Vec::with_capacity(keyed_locks.len());
        for (_, lock) in keyed_locks {
            let acquire = lock.lock_owned();
            tokio::pin!(acquire);
            let cancel =
                wait_for_cancel(&self.database, &work.batch_id, &work.job_id, cancellation);
            tokio::pin!(cancel);
            let guard = tokio::select! {
                biased;
                guard = &mut acquire => guard,
                () = tokio::time::sleep_until(deadline) => {
                    return Err(WorkerControl::TimedOut);
                }
                () = &mut cancel => return Err(WorkerControl::Cancelled),
            };
            guards.push(guard);
        }
        Ok(guards)
    }

    async fn run_plan(
        &self,
        work: &JobWork,
        context: &CaseContext,
        options: PlanOptions,
        cancellation: &Notify,
    ) -> Result<PlanExecution, ServiceError> {
        let PlanOptions {
            mut targets,
            deadline,
        } = options;
        let mut results = BTreeMap::new();
        if deadline <= tokio::time::Instant::now() {
            insert_timeouts(&targets, work.request.timeout_seconds, &mut results);
            return Ok(PlanExecution {
                control: WorkerControl::TimedOut,
                results,
            });
        }

        let _flight_guards = match self
            .acquire_flight_locks(work, context, &targets, deadline, cancellation)
            .await
        {
            Ok(guards) => guards,
            Err(control) => {
                if control == WorkerControl::TimedOut {
                    insert_timeouts(&targets, work.request.timeout_seconds, &mut results);
                }
                return Ok(PlanExecution { control, results });
            }
        };

        for attack in &targets {
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
        targets.retain(|attack| !results.contains_key(attack));
        if targets.is_empty() {
            return Ok(PlanExecution {
                control: WorkerControl::Completed,
                results,
            });
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            insert_timeouts(&targets, work.request.timeout_seconds, &mut results);
            return Ok(PlanExecution {
                control: WorkerControl::TimedOut,
                results,
            });
        }

        let slot = self.estimator_slots.clone().acquire_owned();
        tokio::pin!(slot);
        let cancel = wait_for_cancel(&self.database, &work.batch_id, &work.job_id, cancellation);
        tokio::pin!(cancel);
        let _slot = tokio::select! {
            biased;
            slot = &mut slot => slot.map_err(|_| {
                ServiceError::Internal("estimator concurrency limiter closed".to_owned())
            })?,
            () = tokio::time::sleep_until(deadline) => {
                insert_timeouts(&targets, work.request.timeout_seconds, &mut results);
                return Ok(PlanExecution {
                    control: WorkerControl::TimedOut,
                    results,
                });
            }
            () = &mut cancel => {
                return Ok(PlanExecution {
                    control: WorkerControl::Cancelled,
                    results,
                });
            }
        };

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
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

        let response = tokio::select! {
            biased;
            response = &mut worker => response,
            () = tokio::time::sleep_until(deadline) => {
                insert_timeouts(&targets, work.request.timeout_seconds, &mut results);
                return Ok(PlanExecution {
                    control: WorkerControl::TimedOut,
                    results,
                });
            }
            () = &mut cancel => {
                return Ok(PlanExecution {
                    control: WorkerControl::Cancelled,
                    results,
                });
            }
        };
        let response = match response {
            Ok(response) => response,
            Err(ServiceError::UpstreamTimeout(_)) => {
                insert_timeouts(&targets, work.request.timeout_seconds, &mut results);
                return Ok(PlanExecution {
                    control: WorkerControl::TimedOut,
                    results,
                });
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
            if !targets.contains(&execution.attack) {
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
                WorkerOutcome::NoFiniteEstimate {
                    code,
                    reason,
                    raw_result,
                } => AttackOutcome::NoFiniteEstimate {
                    code,
                    reason,
                    raw_result,
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
            if matches!(
                outcome,
                AttackOutcome::Computed { .. } | AttackOutcome::NoFiniteEstimate { .. }
            ) {
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
        Ok(PlanExecution {
            control: WorkerControl::Completed,
            results,
        })
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
        let estimates = ordered.iter().filter_map(|result| match &result.outcome {
            AttackOutcome::Computed { security_bits, .. } => Some((result.attack, security_bits)),
            _ => None,
        });
        let best =
            estimates.min_by(|left, right| left.1.as_big_decimal().cmp(&right.1.as_big_decimal()));
        let threshold_skipped = ordered.iter().any(|result| {
            matches!(
                &result.outcome,
                AttackOutcome::PolicySkipped { code, .. }
                    if code == "fast_estimate_above_threshold"
            )
        });
        let domain_skipped = ordered.iter().any(|result| {
            matches!(
                &result.outcome,
                AttackOutcome::PolicySkipped { code, .. }
                    if code != "fast_estimate_above_threshold"
            )
        });
        let complete = work.request.mode == EstimateMode::Normal
            && ordered.len() == attacks_for_problem(&work.case.problem).len()
            && ordered.iter().all(|result| {
                matches!(
                    result.outcome,
                    AttackOutcome::Computed { .. }
                        | AttackOutcome::NoFiniteEstimate { .. }
                        | AttackOutcome::PolicySkipped { .. }
                )
            });
        let request_hash = stable_hash(&(
            SLOW_ATTACK_APPLICABILITY_RULE_VERSION,
            work.request.mode,
            &work.request.slow_attack_policy,
            attacks_for_problem(&work.case.problem)
                .iter()
                .map(|attack| context.cache_identity(*attack))
                .collect::<Vec<_>>(),
        ));
        let mut warnings = analysis_warnings(&context.analysis_model);
        if domain_skipped {
            warnings.push(format!(
                "slow attacks outside the reviewed applicability domain were excluded by applicability rules v{SLOW_ATTACK_APPLICABILITY_RULE_VERSION}; completeness is relative to that policy"
            ));
        }
        if threshold_skipped {
            warnings.push(
                "slow attacks were excluded because the lowest fast-attack estimate met the requested security target plus margin; completeness is relative to that policy"
                    .to_owned(),
            );
        }
        if let Some(policy) = &work.request.slow_attack_policy
            && !policy.forced_attacks.is_empty()
        {
            let attacks = policy
                .forced_attacks
                .iter()
                .map(|attack| slow_attack_label(*attack))
                .collect::<Vec<_>>()
                .join(", ");
            warnings.push(format!(
                "slow attacks were explicitly forced ({attacks}); applicability and fast-estimate stop rules were bypassed"
            ));
            for attack in &policy.forced_attacks {
                let applicability = context
                    .applicability(*attack)
                    .expect("forced slow attacks have applicability rules");
                let level = match applicability.level {
                    ApplicabilityLevel::Applicable => "applicable",
                    ApplicabilityLevel::Borderline => "borderline",
                    ApplicabilityLevel::Inapplicable => "inapplicable",
                };
                warnings.push(format!(
                    "policy audit for {}: {level}/{} — {}",
                    slow_attack_label(*attack),
                    applicability.code,
                    applicability.reason
                ));
            }
        }
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
                warnings,
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
        let request = self.database.batch_request(batch_id).await?;
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
            name: request
                .name
                .as_ref()
                .map(|name| format!("{name} security report"))
                .unwrap_or_else(|| format!("Security report {batch_id}")),
            parameter_set_id: request.parameter_set_id,
            reports,
        };
        let report = (!report.reports.is_empty()).then_some(report);
        self.database.finalize_batch(batch_id, state, report).await
    }
}

#[derive(Clone)]
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

    fn applicability(
        &self,
        attack: Attack,
    ) -> Result<crate::SlowAttackApplicability, ServiceError> {
        slow_attack_applicability(&self.estimator_problem, attack).ok_or_else(|| {
            ServiceError::Internal("missing applicability rule for adaptive slow attack".to_owned())
        })
    }
}

fn fast_attack_groups(
    problem: &crate::Problem,
    existing: &BTreeMap<Attack, AttackResult>,
) -> Vec<Vec<Attack>> {
    let families = match problem {
        crate::Problem::Lwe(_) | crate::Problem::Rlwe(_) | crate::Problem::Glwe(_) => vec![
            vec![
                Attack::Usvp,
                Attack::Bdd,
                Attack::BddHybrid,
                Attack::BddMitmHybrid,
            ],
            vec![Attack::Dual, Attack::DualHybrid],
        ],
        crate::Problem::Ntru(_) => vec![
            vec![Attack::Usvp],
            vec![Attack::Dsd],
            vec![Attack::Bdd, Attack::BddHybrid, Attack::BddMitmHybrid],
        ],
        crate::Problem::Sis(_) => vec![vec![Attack::Lattice]],
    };
    families
        .into_iter()
        .map(|family| {
            family
                .into_iter()
                .filter(|attack| !existing.contains_key(attack))
                .collect::<Vec<_>>()
        })
        .filter(|family| !family.is_empty())
        .collect()
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

fn fast_results_meet_stop_threshold(
    results: &BTreeMap<Attack, AttackResult>,
    policy: &crate::SlowAttackPolicy,
) -> bool {
    results
        .values()
        .filter_map(|result| match &result.outcome {
            AttackOutcome::Computed { security_bits, .. } => Some(security_bits),
            _ => None,
        })
        .min_by(|left, right| left.as_big_decimal().cmp(&right.as_big_decimal()))
        .is_some_and(|security_bits| {
            security_bits.as_big_decimal()
                >= policy.required_security_bits.as_big_decimal()
                    + policy.stop_margin_bits.as_big_decimal()
        })
}

fn slow_attack_label(attack: Attack) -> &'static str {
    match attack {
        Attack::AroraGb => "arora_gb",
        Attack::Bkw => "bkw",
        _ => unreachable!("only adaptive slow attacks have labels"),
    }
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

fn insert_plan_failures(
    attacks: &[Attack],
    error: &ServiceError,
    results: &mut BTreeMap<Attack, AttackResult>,
) {
    for attack in attacks {
        results.insert(
            *attack,
            AttackResult {
                attack: *attack,
                cached: false,
                outcome: AttackOutcome::Failed {
                    code: "estimator_plan_failed".to_owned(),
                    message: error.to_string(),
                    retryable: false,
                },
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

    #[test]
    fn fast_estimate_threshold_includes_the_configured_margin() {
        let policy = crate::SlowAttackPolicy {
            required_security_bits: crate::ExactDecimal::new("128").unwrap(),
            stop_margin_bits: crate::ExactDecimal::new("16").unwrap(),
            forced_attacks: Vec::new(),
        };
        let results = |bits: &str| {
            BTreeMap::from([(
                Attack::Usvp,
                AttackResult {
                    attack: Attack::Usvp,
                    cached: false,
                    outcome: AttackOutcome::Computed {
                        security_bits: crate::ExactDecimal::new(bits).unwrap(),
                        duration_ms: 1,
                        metrics: BTreeMap::new(),
                    },
                },
            )])
        };
        assert!(!fast_results_meet_stop_threshold(
            &results("143.999"),
            &policy
        ));
        assert!(fast_results_meet_stop_threshold(&results("144"), &policy));
    }

    #[test]
    fn lwe_fast_attacks_keep_the_primal_family_together() {
        let request: EstimateRequest =
            serde_json::from_str(include_str!("../../fixtures/examples/demo-run.json")).unwrap();
        assert_eq!(
            fast_attack_groups(&request.cases[0].problem, &BTreeMap::new()),
            vec![
                vec![
                    Attack::Usvp,
                    Attack::Bdd,
                    Attack::BddHybrid,
                    Attack::BddMitmHybrid,
                ],
                vec![Attack::Dual, Attack::DualHybrid],
            ]
        );

        let mut existing = BTreeMap::new();
        insert_timeouts(&[Attack::Usvp], 1, &mut existing);
        assert_eq!(
            fast_attack_groups(&request.cases[0].problem, &existing),
            vec![
                vec![Attack::Bdd, Attack::BddHybrid, Attack::BddMitmHybrid],
                vec![Attack::Dual, Attack::DualHybrid],
            ]
        );
    }

    #[test]
    fn failed_plan_becomes_attack_level_failures() {
        let mut results = BTreeMap::new();
        insert_plan_failures(
            &[Attack::Dual, Attack::DualHybrid],
            &ServiceError::Upstream("worker returned 502".to_owned()),
            &mut results,
        );

        for attack in [Attack::Dual, Attack::DualHybrid] {
            assert!(matches!(
                results[&attack].outcome,
                AttackOutcome::Failed {
                    ref code,
                    ref message,
                    retryable: false,
                } if code == "estimator_plan_failed"
                    && message.contains("worker returned 502")
            ));
        }
    }
}

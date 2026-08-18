//! Template-facing view models and display formatting.
//!
//! HTTP/form handling stays in the parent module; this module only converts
//! domain snapshots into values that Askama templates can render.

use std::sync::Arc;

use crate::{
    AttackOutcome, ErrorDistribution, EstimateRequest, ExactDecimal, ParameterCase, Problem,
    SampleCount, SecretDistribution,
    database::ParameterSetSummary,
    error::ServiceError,
    service::{AppState, BatchSnapshot, JobSnapshot},
};

#[derive(Clone)]
pub(super) struct UiParameterSet {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) version: u64,
    pub(super) case_count: usize,
    pub(super) created_at: String,
}

impl From<ParameterSetSummary> for UiParameterSet {
    fn from(value: ParameterSetSummary) -> Self {
        Self {
            id: value.id,
            name: value.name,
            version: value.version,
            case_count: value.case_count,
            created_at: value.created_at,
        }
    }
}

#[derive(Clone)]
pub(super) struct UiBatch {
    pub(super) id: String,
    pub(super) state: String,
    pub(super) revision: u64,
    pub(super) updated_at: String,
    pub(super) terminal: bool,
    pub(super) report_count: usize,
    pub(super) security: String,
    pub(super) case_summary: String,
}

impl UiBatch {
    pub(super) fn new(value: BatchSnapshot, request: &EstimateRequest) -> Self {
        let security = value
            .report
            .as_ref()
            .and_then(|report| {
                report
                    .reports
                    .iter()
                    .filter_map(|entry| entry.summary.security_bits.as_ref())
                    .min_by(|left, right| left.as_big_decimal().cmp(&right.as_big_decimal()))
            })
            .map(format_security_bits)
            .unwrap_or_else(|| "—".to_owned());
        Self {
            id: value.batch_id,
            state: value.state.kind().to_owned(),
            revision: value.revision,
            updated_at: value.updated_at,
            terminal: value.state.terminal(),
            report_count: request.cases.len(),
            security,
            case_summary: batch_case_summary(&request.cases),
        }
    }
}

pub(super) struct UiJob {
    pub(super) id: String,
    pub(super) case_id: String,
    pub(super) state: String,
    pub(super) attempts: u32,
    pub(super) case_name: String,
    pub(super) parameters: UiProblem,
}

impl UiJob {
    pub(super) fn new(value: JobSnapshot, case: Option<&ParameterCase>) -> Self {
        Self {
            id: value.job_id,
            case_id: value.case_id,
            state: value.state.kind().to_owned(),
            attempts: value.attempts,
            case_name: case.map_or_else(|| "Unknown case".to_owned(), |case| case.name.clone()),
            parameters: case.map_or_else(UiProblem::unknown, |case| problem_view(&case.problem)),
        }
    }
}

pub(super) struct UiReport {
    pub(super) case_id: String,
    pub(super) case_name: String,
    pub(super) security: String,
    pub(super) complete: bool,
    pub(super) fast_estimate: bool,
    pub(super) approximate: bool,
    pub(super) parameters: UiProblem,
    pub(super) attacks: Vec<UiAttack>,
}

impl UiReport {
    pub(super) fn new(entry: &crate::SecurityReportEntry) -> Self {
        Self {
            case_id: entry.case.id.clone(),
            case_name: entry.case.name.clone(),
            security: entry
                .summary
                .security_bits
                .as_ref()
                .map(format_security_bits)
                .unwrap_or_else(|| "—".to_owned()),
            complete: entry.summary.complete,
            fast_estimate: entry.summary.fast_estimate,
            approximate: entry.summary.approximate,
            parameters: problem_view(&entry.case.problem),
            attacks: entry.attacks.iter().map(UiAttack::new).collect(),
        }
    }
}

#[derive(Clone)]
pub(super) struct UiProblem {
    pub(super) primary: String,
    pub(super) secret: String,
    pub(super) error: String,
}

impl UiProblem {
    fn unknown() -> Self {
        Self {
            primary: "参数快照不可用".to_owned(),
            secret: String::new(),
            error: String::new(),
        }
    }
}

pub(super) struct UiAttack {
    pub(super) name: String,
    pub(super) outcome: String,
    pub(super) security: String,
    pub(super) detail: String,
    pub(super) audit: String,
    pub(super) cached: bool,
}

impl UiAttack {
    fn new(result: &crate::AttackResult) -> Self {
        Self {
            name: enum_name(&result.attack),
            outcome: outcome_name(&result.outcome).to_owned(),
            security: outcome_security(&result.outcome),
            detail: outcome_detail(&result.outcome),
            audit: outcome_audit(&result.outcome),
            cached: result.cached,
        }
    }
}

pub(super) struct UiCase {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) problem: String,
}

impl UiCase {
    pub(super) fn new(case: &ParameterCase) -> Self {
        Self {
            id: case.id.clone(),
            name: case.name.clone(),
            problem: serde_json::to_string(&case.problem)
                .unwrap_or_else(|_| "invalid problem".to_owned()),
        }
    }
}

pub(super) async fn load_ui_batches(
    state: &Arc<AppState>,
    limit: usize,
) -> Result<Vec<UiBatch>, ServiceError> {
    let snapshots = state
        .database
        .list_batches_with_requests(limit, state.poll_after_seconds)
        .await?;
    Ok(snapshots
        .into_iter()
        .map(|(snapshot, request)| UiBatch::new(snapshot, &request))
        .collect())
}

fn batch_case_summary(cases: &[ParameterCase]) -> String {
    let Some(first) = cases.first() else {
        return "没有 case".to_owned();
    };
    let first_problem = problem_view(&first.problem);
    if cases.len() == 1 {
        format!("{} · {}", first.name, first_problem.primary)
    } else {
        format!(
            "{} · {} · 另有 {} 个 case",
            first.name,
            first_problem.primary,
            cases.len() - 1
        )
    }
}

fn problem_view(problem: &Problem) -> UiProblem {
    match problem {
        Problem::Lwe(problem) => UiProblem {
            primary: format!(
                "LWE · n={} · q={} · samples={}",
                problem.dimension,
                problem.modulus,
                sample_count(&problem.samples)
            ),
            secret: secret_distribution(&problem.secret),
            error: error_distribution(&problem.error),
        },
        Problem::Rlwe(problem) => UiProblem {
            primary: format!(
                "RLWE · N={} · q={} · ring samples={}",
                problem.negacyclic_ring.polynomial_degree,
                problem.negacyclic_ring.ciphertext_modulus,
                sample_count(&problem.samples)
            ),
            secret: secret_distribution(&problem.secret),
            error: error_distribution(&problem.error),
        },
        Problem::Glwe(problem) => UiProblem {
            primary: format!(
                "GLWE · k={} · N={} · q={} · ring samples={}",
                problem.dimension,
                problem.negacyclic_ring.polynomial_degree,
                problem.negacyclic_ring.ciphertext_modulus,
                sample_count(&problem.samples)
            ),
            secret: secret_distribution(&problem.secret),
            error: error_distribution(&problem.error),
        },
        Problem::Ntru(problem) => UiProblem {
            primary: format!(
                "NTRU · n={} · q={} · structure={}",
                problem.dimension,
                problem.modulus,
                enum_name(&problem.structure)
            ),
            secret: secret_distribution(&problem.secret),
            error: error_distribution(&problem.error),
        },
        Problem::Sis(problem) => UiProblem {
            primary: format!(
                "SIS · n={} · q={} · columns={} · bound={} · norm={}",
                problem.dimension,
                problem.modulus,
                problem.columns,
                problem.length_bound,
                enum_name(&problem.norm)
            ),
            secret: String::new(),
            error: String::new(),
        },
    }
}

fn sample_count(samples: &SampleCount) -> String {
    match samples {
        SampleCount::Finite { count } => count.to_string(),
        SampleCount::Unlimited => "unlimited".to_owned(),
    }
}

fn secret_distribution(distribution: &SecretDistribution) -> String {
    match distribution {
        SecretDistribution::UniformBinary => "secret: uniform binary".to_owned(),
        SecretDistribution::UniformTernary => "secret: uniform ternary".to_owned(),
        SecretDistribution::SparseTernary {} => {
            "secret: sparse ternary (P(-1)=1/4, P(0)=1/2, P(1)=1/4)".to_owned()
        }
        SecretDistribution::FixedWeightBinary { hamming_weight } => {
            format!("secret: fixed-weight binary (weight={hamming_weight})")
        }
        SecretDistribution::FixedWeightTernary {
            positive_weight,
            negative_weight,
        } => format!("secret: fixed-weight ternary (+1={positive_weight}, -1={negative_weight})"),
        SecretDistribution::DiscreteGaussian { standard_deviation } => {
            format!("secret: discrete Gaussian (σ={standard_deviation})")
        }
        SecretDistribution::CenteredBinomial { eta } => {
            format!("secret: centered binomial (η={eta})")
        }
        SecretDistribution::UniformInteger { lower, upper } => format!(
            "secret: bounded integer [{}..{}]",
            lower.as_bigint(),
            upper.as_bigint()
        ),
    }
}

fn error_distribution(distribution: &ErrorDistribution) -> String {
    match distribution {
        ErrorDistribution::DiscreteGaussian { standard_deviation } => {
            format!("error: discrete Gaussian (σ={standard_deviation})")
        }
        ErrorDistribution::CenteredBinomial { eta } => {
            format!("error: centered binomial (η={eta})")
        }
        ErrorDistribution::UniformInteger { lower, upper } => format!(
            "error: bounded integer [{}..{}]",
            lower.as_bigint(),
            upper.as_bigint()
        ),
    }
}

fn enum_name<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn outcome_name(outcome: &AttackOutcome) -> &'static str {
    match outcome {
        AttackOutcome::Computed { .. } => "computed",
        AttackOutcome::Approximate { .. } => "approximate",
        AttackOutcome::NoFiniteEstimate { .. } => "no_finite_estimate",
        AttackOutcome::Timeout { .. } => "timeout",
        AttackOutcome::Unsupported { .. } => "unsupported",
        AttackOutcome::Failed { .. } => "failed",
        AttackOutcome::PolicySkipped { .. } => "policy_skipped",
        AttackOutcome::Skipped { .. } => "skipped",
    }
}

fn outcome_security(outcome: &AttackOutcome) -> String {
    match outcome {
        AttackOutcome::Computed { security_bits, .. }
        | AttackOutcome::Approximate { security_bits, .. } => format_security_bits(security_bits),
        AttackOutcome::NoFiniteEstimate { .. } => "∞".to_owned(),
        _ => "—".to_owned(),
    }
}

fn outcome_detail(outcome: &AttackOutcome) -> String {
    match outcome {
        AttackOutcome::Computed { .. } => "computed".to_owned(),
        AttackOutcome::Approximate { provenance, .. } => format!(
            "approximate · {} v{} · {} · holdout MAE {} bit · p95 {} bit · max overestimate {} bit · safety margin {} bit",
            provenance.model_id,
            provenance.model_version,
            provenance.platform,
            provenance.holdout_mean_absolute_error_bits,
            provenance.holdout_p95_absolute_error_bits,
            provenance.holdout_max_overestimate_bits,
            provenance.safety_margin_bits
        ),
        AttackOutcome::NoFiniteEstimate { code, reason, .. } => {
            format!("no finite estimate · {code}: {reason}")
        }
        AttackOutcome::Timeout { timeout_seconds } => format!("timeout after {timeout_seconds}s"),
        AttackOutcome::Unsupported { code, reason } => {
            format!("unsupported · {code}: {reason}")
        }
        AttackOutcome::Failed {
            code,
            message,
            retryable,
        } => format!("failed · {code}: {message} · retryable={retryable}"),
        AttackOutcome::PolicySkipped {
            code,
            reason,
            applicability_rule_version,
        } => format!(
            "policy skipped · applicability rules v{applicability_rule_version} · {code}: {reason}"
        ),
        AttackOutcome::Skipped { reason } => format!("skipped · {reason}"),
    }
}

fn outcome_audit(outcome: &AttackOutcome) -> String {
    match outcome {
        AttackOutcome::NoFiniteEstimate {
            raw_result: Some(raw_result),
            ..
        } => serde_json::to_string_pretty(raw_result).unwrap_or_default(),
        _ => String::new(),
    }
}

pub(super) fn format_security_bits(value: &ExactDecimal) -> String {
    value.as_big_decimal().round(2).normalized().to_string()
}

#[cfg(test)]
mod tests {
    use super::{format_security_bits, outcome_audit, outcome_detail, outcome_security};
    use crate::{AttackOutcome, ExactDecimal};

    #[test]
    fn security_bits_are_rounded_only_for_ui_display() {
        assert_eq!(
            format_security_bits(&ExactDecimal::new("214.105577393628").unwrap()),
            "214.11"
        );
        assert_eq!(
            format_security_bits(&ExactDecimal::new("128.0001").unwrap()),
            "128"
        );
    }

    #[test]
    fn no_finite_estimate_is_distinct_and_auditable_in_ui() {
        let outcome = AttackOutcome::NoFiniteEstimate {
            code: "no_finite_rop".to_owned(),
            reason: "dual_hybrid returned no finite positive rop".to_owned(),
            raw_result: Some(serde_json::json!({"result": "rop: +Infinity"})),
        };
        let detail = outcome_detail(&outcome);
        assert_eq!(
            detail,
            "no finite estimate · no_finite_rop: dual_hybrid returned no finite positive rop"
        );
        assert_eq!(outcome_security(&outcome), "∞");
        assert!(outcome_audit(&outcome).contains("rop: +Infinity"));
    }
}

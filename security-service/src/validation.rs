use std::collections::HashSet;

use num_traits::One;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    FILE_FORMAT_VERSION,
    domain::{
        AnalysisSettings, AttackOutcome, ErrorDistribution, Problem, SampleCount,
        SecretDistribution, attacks_for_problem, slow_attacks_for_problem,
    },
    formats::{EstimateRequest, ParameterCase, ParameterSetFile, SecurityReportFile},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Error)]
#[error("{path}: {message}")]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

impl ValidationError {
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }

    fn prepend(mut self, prefix: &str) -> Self {
        self.path = if self.path.is_empty() {
            prefix.into()
        } else {
            format!("{prefix}.{}", self.path)
        };
        self
    }
}

pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}

impl Validate for ParameterSetFile {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.format != "lattice-security/parameter-set" {
            return Err(ValidationError::new(
                "format",
                "unsupported parameter-set format",
            ));
        }
        if self.version != FILE_FORMAT_VERSION {
            return Err(ValidationError::new(
                "version",
                "unsupported parameter-set major version",
            ));
        }
        validate_identifier(&self.id, "id")?;
        if self.name.trim().is_empty() {
            return Err(ValidationError::new("name", "name must not be empty"));
        }
        if self.cases.is_empty() {
            return Err(ValidationError::new(
                "cases",
                "parameter set must contain at least one case",
            ));
        }
        if self.cases.len() > 500 {
            return Err(ValidationError::new(
                "cases",
                "parameter set exceeds the 500 case limit",
            ));
        }
        let mut ids = HashSet::new();
        for (index, case) in self.cases.iter().enumerate() {
            case.validate()
                .map_err(|error| error.prepend(&format!("cases[{index}]")))?;
            if !ids.insert(&case.id) {
                return Err(ValidationError::new(
                    format!("cases[{index}].id"),
                    "case id must be unique within its parameter set",
                ));
            }
        }
        Ok(())
    }
}

impl Validate for ParameterCase {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_identifier(&self.id, "id")?;
        if self.name.trim().is_empty() {
            return Err(ValidationError::new("name", "name must not be empty"));
        }
        validate_problem(&self.problem)?;
        validate_analysis(&self.problem, &self.analysis)?;
        Ok(())
    }
}

impl Validate for SecurityReportFile {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.format != "lattice-security/security-report" {
            return Err(ValidationError::new(
                "format",
                "unsupported security-report format",
            ));
        }
        if self.version != FILE_FORMAT_VERSION {
            return Err(ValidationError::new(
                "version",
                "unsupported security-report major version",
            ));
        }
        validate_identifier(&self.id, "id")?;
        if self.reports.is_empty() {
            return Err(ValidationError::new(
                "reports",
                "security report must contain at least one entry",
            ));
        }
        for (index, report) in self.reports.iter().enumerate() {
            report
                .case
                .validate()
                .map_err(|error| error.prepend(&format!("reports[{index}].case")))?;
            let expected = attacks_for_problem(&report.case.problem);
            let complete = report.attacks.len() == expected.len()
                && expected
                    .iter()
                    .all(|attack| report.attacks.iter().any(|result| result.attack == *attack))
                && report
                    .attacks
                    .iter()
                    .all(|result| matches!(result.outcome, AttackOutcome::Computed { .. }));
            if report.summary.complete != complete {
                return Err(ValidationError::new(
                    format!("reports[{index}].summary.complete"),
                    "complete must match full computed coverage of the fixed attack set",
                ));
            }
            if report.summary.fast_estimate && report.summary.complete {
                return Err(ValidationError::new(
                    format!("reports[{index}].summary.fast_estimate"),
                    "a fast estimate cannot be marked complete",
                ));
            }
        }
        Ok(())
    }
}

impl Validate for EstimateRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.cases.is_empty() || self.cases.len() > 500 {
            return Err(ValidationError::new(
                "cases",
                "estimate request must contain 1..=500 cases",
            ));
        }
        if !(1..=7_200).contains(&self.timeout_seconds) {
            return Err(ValidationError::new(
                "timeout_seconds",
                "timeout must be in 1..=7200 seconds",
            ));
        }
        let needs_slow_policy = self
            .cases
            .iter()
            .any(|case| !slow_attacks_for_problem(&case.problem).is_empty());
        if needs_slow_policy && self.slow_attack_policy.is_none() {
            return Err(ValidationError::new(
                "slow_attack_policy",
                "LWE/RLWE/GLWE estimates require an explicit slow-attack policy",
            ));
        }
        if let Some(policy) = &self.slow_attack_policy {
            if policy.decision_after_seconds == 0
                || policy.decision_after_seconds >= self.timeout_seconds
            {
                return Err(ValidationError::new(
                    "slow_attack_policy.decision_after_seconds",
                    "decision time must be positive and less than the run timeout",
                ));
            }
            if !policy.high_security_bits.is_positive() {
                return Err(ValidationError::new(
                    "slow_attack_policy.high_security_bits",
                    "high-security threshold must be positive",
                ));
            }
        }
        let mut ids = HashSet::new();
        for (index, case) in self.cases.iter().enumerate() {
            case.validate()
                .map_err(|error| error.prepend(&format!("cases[{index}]")))?;
            if !ids.insert(&case.id) {
                return Err(ValidationError::new(
                    format!("cases[{index}].id"),
                    "case id must be unique within an estimate request",
                ));
            }
        }
        Ok(())
    }
}

fn validate_identifier(value: &str, path: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ValidationError::new(
            path,
            "identifier must be 1..=128 ASCII letters, digits, '.', '_' or '-'",
        ));
    }
    Ok(())
}

fn validate_problem(problem: &Problem) -> Result<(), ValidationError> {
    match problem {
        Problem::Lwe(problem) => {
            validate_positive_dimension(problem.dimension, "problem.dimension")?;
            validate_modulus(&problem.modulus, "problem.modulus")?;
            validate_samples(&problem.samples, "problem.samples")?;
            validate_secret(&problem.secret, problem.dimension, "problem.secret")?;
            validate_error(&problem.error, "problem.error")
        }
        Problem::Rlwe(problem) => {
            validate_ring(&problem.negacyclic_ring)?;
            validate_samples(&problem.samples, "problem.samples")?;
            validate_secret(
                &problem.secret,
                problem.negacyclic_ring.polynomial_degree,
                "problem.secret",
            )?;
            validate_error(&problem.error, "problem.error")
        }
        Problem::Glwe(problem) => {
            validate_ring(&problem.negacyclic_ring)?;
            validate_positive_dimension(problem.dimension, "problem.dimension")?;
            validate_samples(&problem.samples, "problem.samples")?;
            let secret_length = problem
                .dimension
                .checked_mul(problem.negacyclic_ring.polynomial_degree)
                .ok_or_else(|| {
                    ValidationError::new("problem", "GLWE secret length overflows u64")
                })?;
            validate_secret(&problem.secret, secret_length, "problem.secret")?;
            validate_error(&problem.error, "problem.error")
        }
        Problem::Ntru(problem) => {
            validate_positive_dimension(problem.dimension, "problem.dimension")?;
            validate_modulus(&problem.modulus, "problem.modulus")?;
            validate_secret(&problem.secret, problem.dimension, "problem.secret")?;
            validate_error(&problem.error, "problem.error")
        }
        Problem::Sis(problem) => {
            validate_positive_dimension(problem.dimension, "problem.dimension")?;
            validate_positive_dimension(problem.columns, "problem.columns")?;
            validate_modulus(&problem.modulus, "problem.modulus")?;
            if !problem.length_bound.is_positive() {
                return Err(ValidationError::new(
                    "problem.length_bound",
                    "SIS length bound must be positive",
                ));
            }
            Ok(())
        }
    }
}

fn validate_analysis(
    problem: &Problem,
    settings: &AnalysisSettings,
) -> Result<(), ValidationError> {
    match problem {
        Problem::Rlwe(_) | Problem::Glwe(_) => {
            if settings.reduction_model
                != Some(crate::domain::ReductionModel::CoefficientEmbeddingV1)
            {
                return Err(ValidationError::new(
                    "analysis.reduction_model",
                    "RLWE/GLWE requires coefficient_embedding_v1",
                ));
            }
        }
        Problem::Lwe(_) | Problem::Ntru(_) | Problem::Sis(_) => {
            if settings.reduction_model.is_some() {
                return Err(ValidationError::new(
                    "analysis.reduction_model",
                    "direct LWE/NTRU/SIS problems must not specify a reduction model",
                ));
            }
        }
    }
    Ok(())
}

fn validate_ring(ring: &crate::domain::NegacyclicRing) -> Result<(), ValidationError> {
    if ring.polynomial_degree == 0 || !ring.polynomial_degree.is_power_of_two() {
        return Err(ValidationError::new(
            "problem.negacyclic_ring.polynomial_degree",
            "v1 negacyclic polynomial degree must be a non-zero power of two",
        ));
    }
    validate_modulus(
        &ring.ciphertext_modulus,
        "problem.negacyclic_ring.ciphertext_modulus",
    )
}

fn validate_modulus(
    modulus: &crate::domain::PositiveInteger,
    path: &str,
) -> Result<(), ValidationError> {
    if modulus.as_biguint() <= num_bigint::BigUint::one() {
        return Err(ValidationError::new(
            path,
            "modulus must be greater than one",
        ));
    }
    Ok(())
}

fn validate_positive_dimension(value: u64, path: &str) -> Result<(), ValidationError> {
    if value == 0 {
        return Err(ValidationError::new(
            path,
            "value must be greater than zero",
        ));
    }
    Ok(())
}

fn validate_samples(samples: &SampleCount, path: &str) -> Result<(), ValidationError> {
    if matches!(samples, SampleCount::Finite { count: 0 }) {
        return Err(ValidationError::new(
            path,
            "finite sample count must be greater than zero",
        ));
    }
    Ok(())
}

fn validate_secret(
    distribution: &SecretDistribution,
    logical_length: u64,
    path: &str,
) -> Result<(), ValidationError> {
    match distribution {
        SecretDistribution::FixedWeightBinary { hamming_weight } => {
            if *hamming_weight > logical_length {
                return Err(ValidationError::new(
                    path,
                    "fixed binary weight exceeds secret length",
                ));
            }
        }
        SecretDistribution::FixedWeightTernary {
            positive_weight,
            negative_weight,
        } => {
            if positive_weight
                .checked_add(*negative_weight)
                .is_none_or(|weight| weight > logical_length)
            {
                return Err(ValidationError::new(
                    path,
                    "fixed ternary weights exceed secret length",
                ));
            }
        }
        SecretDistribution::DiscreteGaussian { standard_deviation } => {
            if !standard_deviation.is_positive() {
                return Err(ValidationError::new(
                    path,
                    "Gaussian standard deviation must be positive",
                ));
            }
        }
        SecretDistribution::CenteredBinomial { eta } => {
            if *eta == 0 {
                return Err(ValidationError::new(
                    path,
                    "centered binomial eta must be positive",
                ));
            }
        }
        SecretDistribution::UniformInteger { lower, upper } => {
            if lower.as_bigint() > upper.as_bigint() {
                return Err(ValidationError::new(
                    path,
                    "uniform lower bound exceeds upper bound",
                ));
            }
        }
        SecretDistribution::UniformBinary | SecretDistribution::UniformTernary => {}
    }
    Ok(())
}

fn validate_error(distribution: &ErrorDistribution, path: &str) -> Result<(), ValidationError> {
    match distribution {
        ErrorDistribution::DiscreteGaussian { standard_deviation } => {
            if !standard_deviation.is_positive() {
                return Err(ValidationError::new(
                    path,
                    "Gaussian standard deviation must be positive",
                ));
            }
        }
        ErrorDistribution::CenteredBinomial { eta } => {
            if *eta == 0 {
                return Err(ValidationError::new(
                    path,
                    "centered binomial eta must be positive",
                ));
            }
        }
        ErrorDistribution::UniformInteger { lower, upper } => {
            if lower.as_bigint() > upper.as_bigint() {
                return Err(ValidationError::new(
                    path,
                    "uniform lower bound exceeds upper bound",
                ));
            }
        }
    }
    Ok(())
}

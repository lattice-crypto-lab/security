//! Versioned, deterministic applicability rules for expensive LWE attacks.

use num_bigint::{BigInt, BigUint};

use crate::{Attack, ErrorDistribution, EstimatorProblem, LweProblem, SampleCount};

/// Version of the reviewed slow-attack applicability rules.
pub const SLOW_ATTACK_APPLICABILITY_RULE_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicabilityLevel {
    Applicable,
    Borderline,
    Inapplicable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlowAttackApplicability {
    pub level: ApplicabilityLevel,
    pub code: &'static str,
    pub reason: String,
}

impl SlowAttackApplicability {
    fn applicable(code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            level: ApplicabilityLevel::Applicable,
            code,
            reason: reason.into(),
        }
    }

    fn borderline(code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            level: ApplicabilityLevel::Borderline,
            code,
            reason: reason.into(),
        }
    }

    fn inapplicable(code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            level: ApplicabilityLevel::Inapplicable,
            code,
            reason: reason.into(),
        }
    }
}

/// Classify a slow attack before deciding whether Sage needs to run it.
pub fn slow_attack_applicability(
    problem: &EstimatorProblem,
    attack: Attack,
) -> Option<SlowAttackApplicability> {
    let EstimatorProblem::Lwe(problem) = problem else {
        return None;
    };
    match attack {
        Attack::AroraGb => Some(arora_gb_applicability(problem)),
        Attack::Bkw => Some(bkw_applicability(problem)),
        _ => None,
    }
}

fn arora_gb_applicability(problem: &LweProblem) -> SlowAttackApplicability {
    if let SampleCount::Finite { count } = problem.samples {
        let dimension_squared = problem.dimension.checked_mul(problem.dimension);
        if dimension_squared.is_none_or(|limit| count <= limit) {
            return SlowAttackApplicability::inapplicable(
                "arora_sample_starved",
                format!(
                    "finite sample count m={count} is not greater than n^2; Arora-GB is outside the reviewed sample-rich domain"
                ),
            );
        }
    }

    match &problem.error {
        ErrorDistribution::DiscreteGaussian { standard_deviation } => {
            let sigma = standard_deviation.as_big_decimal();
            if problem.dimension <= 256 && sigma <= 2 {
                return SlowAttackApplicability::applicable(
                    "arora_small_gaussian",
                    format!(
                        "Gaussian-like error has n={} and sigma={standard_deviation} inside the reviewed small-instance domain",
                        problem.dimension
                    ),
                );
            }
            if problem.dimension <= 128 && sigma <= 4 {
                return SlowAttackApplicability::borderline(
                    "arora_gaussian_borderline",
                    format!(
                        "Gaussian-like error has n={} and sigma={standard_deviation} inside the conservative borderline domain",
                        problem.dimension
                    ),
                );
            }
            SlowAttackApplicability::inapplicable(
                "arora_gaussian_outside_domain",
                format!(
                    "Gaussian-like error has n={} and sigma={standard_deviation}, outside the reviewed small-error Arora-GB domain",
                    problem.dimension
                ),
            )
        }
        error => {
            let width = bounded_error_width(error)
                .expect("centered-binomial and uniform-integer errors are bounded");
            if width <= BigInt::from(11) {
                return SlowAttackApplicability::applicable(
                    "arora_small_bounded_error",
                    format!(
                        "bounded error support width D={width} is inside the reviewed Arora-GB run domain"
                    ),
                );
            }
            if width <= BigInt::from(13) && problem.dimension <= 512 {
                return SlowAttackApplicability::borderline(
                    "arora_bounded_borderline",
                    format!(
                        "bounded error support width D={width} and n={} are inside the conservative borderline domain",
                        problem.dimension
                    ),
                );
            }
            SlowAttackApplicability::inapplicable(
                "arora_bounded_outside_domain",
                format!(
                    "bounded error support width D={width} and n={} are outside the reviewed Arora-GB domain",
                    problem.dimension
                ),
            )
        }
    }
}

fn bkw_applicability(problem: &LweProblem) -> SlowAttackApplicability {
    let modulus = problem.modulus.as_biguint();
    if modulus <= BigUint::from(4_u8) {
        return SlowAttackApplicability::applicable(
            "bkw_very_small_modulus",
            format!("q={modulus} is inside the reviewed LPN-like BKW domain"),
        );
    }
    if modulus <= BigUint::from(16_u8) && matches!(problem.samples, SampleCount::Unlimited) {
        return SlowAttackApplicability::applicable(
            "bkw_small_modulus_unlimited_samples",
            format!(
                "q={modulus} with unlimited samples is inside the reviewed small-modulus BKW domain"
            ),
        );
    }
    if problem.dimension <= 128 && modulus <= BigUint::from(512_u16) {
        return SlowAttackApplicability::borderline(
            "bkw_small_parameter_borderline",
            format!(
                "n={} and q={modulus} are inside the conservative BKW borderline domain",
                problem.dimension
            ),
        );
    }
    SlowAttackApplicability::inapplicable(
        "bkw_outside_small_modulus_domain",
        format!(
            "n={} and q={modulus} are outside the reviewed small-modulus/LPN-like BKW domain",
            problem.dimension
        ),
    )
}

fn bounded_error_width(error: &ErrorDistribution) -> Option<BigInt> {
    match error {
        ErrorDistribution::CenteredBinomial { eta } => {
            Some(BigInt::from(*eta) * 2 + BigInt::from(1))
        }
        ErrorDistribution::UniformInteger { lower, upper } => {
            Some(upper.as_bigint() - lower.as_bigint() + BigInt::from(1))
        }
        ErrorDistribution::DiscreteGaussian { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExactDecimal, PositiveInteger, SecretDistribution};

    fn lwe(n: u64, q: &str, samples: SampleCount, error: ErrorDistribution) -> EstimatorProblem {
        EstimatorProblem::Lwe(LweProblem {
            dimension: n,
            modulus: PositiveInteger::new(q).unwrap(),
            samples,
            secret: SecretDistribution::UniformBinary,
            error,
        })
    }

    fn gaussian(value: &str) -> ErrorDistribution {
        ErrorDistribution::DiscreteGaussian {
            standard_deviation: ExactDecimal::new(value).unwrap(),
        }
    }

    #[test]
    fn classifies_arora_gb_sample_error_and_borderline_domains() {
        let starved = lwe(
            128,
            "256",
            SampleCount::Finite { count: 16_384 },
            gaussian("1"),
        );
        assert_eq!(
            slow_attack_applicability(&starved, Attack::AroraGb)
                .unwrap()
                .level,
            ApplicabilityLevel::Inapplicable
        );

        let applicable = lwe(256, "65536", SampleCount::Unlimited, gaussian("2"));
        assert_eq!(
            slow_attack_applicability(&applicable, Attack::AroraGb)
                .unwrap()
                .level,
            ApplicabilityLevel::Applicable
        );

        let borderline = lwe(128, "256", SampleCount::Unlimited, gaussian("3.2"));
        assert_eq!(
            slow_attack_applicability(&borderline, Attack::AroraGb)
                .unwrap()
                .level,
            ApplicabilityLevel::Borderline
        );

        let outside = lwe(512, "65536", SampleCount::Unlimited, gaussian("3.2"));
        assert_eq!(
            slow_attack_applicability(&outside, Attack::AroraGb)
                .unwrap()
                .level,
            ApplicabilityLevel::Inapplicable
        );
    }

    #[test]
    fn classifies_bkw_small_modulus_and_borderline_domains() {
        let applicable = lwe(512, "4", SampleCount::Finite { count: 512 }, gaussian("1"));
        assert_eq!(
            slow_attack_applicability(&applicable, Attack::Bkw)
                .unwrap()
                .level,
            ApplicabilityLevel::Applicable
        );

        let borderline = lwe(128, "512", SampleCount::Unlimited, gaussian("3.2"));
        assert_eq!(
            slow_attack_applicability(&borderline, Attack::Bkw)
                .unwrap()
                .level,
            ApplicabilityLevel::Borderline
        );

        let outside = lwe(728, "2013265921", SampleCount::Unlimited, gaussian("11000"));
        assert_eq!(
            slow_attack_applicability(&outside, Attack::Bkw)
                .unwrap()
                .level,
            ApplicabilityLevel::Inapplicable
        );
    }
}

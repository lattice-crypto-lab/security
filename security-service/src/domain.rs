use std::{collections::BTreeMap, fmt, str::FromStr};

use bigdecimal::BigDecimal;
use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::validation::ValidationError;

/// A canonical unsigned decimal integer serialized as a JSON string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct PositiveInteger(#[schemars(regex(pattern = r"^(0|[1-9][0-9]*)$"))] String);

impl PositiveInteger {
    pub fn new(value: impl AsRef<str>) -> Result<Self, String> {
        let value = value.as_ref();
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("expected an unsigned base-10 integer string".into());
        }
        let normalized = value.trim_start_matches('0');
        Ok(Self(if normalized.is_empty() {
            "0".into()
        } else {
            normalized.into()
        }))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_biguint(&self) -> BigUint {
        BigUint::from_str(&self.0).expect("validated decimal integer")
    }
}

impl<'de> Deserialize<'de> for PositiveInteger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

impl fmt::Display for PositiveInteger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A canonical signed decimal integer serialized as a JSON string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct SignedInteger(#[schemars(regex(pattern = r"^(0|-?[1-9][0-9]*)$"))] String);

impl SignedInteger {
    pub fn new(value: impl AsRef<str>) -> Result<Self, String> {
        let value = value.as_ref();
        let (negative, digits) = match value.strip_prefix('-') {
            Some(digits) => (true, digits),
            None => (false, value),
        };
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("expected a signed base-10 integer string".into());
        }
        let normalized = digits.trim_start_matches('0');
        if normalized.is_empty() {
            return Ok(Self("0".into()));
        }
        Ok(Self(if negative {
            format!("-{normalized}")
        } else {
            normalized.into()
        }))
    }

    pub fn as_bigint(&self) -> BigInt {
        BigInt::from_str(&self.0).expect("validated signed integer")
    }
}

impl<'de> Deserialize<'de> for SignedInteger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// A canonical, finite base-10 decimal serialized as a JSON string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ExactDecimal(
    #[schemars(regex(pattern = r"^(?:0|-?(?:0\.[0-9]*[1-9]|[1-9][0-9]*(?:\.[0-9]*[1-9])?))$"))]
    String,
);

impl ExactDecimal {
    pub fn new(value: impl AsRef<str>) -> Result<Self, String> {
        let value = value.as_ref();
        if value.is_empty() || value.starts_with('+') || value.contains(['e', 'E']) {
            return Err(
                "expected a plain finite base-10 decimal string without an exponent".into(),
            );
        }
        let (negative, unsigned) = match value.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, value),
        };
        let mut pieces = unsigned.split('.');
        let integer = pieces.next().unwrap_or_default();
        let fraction = pieces.next();
        if pieces.next().is_some()
            || integer.is_empty()
            || !integer.bytes().all(|byte| byte.is_ascii_digit())
            || fraction.is_some_and(|part| {
                part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err("expected a plain finite base-10 decimal string".into());
        }

        let integer = integer.trim_start_matches('0');
        let integer = if integer.is_empty() { "0" } else { integer };
        let fraction = fraction
            .map(|part| part.trim_end_matches('0'))
            .unwrap_or_default();
        let is_zero = integer == "0" && fraction.is_empty();
        let sign = if negative && !is_zero { "-" } else { "" };
        let normalized = if fraction.is_empty() {
            format!("{sign}{integer}")
        } else {
            format!("{sign}{integer}.{fraction}")
        };
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_big_decimal(&self) -> BigDecimal {
        BigDecimal::from_str(&self.0).expect("validated exact decimal")
    }

    pub fn is_positive(&self) -> bool {
        self.as_big_decimal() > BigDecimal::zero()
    }
}

impl<'de> Deserialize<'de> for ExactDecimal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

impl fmt::Display for ExactDecimal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SampleCount {
    Finite { count: u64 },
    Unlimited,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegacyclicRing {
    #[schemars(range(min = 1))]
    pub polynomial_degree: u64,
    pub ciphertext_modulus: PositiveInteger,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretDistribution {
    UniformBinary,
    UniformTernary,
    /// Independent coefficients with P(-1)=1/4, P(0)=1/2, and P(1)=1/4.
    SparseTernary {},
    FixedWeightBinary {
        hamming_weight: u64,
    },
    FixedWeightTernary {
        positive_weight: u64,
        negative_weight: u64,
    },
    DiscreteGaussian {
        standard_deviation: ExactDecimal,
    },
    CenteredBinomial {
        eta: u64,
    },
    UniformInteger {
        lower: SignedInteger,
        upper: SignedInteger,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ErrorDistribution {
    DiscreteGaussian {
        standard_deviation: ExactDecimal,
    },
    CenteredBinomial {
        eta: u64,
    },
    UniformInteger {
        lower: SignedInteger,
        upper: SignedInteger,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LweProblem {
    #[schemars(range(min = 1))]
    pub dimension: u64,
    pub modulus: PositiveInteger,
    pub samples: SampleCount,
    pub secret: SecretDistribution,
    pub error: ErrorDistribution,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RlweProblem {
    pub negacyclic_ring: NegacyclicRing,
    pub samples: SampleCount,
    pub secret: SecretDistribution,
    pub error: ErrorDistribution,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GlweProblem {
    pub negacyclic_ring: NegacyclicRing,
    #[schemars(range(min = 1))]
    pub dimension: u64,
    pub samples: SampleCount,
    pub secret: SecretDistribution,
    pub error: ErrorDistribution,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NtruStructure {
    Matrix,
    Circulant,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NtruProblem {
    #[schemars(range(min = 1))]
    pub dimension: u64,
    pub modulus: PositiveInteger,
    pub secret: SecretDistribution,
    pub error: ErrorDistribution,
    pub structure: NtruStructure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SisNorm {
    L2,
    LInfinity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SisProblem {
    #[schemars(range(min = 1))]
    pub dimension: u64,
    pub modulus: PositiveInteger,
    #[schemars(range(min = 1))]
    pub columns: u64,
    pub length_bound: ExactDecimal,
    pub norm: SisNorm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Problem {
    Lwe(LweProblem),
    Rlwe(RlweProblem),
    Glwe(GlweProblem),
    Ntru(NtruProblem),
    Sis(SisProblem),
}

/// Problem variants accepted directly by the internal estimator adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EstimatorProblem {
    Lwe(LweProblem),
    Ntru(NtruProblem),
    Sis(SisProblem),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecurityModel {
    Classical,
    Quantum,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ReductionCostModel {
    #[serde(rename = "BDGL16")]
    Bdgl16,
    #[serde(rename = "LaaMosPol14")]
    LaaMosPol14,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ReductionShapeModel {
    #[serde(rename = "GSA")]
    Gsa,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReductionModel {
    CoefficientEmbeddingV1,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Attack {
    AroraGb,
    Bkw,
    Usvp,
    Bdd,
    BddHybrid,
    BddMitmHybrid,
    Dual,
    DualHybrid,
    Dsd,
    Lattice,
}

impl Attack {
    pub const LWE: [Self; 8] = [
        Self::AroraGb,
        Self::Bkw,
        Self::Usvp,
        Self::Bdd,
        Self::BddHybrid,
        Self::BddMitmHybrid,
        Self::Dual,
        Self::DualHybrid,
    ];
    pub const LWE_FAST: [Self; 6] = [
        Self::Usvp,
        Self::Bdd,
        Self::BddHybrid,
        Self::BddMitmHybrid,
        Self::Dual,
        Self::DualHybrid,
    ];
    pub const LWE_SLOW: [Self; 2] = [Self::AroraGb, Self::Bkw];
    pub const NTRU: [Self; 5] = [
        Self::Usvp,
        Self::Dsd,
        Self::Bdd,
        Self::BddHybrid,
        Self::BddMitmHybrid,
    ];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalysisSettings {
    pub security_model: SecurityModel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_model: Option<ReductionCostModel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape_model: Option<ReductionShapeModel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduction_model: Option<ReductionModel>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolvedAnalysisSettings {
    pub security_model: SecurityModel,
    pub cost_model: ReductionCostModel,
    pub shape_model: ReductionShapeModel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduction_model: Option<ReductionModel>,
}

impl Default for AnalysisSettings {
    fn default() -> Self {
        Self {
            security_model: SecurityModel::Classical,
            cost_model: None,
            shape_model: None,
            reduction_model: None,
        }
    }
}

impl AnalysisSettings {
    pub fn resolve(&self) -> ResolvedAnalysisSettings {
        let cost_model = self.cost_model.unwrap_or(match self.security_model {
            SecurityModel::Classical => ReductionCostModel::Bdgl16,
            SecurityModel::Quantum => ReductionCostModel::LaaMosPol14,
        });
        let shape_model = self.shape_model.unwrap_or(ReductionShapeModel::Gsa);
        ResolvedAnalysisSettings {
            security_model: self.security_model,
            cost_model,
            shape_model,
            reduction_model: self.reduction_model,
        }
    }
}

pub fn attacks_for_problem(problem: &Problem) -> &'static [Attack] {
    match problem {
        Problem::Lwe(_) | Problem::Rlwe(_) | Problem::Glwe(_) => &Attack::LWE,
        Problem::Ntru(_) => &Attack::NTRU,
        Problem::Sis(_) => &[Attack::Lattice],
    }
}

pub fn fast_attacks_for_problem(problem: &Problem) -> &'static [Attack] {
    match problem {
        Problem::Lwe(_) | Problem::Rlwe(_) | Problem::Glwe(_) => &Attack::LWE_FAST,
        Problem::Ntru(_) => &Attack::NTRU,
        Problem::Sis(_) => &[Attack::Lattice],
    }
}

pub fn slow_attacks_for_problem(problem: &Problem) -> &'static [Attack] {
    match problem {
        Problem::Lwe(_) | Problem::Rlwe(_) | Problem::Glwe(_) => &Attack::LWE_SLOW,
        Problem::Ntru(_) | Problem::Sis(_) => &[],
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NormalizedMetric {
    Integer { value: SignedInteger },
    Decimal { value: ExactDecimal },
    Boolean { value: bool },
    Text { value: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproximationProvenance {
    pub model_id: String,
    pub model_version: u32,
    pub model_hash: String,
    pub dataset_hash: String,
    pub feature_schema: String,
    pub estimator_commit: String,
    pub sage_version: String,
    pub adapter_version: String,
    pub worker_image: String,
    pub platform: String,
    pub training_points: u64,
    pub holdout_samples: u64,
    pub holdout_mean_absolute_error_bits: ExactDecimal,
    pub holdout_p95_absolute_error_bits: ExactDecimal,
    pub holdout_max_overestimate_bits: ExactDecimal,
    pub safety_margin_bits: ExactDecimal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttackOutcome {
    Computed {
        security_bits: ExactDecimal,
        duration_ms: u64,
        #[serde(default)]
        metrics: BTreeMap<String, NormalizedMetric>,
    },
    Approximate {
        security_bits: ExactDecimal,
        provenance: Box<ApproximationProvenance>,
    },
    NoFiniteEstimate {
        code: String,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        raw_result: Option<serde_json::Value>,
    },
    Timeout {
        timeout_seconds: u64,
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
    PolicySkipped {
        code: String,
        reason: String,
        applicability_rule_version: u32,
    },
    Skipped {
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AnalysisModel {
    DirectLwe {
        version: u32,
    },
    DirectNtru {
        version: u32,
    },
    DirectSis {
        version: u32,
    },
    CoefficientEmbeddingV1 {
        version: u32,
        source_ring_samples: SampleCount,
        scalar_samples: SampleCount,
        derived_lwe: Box<LweProblem>,
        warnings: Vec<String>,
    },
}

pub fn analysis_model_for(
    problem: &Problem,
    settings: &AnalysisSettings,
) -> Result<AnalysisModel, ValidationError> {
    match problem {
        Problem::Lwe(_) => Ok(AnalysisModel::DirectLwe { version: 1 }),
        Problem::Ntru(_) => Ok(AnalysisModel::DirectNtru { version: 1 }),
        Problem::Sis(_) => Ok(AnalysisModel::DirectSis { version: 1 }),
        Problem::Rlwe(problem) => {
            require_coefficient_embedding(settings)?;
            coefficient_embedding(
                &problem.negacyclic_ring,
                1,
                &problem.samples,
                &problem.secret,
                &problem.error,
            )
        }
        Problem::Glwe(problem) => {
            require_coefficient_embedding(settings)?;
            coefficient_embedding(
                &problem.negacyclic_ring,
                problem.dimension,
                &problem.samples,
                &problem.secret,
                &problem.error,
            )
        }
    }
}

fn require_coefficient_embedding(settings: &AnalysisSettings) -> Result<(), ValidationError> {
    if settings.reduction_model != Some(ReductionModel::CoefficientEmbeddingV1) {
        return Err(ValidationError::new(
            "analysis.reduction_model",
            "RLWE/GLWE requires an explicit coefficient_embedding_v1 reduction model",
        ));
    }
    Ok(())
}

fn coefficient_embedding(
    ring: &NegacyclicRing,
    glwe_dimension: u64,
    ring_samples: &SampleCount,
    secret: &SecretDistribution,
    error: &ErrorDistribution,
) -> Result<AnalysisModel, ValidationError> {
    let dimension = glwe_dimension
        .checked_mul(ring.polynomial_degree)
        .ok_or_else(|| ValidationError::new("problem", "derived scalar dimension overflows u64"))?;
    let scalar_samples = match ring_samples {
        SampleCount::Finite { count } => SampleCount::Finite {
            count: count.checked_mul(ring.polynomial_degree).ok_or_else(|| {
                ValidationError::new(
                    "problem.samples",
                    "derived scalar sample count overflows u64",
                )
            })?,
        },
        SampleCount::Unlimited => SampleCount::Unlimited,
    };
    Ok(AnalysisModel::CoefficientEmbeddingV1 {
        version: 1,
        source_ring_samples: ring_samples.clone(),
        scalar_samples: scalar_samples.clone(),
        derived_lwe: Box::new(LweProblem {
            dimension,
            modulus: ring.ciphertext_modulus.clone(),
            samples: scalar_samples,
            secret: secret.clone(),
            error: error.clone(),
        }),
        warnings: vec![
            "coefficient_embedding_v1 treats structured coefficient equations as an unstructured LWE instance"
                .into(),
            "the estimate does not constitute a direct analysis of the original ring problem".into(),
        ],
    })
}

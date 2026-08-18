use std::{cmp::Ordering, collections::HashSet, fs, path::Path, sync::Arc};

use num_traits::ToPrimitive;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ApproximationProvenance, error::ServiceError};
use crate::{
    Attack, AttackCacheIdentity, AttackOutcome, ErrorDistribution, EstimatorContext,
    EstimatorProblem, ExactDecimal, ReductionCostModel, ReductionShapeModel, SampleCount,
    SecretDistribution, SecurityModel, stable_hash,
};

pub const APPROXIMATION_MODEL_FORMAT: &str = "lattice-security/slow-attack-model";
pub const APPROXIMATION_MODEL_VERSION: u32 = 1;
pub const APPROXIMATION_FEATURE_SCHEMA: &str = "lwe-log2-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalibrationProvenance {
    pub estimator_commit: String,
    pub sage_version: String,
    pub adapter_version: String,
    pub worker_image: String,
    pub platform: String,
    pub dataset_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeatureRange {
    pub min: ExactDecimal,
    pub max: ExactDecimal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproximationDomain {
    pub log2_dimension: FeatureRange,
    pub log2_modulus: FeatureRange,
    pub log2_error_standard_deviation: FeatureRange,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log2_samples: Option<FeatureRange>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationSampleMode {
    Unlimited,
    Finite,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalibrationPoint {
    pub log2_dimension: ExactDecimal,
    pub log2_modulus: ExactDecimal,
    pub log2_error_standard_deviation: ExactDecimal,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log2_samples: Option<ExactDecimal>,
    pub security_bits: ExactDecimal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HoldoutMetrics {
    pub samples: u64,
    pub mean_absolute_error_bits: ExactDecimal,
    pub p95_absolute_error_bits: ExactDecimal,
    pub max_overestimate_bits: ExactDecimal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproximationGroup {
    pub id: String,
    pub attack: Attack,
    pub security_model: SecurityModel,
    pub cost_model: ReductionCostModel,
    pub shape_model: ReductionShapeModel,
    pub secret: SecretDistribution,
    pub sample_mode: CalibrationSampleMode,
    pub domain: ApproximationDomain,
    pub neighbor_count: u32,
    pub max_normalized_distance: ExactDecimal,
    pub safety_margin_bits: ExactDecimal,
    pub holdout: HoldoutMetrics,
    pub points: Vec<CalibrationPoint>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproximationModelFile {
    pub format: String,
    pub version: u32,
    pub model_id: String,
    pub generated_at: String,
    pub feature_schema: String,
    pub provenance: CalibrationProvenance,
    pub groups: Vec<ApproximationGroup>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproximationMetadata {
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub attacks: Vec<Attack>,
    pub group_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

#[derive(Clone)]
pub struct ApproximationEngine {
    model: Option<Arc<ApproximationModelFile>>,
    model_hash: Option<String>,
    unavailable_reason: Option<String>,
}

pub struct ApproximationPrediction {
    pub cache_key: String,
    pub model_hash: String,
    pub outcome: AttackOutcome,
}

impl ApproximationEngine {
    pub fn disabled(reason: impl Into<String>) -> Self {
        Self {
            model: None,
            model_hash: None,
            unavailable_reason: Some(reason.into()),
        }
    }

    pub fn load(path: Option<&Path>, context: &EstimatorContext) -> Result<Self, ServiceError> {
        let Some(path) = path else {
            return Ok(Self::disabled("no approximation model configured"));
        };
        if !path.exists() {
            return Ok(Self::disabled(format!(
                "approximation model not found at {}",
                path.display()
            )));
        }
        let bytes = fs::read(path).map_err(ServiceError::database)?;
        let model: ApproximationModelFile =
            serde_json::from_slice(&bytes).map_err(ServiceError::database)?;
        validate_model(&model, context)?;
        let model_hash = stable_hash(&model);
        Ok(Self {
            model: Some(Arc::new(model)),
            model_hash: Some(model_hash),
            unavailable_reason: None,
        })
    }

    pub fn from_model(
        model: ApproximationModelFile,
        context: &EstimatorContext,
    ) -> Result<Self, ServiceError> {
        validate_model(&model, context)?;
        let model_hash = stable_hash(&model);
        Ok(Self {
            model: Some(Arc::new(model)),
            model_hash: Some(model_hash),
            unavailable_reason: None,
        })
    }

    pub fn metadata(&self) -> ApproximationMetadata {
        let Some(model) = &self.model else {
            return ApproximationMetadata {
                available: false,
                unavailable_reason: self.unavailable_reason.clone(),
                ..ApproximationMetadata::default()
            };
        };
        let mut attacks = model
            .groups
            .iter()
            .map(|group| group.attack)
            .collect::<Vec<_>>();
        attacks.sort();
        attacks.dedup();
        ApproximationMetadata {
            available: !model.groups.is_empty(),
            model_id: Some(model.model_id.clone()),
            model_version: Some(model.version),
            model_hash: self.model_hash.clone(),
            dataset_hash: Some(model.provenance.dataset_hash.clone()),
            generated_at: Some(model.generated_at.clone()),
            attacks,
            group_count: model.groups.len(),
            unavailable_reason: model
                .groups
                .is_empty()
                .then(|| "model contains no calibrated groups".to_owned()),
        }
    }

    pub fn unavailable_reason(&self) -> &str {
        self.unavailable_reason
            .as_deref()
            .unwrap_or("parameters are outside the calibrated model domain")
    }

    pub fn cache_key(&self, identity: &AttackCacheIdentity) -> Option<String> {
        self.model_hash
            .as_ref()
            .map(|model_hash| stable_hash(&(identity, model_hash)))
    }

    pub fn predict(
        &self,
        identity: &AttackCacheIdentity,
    ) -> Result<Option<ApproximationPrediction>, ServiceError> {
        let Some(model) = &self.model else {
            return Ok(None);
        };
        if !matches!(identity.attack, Attack::AroraGb | Attack::Bkw) {
            return Ok(None);
        }
        let EstimatorProblem::Lwe(problem) = &identity.estimator_problem else {
            return Ok(None);
        };
        let ErrorDistribution::DiscreteGaussian { standard_deviation } = &problem.error else {
            return Ok(None);
        };
        let features = RuntimeFeatures::new(
            problem.dimension,
            problem.modulus.as_biguint().to_f64(),
            standard_deviation.as_big_decimal().to_f64(),
            &problem.samples,
        )?;
        let Some((group, predicted)) = model.groups.iter().find_map(|group| {
            group_matches(group, identity, &problem.secret, &problem.samples)
                .then(|| predict_group(group, &features))
                .flatten()
                .map(|value| (group, value))
        }) else {
            return Ok(None);
        };
        let model_hash = self
            .model_hash
            .as_ref()
            .expect("loaded model has a hash")
            .clone();
        let security_bits = conservative_decimal(predicted)?;
        let provenance = ApproximationProvenance {
            model_id: model.model_id.clone(),
            model_version: model.version,
            model_hash: model_hash.clone(),
            dataset_hash: model.provenance.dataset_hash.clone(),
            feature_schema: model.feature_schema.clone(),
            estimator_commit: model.provenance.estimator_commit.clone(),
            sage_version: model.provenance.sage_version.clone(),
            adapter_version: model.provenance.adapter_version.clone(),
            worker_image: model.provenance.worker_image.clone(),
            platform: model.provenance.platform.clone(),
            training_points: u64::try_from(group.points.len()).map_err(ServiceError::database)?,
            holdout_samples: group.holdout.samples,
            holdout_mean_absolute_error_bits: group.holdout.mean_absolute_error_bits.clone(),
            holdout_p95_absolute_error_bits: group.holdout.p95_absolute_error_bits.clone(),
            holdout_max_overestimate_bits: group.holdout.max_overestimate_bits.clone(),
            safety_margin_bits: group.safety_margin_bits.clone(),
        };
        let cache_key = stable_hash(&(identity, &model_hash));
        Ok(Some(ApproximationPrediction {
            cache_key,
            model_hash,
            outcome: AttackOutcome::Approximate {
                security_bits,
                provenance: Box::new(provenance),
            },
        }))
    }
}

fn validate_model(
    model: &ApproximationModelFile,
    context: &EstimatorContext,
) -> Result<(), ServiceError> {
    if model.format != APPROXIMATION_MODEL_FORMAT
        || model.version != APPROXIMATION_MODEL_VERSION
        || model.feature_schema != APPROXIMATION_FEATURE_SCHEMA
    {
        return Err(ServiceError::BadRequest(
            "unsupported approximation model contract".to_owned(),
        ));
    }
    let provenance = &model.provenance;
    if provenance.estimator_commit != context.estimator_commit
        || provenance.sage_version != context.sage_version
        || provenance.adapter_version != context.adapter_version
        || provenance.worker_image != context.worker_image
    {
        return Err(ServiceError::BadRequest(
            "approximation model provenance does not match estimator context".to_owned(),
        ));
    }
    if provenance.platform != "linux/amd64"
        || !valid_sha256(&provenance.dataset_hash)
        || model.model_id.is_empty()
        || model.generated_at.is_empty()
        || model.groups.is_empty()
    {
        return Err(ServiceError::BadRequest(
            "approximation model has no calibrated data".to_owned(),
        ));
    }
    let mut group_ids = HashSet::new();
    let mut selectors = HashSet::new();
    for group in &model.groups {
        let selector = stable_hash(&(
            group.attack,
            group.security_model,
            group.cost_model,
            group.shape_model,
            &group.secret,
            group.sample_mode,
        ));
        if group.id.is_empty()
            || !group_ids.insert(group.id.clone())
            || !selectors.insert(selector)
            || !matches!(group.attack, Attack::AroraGb | Attack::Bkw)
            || group.neighbor_count == 0
            || usize::try_from(group.neighbor_count).unwrap_or(usize::MAX) > group.points.len()
            || group.holdout.samples == 0
            || !group.max_normalized_distance.is_positive()
            || !group.safety_margin_bits.is_positive()
            || is_negative(&group.holdout.mean_absolute_error_bits)
            || is_negative(&group.holdout.p95_absolute_error_bits)
        {
            return Err(ServiceError::BadRequest(format!(
                "invalid approximation group '{}'",
                group.id
            )));
        }
        validate_range(&group.domain.log2_dimension)?;
        validate_range(&group.domain.log2_modulus)?;
        validate_range(&group.domain.log2_error_standard_deviation)?;
        match (group.sample_mode, &group.domain.log2_samples) {
            (CalibrationSampleMode::Finite, Some(range)) => validate_range(range)?,
            (CalibrationSampleMode::Unlimited, None) => {}
            _ => {
                return Err(ServiceError::BadRequest(format!(
                    "sample domain disagrees in approximation group '{}'",
                    group.id
                )));
            }
        }
        let Some(ranges) = group_ranges(group) else {
            return Err(ServiceError::BadRequest(format!(
                "unrepresentable approximation group '{}'",
                group.id
            )));
        };
        for point in &group.points {
            let sample_shape_matches = matches!(
                (group.sample_mode, &point.log2_samples),
                (CalibrationSampleMode::Unlimited, None) | (CalibrationSampleMode::Finite, Some(_))
            );
            let values = point_values(point);
            if !sample_shape_matches
                || is_negative(&point.security_bits)
                || values.as_ref().is_none_or(|values| {
                    values.len() != ranges.len()
                        || values
                            .iter()
                            .zip(&ranges)
                            .any(|(value, (min, max))| value < min || value > max)
                })
            {
                return Err(ServiceError::BadRequest(format!(
                    "invalid calibration point in group '{}'",
                    group.id
                )));
            }
        }
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_negative(value: &ExactDecimal) -> bool {
    value.as_str().starts_with('-')
}

fn validate_range(range: &FeatureRange) -> Result<(), ServiceError> {
    if range.min.as_big_decimal() > range.max.as_big_decimal() {
        return Err(ServiceError::BadRequest(
            "approximation domain minimum exceeds maximum".to_owned(),
        ));
    }
    Ok(())
}

fn group_matches(
    group: &ApproximationGroup,
    identity: &AttackCacheIdentity,
    secret: &SecretDistribution,
    samples: &SampleCount,
) -> bool {
    group.attack == identity.attack
        && group.security_model == identity.resolved_analysis.security_model
        && group.cost_model == identity.resolved_analysis.cost_model
        && group.shape_model == identity.resolved_analysis.shape_model
        && &group.secret == secret
        && matches!(
            (group.sample_mode, samples),
            (CalibrationSampleMode::Unlimited, SampleCount::Unlimited)
                | (CalibrationSampleMode::Finite, SampleCount::Finite { .. })
        )
}

struct RuntimeFeatures {
    values: Vec<f64>,
}

impl RuntimeFeatures {
    fn new(
        dimension: u64,
        modulus: Option<f64>,
        error_standard_deviation: Option<f64>,
        samples: &SampleCount,
    ) -> Result<Self, ServiceError> {
        let modulus = modulus.filter(|value| value.is_finite() && *value > 0.0);
        let error = error_standard_deviation.filter(|value| value.is_finite() && *value > 0.0);
        let (Some(modulus), Some(error)) = (modulus, error) else {
            return Err(ServiceError::BadRequest(
                "parameters cannot be represented by approximation feature schema".to_owned(),
            ));
        };
        let mut values = vec![(dimension as f64).log2(), modulus.log2(), error.log2()];
        if let SampleCount::Finite { count } = samples {
            values.push((*count as f64).log2());
        }
        Ok(Self { values })
    }
}

fn predict_group(group: &ApproximationGroup, features: &RuntimeFeatures) -> Option<f64> {
    let ranges = group_ranges(group)?;
    if ranges.len() != features.values.len()
        || !features
            .values
            .iter()
            .zip(&ranges)
            .all(|(value, (min, max))| *value >= *min && *value <= *max)
    {
        return None;
    }
    let mut neighbors = group
        .points
        .iter()
        .filter_map(|point| {
            let point_values = point_values(point)?;
            let distance = normalized_distance(&features.values, &point_values, &ranges);
            let security = point.security_bits.as_big_decimal().to_f64()?;
            Some((distance, security))
        })
        .collect::<Vec<_>>();
    neighbors.sort_by(|left, right| left.0.partial_cmp(&right.0).unwrap_or(Ordering::Equal));
    let nearest_distance = neighbors.first()?.0;
    let maximum = group.max_normalized_distance.as_big_decimal().to_f64()?;
    if nearest_distance > maximum {
        return None;
    }
    if nearest_distance <= f64::EPSILON {
        let margin = group.safety_margin_bits.as_big_decimal().to_f64()?;
        return Some((neighbors[0].1 - margin).max(0.0));
    }
    let count = usize::try_from(group.neighbor_count)
        .ok()?
        .min(neighbors.len());
    let (weighted, total_weight) = neighbors.into_iter().take(count).fold(
        (0.0, 0.0),
        |(weighted, total_weight), (distance, security)| {
            let weight = 1.0 / distance.max(1e-12).powi(2);
            (weighted + security * weight, total_weight + weight)
        },
    );
    let margin = group.safety_margin_bits.as_big_decimal().to_f64()?;
    Some((weighted / total_weight - margin).max(0.0))
}

fn group_ranges(group: &ApproximationGroup) -> Option<Vec<(f64, f64)>> {
    let mut ranges = vec![
        range_values(&group.domain.log2_dimension)?,
        range_values(&group.domain.log2_modulus)?,
        range_values(&group.domain.log2_error_standard_deviation)?,
    ];
    if let Some(samples) = &group.domain.log2_samples {
        ranges.push(range_values(samples)?);
    }
    Some(ranges)
}

fn range_values(range: &FeatureRange) -> Option<(f64, f64)> {
    Some((
        range.min.as_big_decimal().to_f64()?,
        range.max.as_big_decimal().to_f64()?,
    ))
}

fn point_values(point: &CalibrationPoint) -> Option<Vec<f64>> {
    let mut values = vec![
        point.log2_dimension.as_big_decimal().to_f64()?,
        point.log2_modulus.as_big_decimal().to_f64()?,
        point
            .log2_error_standard_deviation
            .as_big_decimal()
            .to_f64()?,
    ];
    if let Some(samples) = &point.log2_samples {
        values.push(samples.as_big_decimal().to_f64()?);
    }
    Some(values)
}

fn normalized_distance(values: &[f64], point: &[f64], ranges: &[(f64, f64)]) -> f64 {
    values
        .iter()
        .zip(point)
        .zip(ranges)
        .map(|((value, point), (min, max))| {
            let width = (max - min).abs();
            let scale = if width <= f64::EPSILON { 1.0 } else { width };
            ((value - point) / scale).powi(2)
        })
        .sum::<f64>()
        .sqrt()
}

fn conservative_decimal(value: f64) -> Result<ExactDecimal, ServiceError> {
    if !value.is_finite() || value < 0.0 {
        return Err(ServiceError::Internal(
            "approximation produced a non-finite value".to_owned(),
        ));
    }
    let floored = (value * 1_000_000.0).floor() / 1_000_000.0;
    ExactDecimal::new(format!("{floored:.6}"))
        .map_err(|error| ServiceError::Internal(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnalysisModel, LweProblem, PositiveInteger, ResolvedAnalysisSettings};

    fn decimal(value: &str) -> ExactDecimal {
        ExactDecimal::new(value).unwrap()
    }

    fn context() -> EstimatorContext {
        EstimatorContext {
            estimator_commit: "estimator-commit".to_owned(),
            sage_version: "10.9".to_owned(),
            adapter_version: "1".to_owned(),
            worker_image: "worker@sha256:test".to_owned(),
        }
    }

    fn model() -> ApproximationModelFile {
        ApproximationModelFile {
            format: APPROXIMATION_MODEL_FORMAT.to_owned(),
            version: APPROXIMATION_MODEL_VERSION,
            model_id: "test-slow-v1".to_owned(),
            generated_at: "2026-08-18T00:00:00Z".to_owned(),
            feature_schema: APPROXIMATION_FEATURE_SCHEMA.to_owned(),
            provenance: CalibrationProvenance {
                estimator_commit: "estimator-commit".to_owned(),
                sage_version: "10.9".to_owned(),
                adapter_version: "1".to_owned(),
                worker_image: "worker@sha256:test".to_owned(),
                platform: "linux/amd64".to_owned(),
                dataset_hash: format!("sha256:{}", "d".repeat(64)),
            },
            groups: vec![ApproximationGroup {
                id: "bkw-binary-unlimited".to_owned(),
                attack: Attack::Bkw,
                security_model: SecurityModel::Classical,
                cost_model: ReductionCostModel::Bdgl16,
                shape_model: ReductionShapeModel::Gsa,
                secret: SecretDistribution::UniformBinary,
                sample_mode: CalibrationSampleMode::Unlimited,
                domain: ApproximationDomain {
                    log2_dimension: FeatureRange {
                        min: decimal("8"),
                        max: decimal("8"),
                    },
                    log2_modulus: FeatureRange {
                        min: decimal("16"),
                        max: decimal("16"),
                    },
                    log2_error_standard_deviation: FeatureRange {
                        min: decimal("2"),
                        max: decimal("2"),
                    },
                    log2_samples: None,
                },
                neighbor_count: 1,
                max_normalized_distance: decimal("0.1"),
                safety_margin_bits: decimal("2"),
                holdout: HoldoutMetrics {
                    samples: 5,
                    mean_absolute_error_bits: decimal("1"),
                    p95_absolute_error_bits: decimal("1.5"),
                    max_overestimate_bits: decimal("0.5"),
                },
                points: vec![CalibrationPoint {
                    log2_dimension: decimal("8"),
                    log2_modulus: decimal("16"),
                    log2_error_standard_deviation: decimal("2"),
                    log2_samples: None,
                    security_bits: decimal("100"),
                }],
            }],
        }
    }

    fn identity(dimension: u64) -> AttackCacheIdentity {
        AttackCacheIdentity::new(
            EstimatorProblem::Lwe(LweProblem {
                dimension,
                modulus: PositiveInteger::new("65536").unwrap(),
                samples: SampleCount::Unlimited,
                secret: SecretDistribution::UniformBinary,
                error: ErrorDistribution::DiscreteGaussian {
                    standard_deviation: decimal("4"),
                },
            }),
            AnalysisModel::DirectLwe { version: 1 },
            ResolvedAnalysisSettings {
                security_model: SecurityModel::Classical,
                cost_model: ReductionCostModel::Bdgl16,
                shape_model: ReductionShapeModel::Gsa,
                reduction_model: None,
            },
            Attack::Bkw,
            context(),
        )
    }

    #[test]
    fn prediction_is_margin_adjusted_and_carries_holdout_provenance() {
        let engine = ApproximationEngine::from_model(model(), &context()).unwrap();
        let prediction = engine.predict(&identity(256)).unwrap().unwrap();
        let AttackOutcome::Approximate {
            security_bits,
            provenance,
        } = prediction.outcome
        else {
            panic!("expected approximate outcome");
        };
        assert_eq!(security_bits, decimal("98"));
        assert_eq!(provenance.holdout_samples, 5);
        assert_eq!(provenance.safety_margin_bits, decimal("2"));
        assert!(prediction.cache_key.starts_with("sha256:"));
    }

    #[test]
    fn prediction_refuses_parameters_outside_the_calibrated_domain() {
        let engine = ApproximationEngine::from_model(model(), &context()).unwrap();
        assert!(engine.predict(&identity(512)).unwrap().is_none());
    }

    #[test]
    fn model_provenance_must_match_the_live_estimator() {
        let mut mismatched = context();
        mismatched.sage_version = "11.0".to_owned();
        assert!(ApproximationEngine::from_model(model(), &mismatched).is_err());
    }
}

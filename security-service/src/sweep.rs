use std::collections::HashSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ErrorDistribution, EstimateRequest, ParameterCase, Problem, SampleCount, SweepAxis,
    SweepRequest, Validate, error::ServiceError, service::BatchSnapshot,
};

pub const MAX_SWEEP_CASES: usize = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SweepResponse {
    pub sweep_id: String,
    pub case_count: usize,
    pub batch_ids: Vec<String>,
    pub batches: Vec<BatchSnapshot>,
}

pub fn expand(request: &SweepRequest) -> Result<Vec<ParameterCase>, ServiceError> {
    request.base_case.validate()?;
    if request.axes.is_empty() || request.axes.len() > 4 {
        return Err(ServiceError::BadRequest(
            "sweep requires 1..=4 axes".to_owned(),
        ));
    }
    let mut kinds = HashSet::new();
    let mut total = 1usize;
    for axis in &request.axes {
        let (kind, len) = axis_kind_len(axis);
        if !kinds.insert(kind) {
            return Err(ServiceError::BadRequest(format!(
                "sweep axis '{kind}' appears more than once"
            )));
        }
        if len == 0 {
            return Err(ServiceError::BadRequest(format!(
                "sweep axis '{kind}' has no values"
            )));
        }
        total = total
            .checked_mul(len)
            .filter(|total| *total <= MAX_SWEEP_CASES)
            .ok_or_else(|| {
                ServiceError::BadRequest(format!("sweep exceeds the {MAX_SWEEP_CASES} case limit"))
            })?;
    }

    let mut cases = vec![request.base_case.clone()];
    for axis in &request.axes {
        let mut next = Vec::with_capacity(cases.len() * axis_kind_len(axis).1);
        for case in cases {
            for value_index in 0..axis_kind_len(axis).1 {
                let mut generated = case.clone();
                apply_axis(&mut generated, axis, value_index)?;
                next.push(generated);
            }
        }
        cases = next;
    }
    for (index, case) in cases.iter_mut().enumerate() {
        case.id = format!("{}-s{:05}", request.base_case.id, index + 1);
        case.name = format!("{} · sweep {}", request.base_case.name, index + 1);
        if !case.tags.iter().any(|tag| tag == "sweep") {
            case.tags.push("sweep".to_owned());
        }
        case.validate().map_err(|error| {
            ServiceError::BadRequest(format!(
                "generated case {} is invalid at {}: {}",
                index, error.path, error.message
            ))
        })?;
    }
    let probe = EstimateRequest {
        cases: vec![cases[0].clone()],
        mode: crate::EstimateMode::Normal,
        timeout_seconds: request.timeout_seconds,
        slow_attack_policy: request.slow_attack_policy.clone(),
    };
    probe.validate()?;
    Ok(cases)
}

pub fn response(batches: Vec<BatchSnapshot>, case_count: usize) -> SweepResponse {
    SweepResponse {
        sweep_id: Uuid::new_v4().to_string(),
        case_count,
        batch_ids: batches.iter().map(|batch| batch.batch_id.clone()).collect(),
        batches,
    }
}

fn axis_kind_len(axis: &SweepAxis) -> (&'static str, usize) {
    match axis {
        SweepAxis::Dimension { values } => ("dimension", values.len()),
        SweepAxis::Modulus { values } => ("modulus", values.len()),
        SweepAxis::ErrorStandardDeviation { values } => ("error_standard_deviation", values.len()),
        SweepAxis::SampleCount { values } => ("sample_count", values.len()),
    }
}

fn apply_axis(
    case: &mut ParameterCase,
    axis: &SweepAxis,
    value_index: usize,
) -> Result<(), ServiceError> {
    match axis {
        SweepAxis::Dimension { values } => match &mut case.problem {
            Problem::Lwe(problem) => problem.dimension = values[value_index],
            Problem::Glwe(problem) => problem.dimension = values[value_index],
            Problem::Ntru(problem) => problem.dimension = values[value_index],
            Problem::Sis(problem) => problem.dimension = values[value_index],
            Problem::Rlwe(_) => {
                return Err(incompatible("dimension", "rlwe"));
            }
        },
        SweepAxis::Modulus { values } => match &mut case.problem {
            Problem::Lwe(problem) => problem.modulus = values[value_index].clone(),
            Problem::Rlwe(problem) => {
                problem.negacyclic_ring.ciphertext_modulus = values[value_index].clone();
            }
            Problem::Glwe(problem) => {
                problem.negacyclic_ring.ciphertext_modulus = values[value_index].clone();
            }
            Problem::Ntru(problem) => problem.modulus = values[value_index].clone(),
            Problem::Sis(problem) => problem.modulus = values[value_index].clone(),
        },
        SweepAxis::ErrorStandardDeviation { values } => {
            let error = match &mut case.problem {
                Problem::Lwe(problem) => &mut problem.error,
                Problem::Rlwe(problem) => &mut problem.error,
                Problem::Glwe(problem) => &mut problem.error,
                Problem::Ntru(problem) => &mut problem.error,
                Problem::Sis(_) => return Err(incompatible("error_standard_deviation", "sis")),
            };
            if !matches!(error, ErrorDistribution::DiscreteGaussian { .. }) {
                return Err(ServiceError::BadRequest(
                    "error_standard_deviation requires a discrete_gaussian base error".to_owned(),
                ));
            }
            *error = ErrorDistribution::DiscreteGaussian {
                standard_deviation: values[value_index].clone(),
            };
        }
        SweepAxis::SampleCount { values } => {
            let samples = match &mut case.problem {
                Problem::Lwe(problem) => &mut problem.samples,
                Problem::Rlwe(problem) => &mut problem.samples,
                Problem::Glwe(problem) => &mut problem.samples,
                Problem::Ntru(_) => return Err(incompatible("sample_count", "ntru")),
                Problem::Sis(_) => return Err(incompatible("sample_count", "sis")),
            };
            *samples = SampleCount::Finite {
                count: values[value_index],
            };
        }
    }
    Ok(())
}

fn incompatible(axis: &str, problem: &str) -> ServiceError {
    ServiceError::BadRequest(format!("sweep axis '{axis}' is not valid for {problem}"))
}

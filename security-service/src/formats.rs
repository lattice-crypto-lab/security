use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::domain::{
    AnalysisModel, AnalysisSettings, Attack, AttackOutcome, ExactDecimal, Problem,
    ResolvedAnalysisSettings,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParameterCase {
    #[schemars(length(min = 1, max = 128), regex(pattern = r"^[A-Za-z0-9._-]+$"))]
    pub id: String,
    #[schemars(length(min = 1))]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub problem: Problem,
    #[serde(default)]
    pub analysis: AnalysisSettings,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParameterSetFile {
    #[schemars(schema_with = "parameter_set_format_schema")]
    pub format: String,
    #[schemars(schema_with = "file_version_schema")]
    pub version: u32,
    #[schemars(length(min = 1, max = 128), regex(pattern = r"^[A-Za-z0-9._-]+$"))]
    pub id: String,
    #[schemars(length(min = 1))]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[schemars(length(min = 1, max = 500))]
    pub cases: Vec<ParameterCase>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecuritySummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_bits: Option<ExactDecimal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub best_attack: Option<Attack>,
    pub complete: bool,
    #[serde(default)]
    pub fast_estimate: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttackResult {
    pub attack: Attack,
    #[serde(default)]
    pub cached: bool,
    pub outcome: AttackOutcome,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub estimator_commit: String,
    pub sage_version: String,
    pub adapter_version: String,
    pub worker_image: String,
    pub analysis_model: AnalysisModel,
    pub resolved_analysis: ResolvedAnalysisSettings,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityReportEntry {
    pub case: ParameterCase,
    pub request_hash: String,
    pub provenance: Provenance,
    pub summary: SecuritySummary,
    #[serde(default)]
    pub attacks: Vec<AttackResult>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityReportFile {
    #[schemars(schema_with = "security_report_format_schema")]
    pub format: String,
    #[schemars(schema_with = "file_version_schema")]
    pub version: u32,
    #[schemars(length(min = 1, max = 128), regex(pattern = r"^[A-Za-z0-9._-]+$"))]
    pub id: String,
    #[schemars(length(min = 1))]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter_set_id: Option<String>,
    #[schemars(length(min = 1))]
    pub reports: Vec<SecurityReportEntry>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EstimateRequest {
    pub cases: Vec<ParameterCase>,
    #[serde(default)]
    pub mode: EstimateMode,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slow_attack_policy: Option<SlowAttackPolicy>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EstimateMode {
    Rough,
    #[default]
    Normal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlowAttackPolicy {
    pub required_security_bits: ExactDecimal,
    pub stop_margin_bits: ExactDecimal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub request_id: String,
    #[serde(default)]
    pub details: BTreeMap<String, serde_json::Value>,
}

fn parameter_set_format_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "const": "lattice-security/parameter-set"
    })
}

fn security_report_format_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "const": "lattice-security/security-report"
    })
}

fn file_version_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "integer",
        "const": 1
    })
}

const fn default_timeout_seconds() -> u64 {
    3_600
}

use std::{fs, path::PathBuf};

use lattice_security::{
    AnalysisModel, AnalysisSettings, Attack, AttackCacheIdentity, ErrorDistribution,
    EstimateRequest, EstimatorContext, EstimatorProblem, ExactDecimal, GlweProblem, NegacyclicRing,
    ParameterSetFile, PositiveInteger, Problem, ReductionModel, RlweProblem, SampleCount,
    SecretDistribution, SecurityModel, SecurityReportFile, SlowAttackPolicy, Validate,
    analysis_model_for, attacks_for_problem, fast_attacks_for_problem, slow_attacks_for_problem,
};

fn decimal(value: &str) -> ExactDecimal {
    ExactDecimal::new(value).unwrap()
}

fn integer(value: &str) -> PositiveInteger {
    PositiveInteger::new(value).unwrap()
}

fn gaussian(value: &str) -> ErrorDistribution {
    ErrorDistribution::DiscreteGaussian {
        standard_deviation: decimal(value),
    }
}

fn classical(reduction_model: Option<ReductionModel>) -> AnalysisSettings {
    AnalysisSettings {
        security_model: SecurityModel::Classical,
        cost_model: None,
        shape_model: None,
        reduction_model,
    }
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate is inside the repository")
        .to_path_buf()
}

#[test]
fn exact_values_are_canonicalized_at_the_boundary() {
    assert_eq!(integer("0004294967296").as_str(), "4294967296");
    assert_eq!(decimal("00022.8000").as_str(), "22.8");
    assert_eq!(decimal("-0.000").as_str(), "0");
    assert!(ExactDecimal::new("2.28e1").is_err());
    assert!(PositiveInteger::new("0x100").is_err());
}

#[test]
fn tagged_problem_rejects_fields_from_another_variant() {
    let json = r#"{
        "kind":"lwe",
        "dimension":512,
        "modulus":"2048",
        "samples":{"kind":"unlimited"},
        "secret":{"kind":"uniform_binary"},
        "error":{"kind":"discrete_gaussian","standard_deviation":"3.2"},
        "columns":10
    }"#;
    assert!(serde_json::from_str::<Problem>(json).is_err());
}

#[test]
fn lwe_exposes_fast_and_adaptive_slow_attack_sets() {
    let problem: Problem = serde_json::from_str(
        r#"{
          "kind":"lwe","dimension":512,"modulus":"2048",
          "samples":{"kind":"unlimited"},
          "secret":{"kind":"uniform_binary"},
          "error":{"kind":"discrete_gaussian","standard_deviation":"0.92"}
        }"#,
    )
    .unwrap();
    assert_eq!(
        attacks_for_problem(&problem),
        &[
            Attack::AroraGb,
            Attack::Bkw,
            Attack::Usvp,
            Attack::Bdd,
            Attack::BddHybrid,
            Attack::BddMitmHybrid,
            Attack::Dual,
            Attack::DualHybrid,
        ]
    );
    assert_eq!(
        fast_attacks_for_problem(&problem),
        &[
            Attack::Usvp,
            Attack::Bdd,
            Attack::BddHybrid,
            Attack::BddMitmHybrid,
            Attack::Dual,
            Attack::DualHybrid,
        ]
    );
    assert_eq!(
        slow_attacks_for_problem(&problem),
        &[Attack::AroraGb, Attack::Bkw]
    );
    assert_eq!(
        serde_json::from_str::<Attack>(r#""arora_gb""#).unwrap(),
        Attack::AroraGb
    );
    assert_eq!(
        serde_json::from_str::<Attack>(r#""bkw""#).unwrap(),
        Attack::Bkw
    );
}

#[test]
fn coefficient_embedding_preserves_source_and_derives_checked_lwe() {
    let problem = Problem::Glwe(GlweProblem {
        negacyclic_ring: NegacyclicRing {
            polynomial_degree: 1024,
            ciphertext_modulus: integer("134215681"),
        },
        dimension: 2,
        samples: SampleCount::Finite { count: 3 },
        secret: SecretDistribution::SparseTernary {},
        error: gaussian("3.2"),
    });
    let model = analysis_model_for(
        &problem,
        &classical(Some(ReductionModel::CoefficientEmbeddingV1)),
    )
    .unwrap();
    let AnalysisModel::CoefficientEmbeddingV1 {
        derived_lwe,
        scalar_samples,
        warnings,
        ..
    } = model
    else {
        panic!("expected coefficient embedding")
    };
    assert_eq!(derived_lwe.dimension, 2048);
    assert_eq!(scalar_samples, SampleCount::Finite { count: 3072 });
    assert_eq!(warnings.len(), 2);
}

#[test]
fn ring_problem_requires_explicit_reduction() {
    let problem = Problem::Rlwe(RlweProblem {
        negacyclic_ring: NegacyclicRing {
            polynomial_degree: 1024,
            ciphertext_modulus: integer("2013265921"),
        },
        samples: SampleCount::Unlimited,
        secret: SecretDistribution::UniformTernary,
        error: gaussian("3.19"),
    });
    let error = analysis_model_for(&problem, &classical(None)).unwrap_err();
    assert_eq!(error.path, "analysis.reduction_model");
}

#[test]
fn cache_hash_ignores_field_order_and_tracks_estimator_context() {
    let problem_a: EstimatorProblem = serde_json::from_str(
        r#"{
          "kind":"lwe","dimension":512,"modulus":"002048",
          "samples":{"kind":"unlimited"},
          "secret":{"kind":"uniform_binary"},
          "error":{"kind":"discrete_gaussian","standard_deviation":"00.9200"}
        }"#,
    )
    .unwrap();
    let problem_b: EstimatorProblem = serde_json::from_str(
        r#"{
          "error":{"standard_deviation":"0.92","kind":"discrete_gaussian"},
          "secret":{"kind":"uniform_binary"},"samples":{"kind":"unlimited"},
          "modulus":"2048","dimension":512,"kind":"lwe"
        }"#,
    )
    .unwrap();
    assert_eq!(problem_a, problem_b);

    let context = EstimatorContext {
        estimator_commit: "6019056011d10d7e9c30a0d5da2d2f729fbc2eec".into(),
        sage_version: "10.9".into(),
        adapter_version: "1".into(),
        worker_image: "sha256:worker".into(),
    };
    let analysis = classical(None).resolve();
    let first = AttackCacheIdentity::new(
        problem_a,
        AnalysisModel::DirectLwe { version: 1 },
        analysis.clone(),
        Attack::Usvp,
        context.clone(),
    );
    let second = AttackCacheIdentity::new(
        problem_b.clone(),
        AnalysisModel::DirectLwe { version: 1 },
        analysis.clone(),
        Attack::Usvp,
        context.clone(),
    );
    assert_eq!(first.hash(), second.hash());
    assert_eq!(
        first.hash(),
        "sha256:f914d1d00eba06a6980eecc041174888368cedd334d80fe078a43a66057d7162"
    );

    let changed = AttackCacheIdentity::new(
        problem_b,
        AnalysisModel::DirectLwe { version: 1 },
        analysis,
        Attack::Usvp,
        EstimatorContext {
            estimator_commit: "different".into(),
            ..context
        },
    );
    assert_ne!(first.hash(), changed.hash());
}

#[test]
fn sparse_ternary_rejects_obsolete_fixed_counts() {
    let value = r#"{
      "format":"lattice-security/parameter-set","version":1,
      "id":"bad-set","name":"Bad set","cases":[{
        "id":"case","name":"Case","problem":{
          "kind":"lwe","dimension":8,"modulus":"16",
          "samples":{"kind":"finite","count":8},
          "secret":{"kind":"sparse_ternary","positive_count":2,"negative_count":2},
          "error":{"kind":"discrete_gaussian","standard_deviation":"1"}
        }
      }]
    }"#;
    assert!(serde_json::from_str::<ParameterSetFile>(value).is_err());
}

#[test]
fn lwe_run_requires_explicit_slow_attack_preflight_policy() {
    let parameter_set: ParameterSetFile = serde_json::from_str(
        &fs::read_to_string(
            repository_root().join("fixtures/schema/valid/parameter-set-minimal.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut request = EstimateRequest {
        name: None,
        parameter_set_id: None,
        cases: parameter_set.cases,
        mode: lattice_security::EstimateMode::Normal,
        timeout_seconds: 600,
        slow_attack_policy: None,
    };
    assert_eq!(request.validate().unwrap_err().path, "slow_attack_policy");

    request.slow_attack_policy = Some(SlowAttackPolicy {
        required_security_bits: decimal("128"),
        stop_margin_bits: decimal("16"),
        forced_attacks: Vec::new(),
    });
    request.validate().unwrap();

    request
        .slow_attack_policy
        .as_mut()
        .unwrap()
        .stop_margin_bits = decimal("-1");
    assert_eq!(
        request.validate().unwrap_err().path,
        "slow_attack_policy.stop_margin_bits"
    );
    request
        .slow_attack_policy
        .as_mut()
        .unwrap()
        .stop_margin_bits = decimal("0");
    request.validate().unwrap();

    request.slow_attack_policy.as_mut().unwrap().forced_attacks = vec![Attack::Usvp];
    assert_eq!(
        request.validate().unwrap_err().path,
        "slow_attack_policy.forced_attacks[0]"
    );
    request.slow_attack_policy.as_mut().unwrap().forced_attacks = vec![Attack::Bkw, Attack::Bkw];
    assert_eq!(
        request.validate().unwrap_err().path,
        "slow_attack_policy.forced_attacks[1]"
    );
    request.slow_attack_policy.as_mut().unwrap().forced_attacks =
        vec![Attack::AroraGb, Attack::Bkw];
    request.validate().unwrap();

    request.mode = lattice_security::EstimateMode::Rough;
    request.slow_attack_policy = None;
    request.validate().unwrap();

    let example: EstimateRequest = serde_json::from_str(
        &fs::read_to_string(repository_root().join("fixtures/examples/demo-run.json")).unwrap(),
    )
    .unwrap();
    example.validate().unwrap();
    assert_eq!(
        example.slow_attack_policy.unwrap().required_security_bits,
        decimal("128")
    );
}

#[test]
fn example_parameter_set_and_report_round_trip() {
    let directory = repository_root().join("fixtures/examples");
    let parameter_set: ParameterSetFile = serde_json::from_str(
        &fs::read_to_string(directory.join("demo-scheme.lattice-params.json")).unwrap(),
    )
    .unwrap();
    parameter_set.validate().unwrap();
    assert_eq!(parameter_set.cases.len(), 2);
    let round_trip: ParameterSetFile =
        serde_json::from_str(&serde_json::to_string(&parameter_set).unwrap()).unwrap();
    assert_eq!(parameter_set, round_trip);

    let report: SecurityReportFile = serde_json::from_str(
        &fs::read_to_string(directory.join("demo-scheme.lattice-report.json")).unwrap(),
    )
    .unwrap();
    report.validate().unwrap();
    let round_trip: SecurityReportFile =
        serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
    assert_eq!(report, round_trip);
}

#[test]
fn schema_fixtures_separate_shape_and_semantic_failures() {
    let root = repository_root().join("fixtures/schema");
    let valid: ParameterSetFile = serde_json::from_str(
        &fs::read_to_string(root.join("valid/parameter-set-minimal.json")).unwrap(),
    )
    .unwrap();
    valid.validate().unwrap();

    for name in ["decimal-exponent.json", "cross-variant-field.json"] {
        let source = fs::read_to_string(root.join("invalid").join(name)).unwrap();
        assert!(
            serde_json::from_str::<ParameterSetFile>(&source).is_err(),
            "{name} must fail strict JSON decoding"
        );
    }

    let semantic_cases = [
        ("fixed-weight-overflow.json", "cases[0].problem.secret"),
        (
            "ring-reduction-missing.json",
            "cases[0].analysis.reduction_model",
        ),
    ];
    for (name, expected_path) in semantic_cases {
        let source = fs::read_to_string(root.join("invalid").join(name)).unwrap();
        let parameter_set: ParameterSetFile = serde_json::from_str(&source).unwrap();
        assert_eq!(parameter_set.validate().unwrap_err().path, expected_path);
    }
}

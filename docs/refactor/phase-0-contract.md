# Minimal service contract

Status: **Windows implementation complete; Linux verification pending**

The Rust types in `security-service` are the source of truth for the generated
JSON schemas in `schemas`.

## Product scope

- A parameter set is a named scheme containing 1–500 ordered cases.
- The service can run all cases, selected cases, or a single case.
- Each case stores a typed problem and optional analysis settings.
- Reports embed the complete case snapshot and every per-attack outcome.
- Parameter sets and reports support JSON import/export.
- Successful per-attack results are cached in SQLite and reused automatically.
- The Rust service is the only public HTTP/Web endpoint. The Sage adapter is
  reachable only on the Compose network.

No compatibility with historical profiles, notebook results, Parquet caches,
or legacy report formats is provided. After parameter migration was verified,
the superseded root scripts, notebooks, and `lwe_security` package were
removed; the migrated JSON parameter sets are the maintained source.

## Problems and analysis

The contract supports LWE, RLWE, GLWE, standard NTRU, and SIS. Numeric identity
uses canonical decimal strings; exponents, NaN, Infinity, and expressions are
rejected. Sample counts are explicitly finite or unlimited.

Analysis settings contain only the security model, optional cost/shape model,
and optional RLWE/GLWE reduction model. Classical defaults to `BDGL16`, quantum
to `LaaMosPol14`, and shape to `GSA`. There are no named profiles or attack-set
profiles.

RLWE and GLWE require `coefficient_embedding_v1`. The report records the source
problem, derived LWE instance, sample mapping, model version, and structural
warning. The mapping uses checked arithmetic.

## Fixed attacks

- LWE/RLWE/GLWE fast set: `usvp`, `bdd`, `bdd_hybrid`, `bdd_mitm_hybrid`,
  `dual`, `dual_hybrid`.
- LWE/RLWE/GLWE adaptive slow set: `arora_gb`, `bkw`.
- Standard NTRU: `usvp`, `dsd`, `bdd`, `bdd_hybrid`, `bdd_mitm_hybrid`.
- SIS: `lattice`.

`arora_gb` and `bkw` remain public attacks and use a versioned three-level
applicability decision. Clearly inapplicable inputs produce a
`policy_skipped` outcome. Clearly applicable inputs run in separate estimator
plans. Borderline inputs consult a calibrated conservative approximation; if
it is at least `required_security_bits + stop_margin_bits`, the approximation
is returned and the Sage attack process is never created. Missing or lower
borderline predictions cause the real attack to run until completion or the
overall timeout.

Outcomes include `computed`, `no_finite_estimate`, calibrated `approximate`,
`timeout`, `unsupported`, `failed`, `policy_skipped`, and rough-mode `skipped`.
A complete normal report means every attack in the fixed set has a computed,
no-finite, or reviewed policy-excluded result.
The case security level is the minimum computed security-bit value and records
the corresponding attack.

## Cache identity

The immutable per-attack cache key contains:

- normalized direct estimator problem;
- analysis model and version;
- resolved cost, shape, security, and reduction settings;
- attack;
- estimator commit, Sage version, adapter version, and worker image.

Names, tags, case order, timestamps, and timeout do not participate. Timeouts,
unsupported outcomes, and failures are not successful cache entries.

## Public schemas

- `lattice-security/parameter-set` v1
- `lattice-security/security-report` v1
- multi-case estimate request
- common public error response

The example parameter set and report in `fixtures/examples` exercise multi-case
import/export and complete computed reports. Strict invalid fixtures cover
cross-variant fields, exponents, fixed-weight overflow, and missing ring
reduction.

## Operational defaults

- linux/amd64, Rust 1.97.1, Sage 10.9, fixed estimator commit.
- 8 MiB request limit and at most 500 cases per request.
- Case concurrency two and Sage-process concurrency three, both configurable
  from 1 to 32. Default timeout is 3,600 seconds, maximum 7,200 seconds, and
  cleanup grace is 15 seconds.
- SQLite path `/var/lib/lattice-security/lattice-security.db`.
- No SSE/WebSocket, PostgreSQL, multi-instance, ARM64, external legacy
  converter, or Primus repository changes.

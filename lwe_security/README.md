# lwe_security

Utilities for estimating and caching LWE security levels with the local
`lattice-estimator` checkout.

The package is designed for script/API use. It keeps the new implementation
separate from the legacy `utils.py` flow.

## Public API

Typical imports:

```python
from estimator.estimator import ND
from lwe_security import AttackSet, SecurityModel, check_lwe_security
```

Run a fast classical estimate:

```python
result = check_lwe_security(
    dimension=512,
    modulus=2048,
    secret_distr=ND.SparseBinary(256, 512),
    noise_stddev=0.92,
    security_model=SecurityModel.CLASSICAL,
    attack_set=AttackSet.FAST_SUBSET,
)
```

Arguments after `noise_stddev` are keyword-only, so profile selection must use
`security_model=` and `attack_set=`.

Run the exact classical profile later:

```python
exact = check_lwe_security(
    dimension=512,
    modulus=2048,
    secret_distr=ND.SparseBinary(256, 512),
    noise_stddev=0.92,
    security_model=SecurityModel.CLASSICAL,
    attack_set=AttackSet.EXACT,
)
```

If a compatible fast run already exists, the exact run reuses completed
per-attack rows and computes only missing attacks.

Run the smart-exact classical profile for day-to-day final estimates:

```python
smart = check_lwe_security(
    dimension=512,
    modulus=2048,
    secret_distr=ND.SparseBinary(256, 512),
    noise_stddev=0.92,
    security_model=SecurityModel.CLASSICAL,
    attack_set=AttackSet.SMART_EXACT,
)
```

Smart-exact profiles always keep the standard lattice attack surface enabled and
screen only the expensive special-purpose attacks (`arora-gb` and `bkw`).
Skipped attacks are recorded as audit rows with the smart-screen reason.
Small borderline cases may also run expensive attacks in calibration mode. A
successful calibration result is included in the security minimum; a failed
calibration result is recorded for inspection but does not make the smart-exact
profile incomplete.

Convenience wrappers are also available:

```python
from lwe_security import (
    check_lwe_security_fast,
    check_lwe_security_exact,
    check_lwe_security_smart_exact,
)
```

## Profiles

User-facing profile selection is split into two enum axes:

```python
SecurityModel.CLASSICAL
SecurityModel.QUANTUM

AttackSet.FAST_SUBSET
AttackSet.EXACT
AttackSet.SMART_EXACT
```

Fast subset profiles deny the attack families configured in
`lwe_security.constants.FAST_SUBSET_DENY_LIST`. Exact profiles deny the attack
families configured in `lwe_security.constants.EXACT_DENY_LIST`.

Smart-exact profiles resolve their deny list per parameter set using
`lwe_security.smart_exact`. The core attacks are:

```text
usvp
bdd
bdd_hybrid
bdd_mitm_hybrid
dual
dual_hybrid
```

The smart screen decides whether to run:

```text
arora-gb
bkw
```

The resolved deny list, optional calibration attacks, rough quick bounds, and
decision metadata are included in `profile_json`, so profile-level cache keys
distinguish different smart decisions and smart rule versions. Per-attack reuse
still uses `estimate_context_hash`, so compatible attack rows can be reused
across fast, exact, and smart-exact profiles.

The package still stores a derived versioned `profile_id`, such as
`fast_subset_classical_v3`, in cache rows for auditability and profile-level
cache identity.

The profile id version is controlled by
`lwe_security.constants.PROFILE_ID_VERSION`. Bump it when a profile's meaning
changes and old profile-level cache hits should not be reused.

## Cache

By default, cache files are stored in the current working directory:

```text
security_runs.parquet
security_attack_results.parquet
```

Use `cache_dir` to isolate experiments:

```python
result = check_lwe_security(..., cache_dir="cache/lwe")
```

The run cache key includes the parameter descriptor, profile hash, and
estimator version. Per-attack reuse uses `estimate_context_hash`, which includes
the estimator, cost model, shape model, and explicit `quantum` flag, but not the
profile deny list.

Only successful run summaries are treated as cache hits. Partial or failed runs
remain in the cache for inspection, but a later call may recompute the same
profile.

Use:

```python
check_lwe_security(..., force=True, reuse_attacks=False)
```

to recompute every attack required by the requested profile.

Use:

```python
check_lwe_security(..., force=True, reuse_attacks=True)
```

to create a fresh run row while still reusing compatible per-attack rows.

By default, only successful per-attack rows are reused. If an estimator attack is
known to fail for a parameter set and you want later runs to skip recomputing
that same failed attack, use:

```python
check_lwe_security(..., reuse_failed_attacks=True)
```

Known failures are copied into the new run as `known_error` or
`known_no_finite_rop`. They are still treated as incomplete results, so the
overall estimate remains `partial` or `error` unless every required attack has a
finite result.

## Display

Plain Python formatters are available:

```python
from lwe_security import print_security_result, print_attack_results

print_security_result(result)
print_attack_results(result["run_id"])
```

If `rich` is installed, `print_*` helpers render Rich tables automatically.
Pass `use_rich=False` to force plain-text output.

Attack tables show whether each row was computed in the current run or reused
from a compatible previous run.

## Constants

Shared constants live in `lwe_security/constants.py`.

Common values to adjust:

```python
PROFILE_ID_VERSION
DEFAULT_JOBS
FAST_SUBSET_DENY_LIST
EXACT_DENY_LIST
ESTIMATOR_VERSION
CLASSICAL_COST_MODEL
QUANTUM_COST_MODEL
DEFAULT_SHAPE_MODEL
```

Smart-exact rule thresholds live in `lwe_security/smart_exact.py`.

Modulus constants copied from the legacy `utils.py` are also available there:

```python
from lwe_security import QBabyBear, QGoldilocks, QXX
```

`DEFAULT_JOBS` is currently `1` because the estimator uses multiprocessing and
the cache layer imports Polars. Keeping estimator jobs single-process avoids
fork-related instability in this environment.

## Notes

- Large moduli are stored as decimal strings in Parquet.
- `modulus_bits(q)` returns `ceil(log2(q))`; powers of two return the exponent.
- Cache timestamps use the `Asia/Shanghai` time zone.
- Distribution descriptors distinguish sparse ternary, uniform ternary, binary,
  Gaussian, centered binomial, generic uniform, and unknown distributions.

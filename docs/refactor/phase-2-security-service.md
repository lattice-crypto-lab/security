# Phase 2 security service

Phase 2 adds one Axum binary backed by a dedicated SQLite thread. Async request
handlers send closures over a channel; estimator work never holds a database
transaction. SQLite enables WAL, foreign keys, a five-second busy timeout, and
versioned migrations.

Persisted data is separated into parameter-set versions, batches/jobs,
execution attempts, and an immutable successful attack cache. Cache keys use
the normalized estimator problem, resolved analysis, analysis model, attack,
and exact estimator context. Names, tags, case order, timeout, and slow-attack
policy do not affect the key.

The scheduler has one execution lane, which matches the worker concurrency and
also provides single-flight behavior: overlapping jobs recheck the attack
cache after acquiring the lane. Worker transport failures are retried once.
On restart, unfinished attempts become interrupted; attempts below the retry
limit are queued once more.

For LWE-derived cases, missing fast attacks run as one plan. Before creating
separate `arora_gb` and `bkw` plans, versioned applicability rules classify
each attack as applicable, borderline, or inapplicable. Inapplicable attacks
produce `policy_skipped`; applicable attacks run. Borderline inputs consult the
calibrated model. A prediction at or above
`required_security_bits + stop_margin_bits` skips that worker plan entirely;
a missing or lower prediction causes the real attack to run until completion
or the overall worker timeout.

Cancellation is persisted before the in-flight HTTP request is dropped. Any
completed results remain cached and exportable in a partial report. A policy
preflight produces a calibrated `approximate` outcome in its separate model-keyed
cache and never populates the computed cache.

## Status

- **Windows implementation complete**: contracts and mock integration tests.
- **Linux verification pending**: real Sage results, Docker builds, Compose
  network/volume/health checks, non-root execution, and resource limits.
- **Linux verification complete** is not claimed.

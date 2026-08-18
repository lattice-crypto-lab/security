# Phase 4: calibrated slow-attack approximation

## Scope

Phase 4 adds a conservative empirical fallback for the public LWE attacks
`arora_gb` and `bkw`. It does not remove either attack from the public contract
and does not claim a mathematical proof or a computed estimator result.

The Rust service accepts a prediction only when all of the following match a
reviewed model group:

- estimator commit, Sage version, adapter version, and worker image;
- attack, security/cost/shape models, secret distribution, and sample mode;
- every normalized feature is inside the calibrated domain;
- the nearest training point is within the calibrated distance limit.

The returned bit value is the interpolated prediction minus a safety margin.
The margin is the largest holdout overestimate plus a configured cushion
(2 bits in the v1 plan). Reports retain the model and dataset hashes, training
and holdout counts, holdout error, and margin. Approximate and computed caches
are separate, and the model hash is part of approximation cache identity.

The runtime `stop_margin_bits` is an additional operational margin after this
model safety adjustment. With the Web defaults, an attack is eligible for
early termination after 300 seconds only when its already-conservative estimate
is at least `128 + 16 = 144` bits.

No old database or report migration is provided. For this pre-release phase,
redeploy with a fresh volume when the storage contract changes.

## Linux collection

Real Sage collection must run on the target `linux/amd64` image. Start the
normal stack, then invoke the one-shot Compose profile from the repository
root:

```bash
mkdir -p calibration/output
docker compose up -d estimator-api
docker compose --profile calibration run --rm calibration collect \
  --plan /calibration/plans/slow-attacks-v1.json \
  --output /calibration/output/slow-attacks-v1.jsonl \
  --estimator-url http://estimator-api:8000
```

The checked-in v1 plan contains 896 attack observations. Each observation may
run for up to 3,600 seconds, so collection can take a long time. Re-running the
same command resumes completed observations. Transient collection failures and
timeouts remain eligible for retry; computed and definitively unsupported rows
are skipped.

Do not mix observation files from different estimator provenance. The model
builder rejects a mixed dataset.

## Build and review

Build the candidate artifact with the same one-shot image:

```bash
docker compose --profile calibration run --rm calibration build \
  --input /calibration/output/slow-attacks-v1.jsonl \
  --output /calibration/output/slow-attacks-v1.model.json \
  --model-id slow-attacks-v1 \
  --neighbors 4 \
  --safety-cushion-bits 2
```

Before publishing, review every group's training/holdout count, mean and p95
absolute error, maximum overestimate, domain, and maximum neighbor distance.
Copy an accepted artifact to:

```text
security-service/models/slow-attacks-v1.json
```

Then rebuild `security-service`. Its startup validates both the artifact format
and exact estimator provenance. A missing artifact leaves approximation
disabled; an invalid or mismatched artifact fails closed.

## Runtime policy

- `rough`: run fast attacks, then fill covered slow attacks from the calibrated
  model. Uncovered attacks remain policy-skipped.
- `normal`: prefer computed cache and real estimator results. `arora_gb` and
  `bkw` run as separate plans with separate timers. At its decision time, an
  attack is stopped only when its conservative approximation is at least
  `required_security_bits + stop_margin_bits`. Approximation may also replace a
  slow timeout or unsupported worker outcome when it is inside the calibrated
  domain.
- Real computed outcomes always take precedence. Approximation never enters the
  immutable computed cache and never makes a report `complete=true`.

## Verification state

- Windows implementation complete: contract, loader, domain checks, predictor,
  separate cache, scheduler policy, UI provenance, collector/builder, and mock
  tests.
- Linux calibration pending: collect the fixed grid, review holdout metrics,
  commit the accepted model artifact, and run real Sage golden tests.
- Linux verification pending: image build, Compose network/volume/healthcheck,
  non-root/resource limits, cancellation cleanup, and browser smoke test.

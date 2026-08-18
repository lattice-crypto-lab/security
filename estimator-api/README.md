# estimator-api

Internal, stateless FastAPI adapter for the fixed SageMath and
lattice-estimator environment. It is not a public service and must not publish
a host port in the final Compose configuration.

## Endpoints

- `GET /healthz` performs no estimate and reports API liveness.
- `GET /v1/metadata` reports exact runtime provenance, supported problem
  attacks/distributions, dependencies, and the adaptive slow attacks.
- `POST /v1/estimate` validates one direct LWE/NTRU/SIS problem plus a target
  attack list, expands required support attacks, and runs the plan in one Sage
  process group.

LWE runs `usvp`, `bdd`, `bdd_hybrid`, `bdd_mitm_hybrid`, `dual`, and
`dual_hybrid`. `arora_gb` and `bkw` remain callable so the Rust service can run
and cancel them under its configured time/security policy.

The request limit is 8 MiB. The default hard timeout is 3,600 seconds, the
maximum is 7,200 seconds, cleanup grace is 15 seconds, and concurrency is one.
Timeout, HTTP disconnect, caller cancellation, and server task cancellation
all trigger process-group TERM, bounded grace, KILL, and wait.

## Locked environment

- SageMath: `10.9`
- Docker Hub OCI index:
  `sha256:e068670ae5863b54b2550e72437ec637b0283acb0dc712c8584c124dbf44e667`
- linux/amd64 manifest:
  `sha256:2401ffa8e9fc85c7ea17d3649bde5958b4dbf0858b3e504098c4102720151711`
- lattice-estimator:
  `6019056011d10d7e9c30a0d5da2d2f729fbc2eec`

`uv.lock` fixes development and production dependencies. `requirements.lock`
is the hash-locked, third-party-only export installed by the Sage image.

## Phase 4 calibration tool

The image includes `/app/estimator-api/tools/phase4_calibration.py`. It collects real
`arora_gb`/`bkw` observations through this API and builds the versioned
conservative model consumed by `security-service`. The normal two-service stack
does not run the tool; `compose.calibration.yaml` provides a separate one-shot
entry point. Collection is resumable and retries transient collector failures.
See `docs/refactor/phase-4-approximation.md` for the reviewed workflow.

## Windows mock verification

```powershell
uv sync --frozen --all-groups
uv run --frozen ruff check src tests
uv run --frozen ruff format --check src tests
uv run --frozen pytest
```

These checks use the mock child process and do not constitute Sage or Docker
verification. Real estimator golden results and POSIX descendant cleanup remain
Linux verification tasks.

# estimator-api

A private, stateless FastAPI wrapper around SageMath and the pinned
`lattice-estimator` submodule.

It has only three endpoints:

- `GET /healthz`
- `GET /v1/metadata`
- `POST /v1/estimate`

One estimate request contains one direct LWE, NTRU, or SIS problem and an
explicit attack list. The adapter converts distributions and models to
`lattice-estimator`, denies every unrequested attack, and returns normalized
security bits and metrics. Attack grouping, caching, applicability policy, and
multi-case scheduling belong to Rust.

Every call launches one Sage subprocess in its own process group. Timeout,
disconnect, cancellation, and task failure trigger TERM, a bounded grace
period, KILL if necessary, and process reaping. Concurrent Sage subprocesses
default to three (`ESTIMATOR_CONCURRENCY`, range 1–32).

## Pinned runtime

- SageMath `10.9`
- linux/amd64 image digest
  `sha256:2401ffa8e9fc85c7ea17d3649bde5958b4dbf0858b3e504098c4102720151711`
- lattice-estimator commit
  `6019056011d10d7e9c30a0d5da2d2f729fbc2eec`

`requirements.lock` is installed by the image; `uv.lock` also contains the
development tools.

```powershell
uv sync --frozen --all-groups
uv run --frozen pytest
uv run --frozen ruff check src tests
uv run --frozen ruff format --check src tests
```

These Windows checks use a mock child process and do not claim real Sage or
container verification.

# Phase 1 estimator API

Phase 1 provides the internal stateless boundary around fixed SageMath and
lattice-estimator versions. It exposes only `GET /healthz`, `GET /v1/metadata`,
and `POST /v1/estimate` on the Compose network.

An estimate request contains one direct LWE, standard NTRU, or SIS problem,
resolved cost/shape models, a target attack list, and a timeout. The adapter
validates the list, expands estimator dependencies, and reports target versus
support results. This lets the Rust scheduler run/cache the fast set normally
and control `arora_gb`/`bkw` as separate cancellable work.

Each requested execution plan runs in one killable Sage process group. Timeout, HTTP
disconnect, caller cancellation, and exceptional shutdown use TERM, a bounded
15-second grace period, KILL when needed, and process reaping. Concurrency is
fixed at one and request bodies are limited to 8 MiB.

Results contain one typed outcome per fixed attack and exact security bits as
canonical decimal strings. Sage output is normalized at the Python boundary;
failure audit text is bounded. The Rust service later stores only successful
computed outcomes in its per-attack cache.

Supported distributions are uniform binary/ternary, sparse ternary, fixed-weight
binary/ternary, discrete Gaussian, centered binomial, and bounded uniform
integers. Inputs that cannot be represented exactly by the pinned estimator are
rejected by the strict request model rather than approximated.

## Fixed environment

- SageMath `10.9`
- Docker Hub OCI index
  `sha256:e068670ae5863b54b2550e72437ec637b0283acb0dc712c8584c124dbf44e667`
- linux/amd64 manifest
  `sha256:2401ffa8e9fc85c7ea17d3649bde5958b4dbf0858b3e504098c4102720151711`
- lattice-estimator
  `6019056011d10d7e9c30a0d5da2d2f729fbc2eec`

`uv.lock` pins development and production dependencies. `requirements.lock` is
the hash-locked production export installed in the container. The complete
upstream estimator source and LGPLv3+ notices remain present.

## Verification

- **Windows implementation complete**: strict models, attack-plan selection,
  distribution conversion, worker protocol, timeout/cancellation, request
  limit, formatting, lint, and mock tests pass.
- **Linux verification pending**: real Sage golden results, image build,
  POSIX descendant cleanup, non-root/health checks, and resource limits have
  not run on this machine.
- **Linux verification complete** is not claimed.

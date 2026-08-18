# lattice-security

Web UI and API for estimating the security of LWE, RLWE, GLWE, NTRU, and SIS
parameter sets with the pinned
[`lattice-estimator`](https://github.com/malb/lattice-estimator).

It supports multi-case schemes, JSON import/export, asynchronous runs, and a
persistent per-attack cache. The browser only connects to the Rust service;
SageMath remains inside the Compose network.

## Quick start

Requirements: Docker with Compose and an x86-64 Linux host.

```bash
docker compose pull
docker compose up -d
```

Open <http://127.0.0.1:8080>. Runtime data is stored in the named Docker volume
`lattice-security-data` and survives container replacement.

If the GHCR packages are private, log in before pulling:

```bash
echo "$GHCR_TOKEN" | docker login ghcr.io --username YOUR_GITHUB_NAME --password-stdin
```

The token needs read access to the two container packages.

## Configuration

Create a `.env` file next to `compose.yaml` only for values you want to change:

```dotenv
# Allow access from other machines. Keep 127.0.0.1 for local-only access.
LATTICE_SECURITY_HOST=0.0.0.0

# Strongly recommended when exposing the service to a LAN.
LATTICE_SECURITY_API_TOKEN=replace-with-a-random-token

# Optional reproducible image versions; the default is latest.
SECURITY_SERVICE_VERSION=0.1.2
ESTIMATOR_API_VERSION=0.1.1

# Optional bounded parallelism.
LATTICE_SECURITY_CASE_CONCURRENCY=2
ESTIMATOR_CONCURRENCY=3
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `LATTICE_SECURITY_HOST` | `127.0.0.1` | Host address on which the Web service is published |
| `LATTICE_SECURITY_PORT` | `8080` | Published host port |
| `LATTICE_SECURITY_API_TOKEN` | empty | Shared Web login and Bearer API token |
| `SECURITY_SERVICE_VERSION` | `latest` | Rust service image tag |
| `ESTIMATOR_API_VERSION` | `latest` | Sage adapter image tag |
| `LATTICE_SECURITY_CASE_CONCURRENCY` | `2` | Cases processed concurrently |
| `ESTIMATOR_CONCURRENCY` | `3` | Maximum concurrent Sage processes |

Apply configuration changes with:

```bash
docker compose up -d --pull always
```

## What it provides

- Direct `rough` or `normal` security estimation for one or more cases.
- A parameter-set library with editing, import, export, and selected-case runs.
- Persistent batch history and immutable computed attack caching.
- Bounded parallel execution across cases and independent attack families.
- Versioned handling of the expensive `arora_gb` and `bkw` attacks.
- Explicit RLWE/GLWE coefficient-embedding reports instead of silent reduction.

`rough` runs the fast attack set. `normal` additionally classifies each slow
attack as applicable, borderline, or irrelevant. Applicable attacks run in
Sage, irrelevant attacks are recorded as policy-skipped, and borderline
attacks may use a reviewed conservative calibration model when available.

## Architecture

- `security-service`: public Rust Web/API service, scheduler, SQLite database,
  reports, and caches.
- `estimator-api`: private Python/Sage adapter around the pinned `estimator/`
  submodule.

Only `security-service` publishes a host port. Parameters and reports use the
schemas in [`schemas/`](schemas/), and maintained example schemes live in
[`parameter-sets/`](parameter-sets/).

## Development

Initialize the estimator submodule and build both images locally:

```bash
git submodule update --init --recursive
docker compose -f compose.yaml -f compose.build.yaml up --build
```

Run the local checks:

```powershell
cargo test --locked --manifest-path security-service/Cargo.toml
cargo clippy --locked --manifest-path security-service/Cargo.toml --all-targets -- -D warnings

cd estimator-api
uv sync --frozen --all-groups
uv run --frozen pytest
uv run --frozen ruff check src tests tools
```

## Documentation

- [`security-service/README.md`](security-service/README.md): API, Web UI, and
  runtime behavior.
- [`estimator-api/README.md`](estimator-api/README.md): Sage adapter contract
  and locked environment.
- [`docs/refactor/phase-4-approximation.md`](docs/refactor/phase-4-approximation.md):
  slow-attack calibration and review workflow.
- [`fixtures/README.md`](fixtures/README.md): purpose and maintenance rules for
  test fixtures.

## Status

The Rust service and mock estimator integration pass on Windows. Real Sage
calibration, image verification, and browser smoke tests on Linux remain
pending; the repository does not claim those checks are complete.

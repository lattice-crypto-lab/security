# lattice-security

Security estimation for LWE, RLWE, GLWE, NTRU, and SIS parameters using a
pinned [lattice-estimator](https://github.com/malb/lattice-estimator).

The browser talks only to the Rust service. SageMath and the Python adapter
remain private inside the Compose network.

## Run

On an x86-64 Linux host with Docker Compose:

```bash
docker compose pull
docker compose up -d
```

Open <http://127.0.0.1:8080>. To expose it on a trusted LAN, create `.env`:

```dotenv
LATTICE_SECURITY_HOST=0.0.0.0
LATTICE_SECURITY_API_TOKEN=replace-with-a-random-token
```

Images default to `latest`. Pin either service independently when needed:

```dotenv
SECURITY_SERVICE_VERSION=0.2.0
ESTIMATOR_API_VERSION=0.2.0
```

Data is stored in the `lattice-security-data` volume. If the GHCR packages are
private, run `docker login ghcr.io` with a token that can read both packages.

## How it works

- `security-service` is the public API, Svelte Web UI, scheduler, SQLite state,
  history, and per-attack cache.
- `estimator-api` is a small internal FastAPI boundary that validates one
  direct problem, launches a killable Sage subprocess, calls the pinned
  estimator, and normalizes its result.
- Fast LWE work runs as a primal/BDD group and a dual group. `arora_gb` and
  `bkw` are first classified by deterministic applicability rules. After the
  fast result, a slow attack is skipped when the lowest fast estimate already
  reaches `required_security_bits + stop_margin_bits`; otherwise it runs in
  its own Sage process.

Parameter sets and reports are the two durable exchange formats. Their JSON
Schemas are committed in [`schemas/`](schemas/). Maintained examples are in
[`parameter-sets/`](parameter-sets/), and [`fixtures/README.md`](fixtures/README.md)
explains the small test fixtures.

## Development

```bash
git submodule update --init --recursive

cargo test --locked --manifest-path security-service/Cargo.toml --all-targets
cargo clippy --locked --manifest-path security-service/Cargo.toml --all-targets -- -D warnings

cd web
npm ci
npm run check
npm run build

cd ../estimator-api
uv sync --frozen --all-groups
uv run --frozen pytest
uv run --frozen ruff check src tests
```

The Windows test suite uses a mock estimator. Real Sage, image, Compose, and
browser verification for each release still belongs in Linux CI or deployment
testing.

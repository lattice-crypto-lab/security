# lattice-security

Local Web service for evaluating lattice parameter sets with the pinned
[`lattice-estimator`](https://github.com/malb/lattice-estimator).

The target deployment has two containers:

- `security-service`: the only public service. It owns the public API, JSON
  import/export, SQLite state, per-attack cache, run scheduling, and Web UI.
- `estimator-api`: an internal FastAPI/Sage adapter. It accepts one normalized
  problem, runs the fixed estimator attack set, and returns security bits.

A parameter set represents one scheme and contains one or more independently
runnable cases. Cases can be evaluated together, selected, or one at a time.
Computed attack results are cached by normalized parameters, analysis model,
attack, and exact estimator environment.

The Web UI also has a direct security-estimation form for entering one or more
LWE, RLWE, GLWE, NTRU, or SIS cases without first creating an import file.
`rough` runs only the fast attack set; `normal` additionally runs adaptive
`arora_gb` and `bkw`. Both modes use the same per-attack cache.

For LWE-derived problems the service exposes all eight estimator attacks. Six
fast attacks run normally. `arora_gb` and `bkw` are adaptive: after a configured
decision time, the service cancels unfinished slow work when the minimum fast
estimate is at or above the configured high-security threshold; otherwise it
continues waiting up to the run timeout.

The original notebooks and Python utilities remain in the repository as
research archives. The new service does not preserve their profiles, caches,
or historical result formats.

Current status:

- Contract, estimator adapter, Rust service, and phase 3 Web UI pass Windows
  mock and browser tests.
- Linux Sage/Docker verification pending.

Run the Rust checks on Windows with:

```powershell
cargo test --locked --manifest-path security-service/Cargo.toml
cargo clippy --locked --manifest-path security-service/Cargo.toml --all-targets -- -D warnings
```

Release tags compare image inputs with the previous release tag and publish
only changed `linux/amd64` images to GHCR. The two image versions are therefore
independent. Stable releases also update each image's `latest` alias; an
unchanged image is retagged without being rebuilt. Pre-release tags do not move
`latest`.

Compose uses `latest` by default. For a reproducible Debian deployment, pin
exact versions with:

```bash
export SECURITY_SERVICE_VERSION=0.1.1
export ESTIMATOR_API_VERSION=0.1.0
docker compose pull
docker compose up -d
```

For a local source build, initialize the pinned estimator submodule and run:

```bash
git submodule update --init --recursive
docker compose -f compose.yaml -f compose.build.yaml up --build
```

Compose publishes only `127.0.0.1:8080`; `estimator-api` has no host port.

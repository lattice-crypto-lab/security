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
`rough` runs the fast attack set and, when a reviewed phase 4 model covers the
input, adds conservative estimates for `arora_gb` and `bkw`. `normal`
additionally runs those attacks and uses the same approximation only after the
adaptive cutoff or timeout. Computed and approximate results use separate
per-attack caches.

For LWE-derived problems the service exposes all eight estimator attacks. Six
fast attacks run normally. `arora_gb` and `bkw` then run in separate estimator
plans with separate decision timers (300 seconds by default). At a decision
time, the service cancels only that unfinished attack and only when its
calibrated conservative estimate is at least the requested security level plus
the stop margin (16 bits by default). Missing, out-of-domain, or insufficient
approximations never trigger early termination. A slow estimate always
identifies its dataset, estimator environment, holdout error, and safety margin.

The original notebooks and Python utilities remain in the repository as
research archives. The new service does not preserve their profiles, caches,
or historical result formats.

Current status:

- Contract, estimator adapter, Rust service, phase 3 Web UI, and phase 4 model
  pipeline pass Windows mock tests.
- Phase 4 Linux Sage observations, model review, and Docker verification are
  pending. Until a reviewed `security-service/models/slow-attacks-v1.json`
  exists, approximation is intentionally disabled.

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
The optional `calibration` Compose profile is a one-shot tool, not a third
production service. See `docs/refactor/phase-4-approximation.md` for collection
and model-build commands.

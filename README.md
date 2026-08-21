# lattice-security (archived)

> [!WARNING]
> This repository is no longer maintained. It does not run CI, publish
> releases, or receive fixes, including security fixes.

The project has been split into two independently maintained repositories:

- [`haofeiliang/lattice-estimator-api`](https://github.com/haofeiliang/lattice-estimator-api):
  the SageMath and lattice-estimator HTTP API.
- [`haofeiliang/lattice-estimator-web`](https://github.com/haofeiliang/lattice-estimator-web):
  the Rust service, Svelte Web UI, scheduler, SQLite state, schemas, examples,
  Compose configuration, and deployment documentation.

Use the new repositories for all development, issues, pull requests, releases,
and container images. The historical `estimator-api` and `security-service`
images are frozen and must not be treated as supported releases.

## Migration notes

The new projects intentionally do not preserve the old database, volume paths,
environment-variable names, or container-image names. Do not mount an old
SQLite database into `lattice-estimator-web`.

To retain business data:

1. Export parameter sets or security reports as JSON with the old service.
2. Use `lattice-estimator-migrate` from `lattice-estimator-web` to convert a
   v1 file to the maintained v2 format.
3. Import the converted v2 JSON into the new Web service.

The converter writes to standard output and does not overwrite the input:

```bash
cargo run --locked --manifest-path backend/Cargo.toml \
  --bin lattice-estimator-migrate -- old.json > migrated.json
```

See the two maintained repositories for current installation, configuration,
file-format, and release instructions. This repository remains available only
as historical source and migration reference.

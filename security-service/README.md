# security-service

The single public service. Its source is intentionally divided into:

- `core`: parameter/report types, validation, canonical identities, reductions,
  and slow-attack applicability rules;
- `application`: concrete use-cases hiding SQLite and scheduler details;
- `api` and `web`: HTTP transport and the compiled Svelte application;
- `lattice-security-cli`: a thin HTTP client for automation.

No generic repository interfaces are used. Jobs and execution attempts are
internal persistence details; public clients work with batches.

## API

- `GET /healthz`, `GET /v1/metadata`
- `POST /v1/estimates`
- `GET /v1/batches`
- `GET|DELETE /v1/batches/{id}`
- `POST /v1/batches/{id}/cancel|rerun`
- `GET /v1/batches/{id}/export`
- `GET /v1/parameter-sets`
- `POST /v1/parameter-sets/import?conflict=reject|replace`
- `GET|DELETE /v1/parameter-sets/{id}`

`reject` leaves an existing parameter-set ID unchanged. `replace` creates a new
current version; historical batches and reports keep their embedded snapshots.

## CLI

The image contains `lattice-security-cli`. Set `LATTICE_SECURITY_URL` and, when
required, `LATTICE_SECURITY_API_TOKEN`, then run `lattice-security-cli` to see
the compact command list. It supports estimates, batches, reports, and
parameter-set import/export operations through the same API as the Web UI.

## Configuration

| Variable | Default |
| --- | --- |
| `LATTICE_SECURITY_BIND` | `127.0.0.1:8080` |
| `LATTICE_SECURITY_DATABASE` | `/var/lib/lattice-security/lattice-security.db` |
| `LATTICE_SECURITY_WEB_DIR` | `web/dist` |
| `ESTIMATOR_API_URL` | `http://estimator-api:8000/` |
| `LATTICE_SECURITY_API_TOKEN` | empty |
| `LATTICE_SECURITY_CASE_CONCURRENCY` | `2` |
| `LATTICE_SECURITY_ESTIMATOR_CONCURRENCY` | `3` |

Identical submissions create independent history records, while immutable
per-attack cache entries and scheduler single-flight prevent duplicate Sage
work. Finished history can be deleted without evicting that cache.

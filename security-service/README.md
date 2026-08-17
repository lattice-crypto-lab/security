# security-service

The Rust service is the only public lattice-security endpoint. It validates
multi-case requests, stores state in SQLite, caches successful results per
attack, and calls the internal estimator adapter.

## Configuration

- `LATTICE_SECURITY_BIND` defaults to `127.0.0.1:8080`.
- `LATTICE_SECURITY_DATABASE` defaults to
  `/var/lib/lattice-security/lattice-security.db`.
- `ESTIMATOR_API_URL` defaults to `http://estimator-api:8000/`.
- `LATTICE_SECURITY_API_TOKEN`, when non-empty, requires
  `Authorization: Bearer <token>` on every endpoint.

## Public endpoints

- `GET /healthz`
- `GET /v1/metadata`
- `POST /v1/estimates`
- `POST /v1/sweeps`
- `GET /v1/batches/{batch_id}` with ETag/`If-None-Match`
- `POST /v1/batches/{batch_id}/cancel`
- `POST /v1/batches/{batch_id}/rerun`
- `GET /v1/batches/{batch_id}/export`
- `GET /v1/results/{batch_id}`
- `GET /v1/jobs/{job_id}`
- `POST /v1/parameter-sets/import?conflict=reject|replace`
- `GET /v1/parameter-sets/{id}/export`

## Web UI

`GET /` serves the Askama/HTMX workbench. It supports parameter-set import,
case selection, batch filtering/sorting, attack details, polling, bulk
cancel/rerun/export, and one-axis sweep creation. The JSON sweep API supports
up to four Cartesian axes and 10,000 generated cases.

HTMX 2.0.10 is version-pinned with SRI. The UI is server-rendered; imported
sets and active batches are reconstructed from SQLite after reload or
disconnect. When an API token is configured, `/login` exchanges it for an
HttpOnly, SameSite=Strict cookie used by the same authentication middleware as
the JSON API.

An estimate returns `202` when work was queued and `200` when every attack was
already cached. Batch snapshots contain a monotonic revision, update time,
polling hint, job IDs, and the report once available.

The scheduler runs the six fast LWE attacks before the separate slow plan. If
all fast attacks computed and their minimum security estimate reaches the
request threshold, an unfinished `arora_gb`/`bkw` plan is disconnected after
the configured decision time. The Python adapter then terminates and reaps the
Sage process group. Policy-skipped results are not cached.

## Verification status

Windows mock integration covers caching, overlapping requests, ETag, adaptive
cutoff, cancellation, transactional parameter-set import, UI rendering,
selected-case execution, Cartesian sweep expansion, and pending queue staging.
An in-app browser smoke test covers the desktop workbench, HTMX batch detail and
filtering, and the 390-pixel responsive breakpoint. Real Sage, container
health/resource behavior, Compose networking, and containerized browser smoke
remain Linux verification pending.

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
- `LATTICE_SECURITY_APPROXIMATION_MODEL` optionally points to a reviewed
  `lattice-security/slow-attack-model` v1 JSON artifact. A missing path disables
  approximation; an invalid or provenance-mismatched artifact prevents startup.
- `LATTICE_SECURITY_CASE_CONCURRENCY` defaults to `2` concurrent cases.
- `LATTICE_SECURITY_ESTIMATOR_CONCURRENCY` defaults to `3` concurrent estimator
  plans and should match the adapter's `ESTIMATOR_CONCURRENCY`.

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

`GET /` serves the Askama/HTMX workbench. Four tabs separate direct security
estimation, the parameter-set library, run batches, and sweeps. The run view
uses a master-detail layout with the batch list on the left and the selected
report on the right. It supports parameter-set import/deletion, case selection,
direct multi-case parameter entry with save/save-and-run actions, batch
filtering/sorting, readable parameter snapshots next to their security bits,
attack details, polling, bulk cancel/rerun/export, and one-axis sweep creation. The JSON sweep
API supports up to four Cartesian axes and 10,000 generated cases.

Finished run batches can also be deleted individually or in bulk. Active
batches must be cancelled first. Deleting run history removes its jobs,
reports, and attempt audit records while retaining computed and approximation
caches.

The import form explains both conflict policies inline. `reject` leaves the
existing parameter set unchanged when its external ID already exists;
`replace` atomically creates a new current version. Deleting a parameter set
removes all of its library versions, but intentionally keeps historical batch
requests, reports, and attack-cache entries because those records contain their
own immutable case snapshots.

The direct form has two execution modes. `rough` runs the fast attack set and
uses a calibrated conservative approximation for borderline `arora_gb` and
`bkw` inputs when the model covers them. `normal` first applies versioned
applicability rules: clearly irrelevant attacks become `policy_skipped`,
borderline inputs consult the calibrated model, and clearly applicable inputs
run the real attack. A later normal run reuses fast results produced by a rough
run. Submitting identical work creates separate batch records, while
completed-cache lookup and scheduler single-flight prevent duplicate estimator
execution.

Independent LWE work is split into `usvp`, the BDD dependency family, the dual
family, `arora_gb`, and `bkw` plans. Cases and plans run concurrently under
separate bounds; lattice-estimator itself stays at `jobs=1` so parallelism has
one owner and cannot multiply inside each Sage process.

HTMX 2.0.10 is version-pinned with SRI. The UI is server-rendered; imported
sets and active batches are reconstructed from SQLite after reload or
disconnect. When an API token is configured, `/login` exchanges it for an
HttpOnly, SameSite=Strict cookie used by the same authentication middleware as
the JSON API.

An estimate returns `202` when work was queued and `200` when every attack was
already cached. Batch snapshots contain a monotonic revision, update time,
polling hint, job IDs, and the report once available.

The normal-mode form explains the three-level slow-attack rule inline. The
scheduler runs the six fast LWE attacks first, then classifies `arora_gb` and
`bkw` individually. An inapplicable attack receives a versioned
`policy_skipped` outcome. A borderline attack consults the model; a calibrated
conservative estimate reaching `required_security_bits + stop_margin_bits`
skips that estimator plan before any Sage process is created. Applicable
attacks and borderline inputs with a missing or lower estimate run until a
result or the overall timeout. The Python adapter
terminates and reaps a timed-out Sage process group. The Web default is a
16-bit preflight margin. Computed and
approximate caches are separate. Approximate
cache identity includes the model hash, so replacing the model cannot reuse
stale estimates. The UI labels approximate outcomes and exposes dataset,
estimator provenance, holdout error, and the applied safety margin.

## Verification status

Windows mock integration covers caching, overlapping requests, ETag, calibrated
preflight, cancellation, transactional parameter-set import/editing, UI rendering,
selected-case execution, Cartesian sweep expansion, and pending queue staging.
It also covers calibrated approximation, provenance matching, domain refusal,
and model-versioned caching. An in-app browser smoke test covers the desktop
workbench, HTMX batch detail and filtering, and the 390-pixel responsive
breakpoint. Real Sage calibration, model review, container health/resource
behavior, Compose networking, and containerized browser smoke remain Linux
verification pending.

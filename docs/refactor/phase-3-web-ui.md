# Phase 3 Web UI and sweeps

Phase 3 adds a server-rendered Askama workbench at `/` with HTMX 2.0.10 for
incremental requests and polling. No frontend build tool or Node runtime is
required. The page reloads parameter sets and recent batches from SQLite, so
browser reload and disconnect recovery do not depend on client-side state.

The workbench supports:

- separate tabs for direct estimates, the parameter-set library, run batches,
  and parameter sweeps;
- direct entry of one or more LWE, RLWE, GLWE, NTRU, or SIS cases in a single
  batch, with `rough` and `normal` execution modes; the same form can run
  immediately, save the cases as a named parameter set, or save and run;
- parameter-set JSON import with explained reject/replace behavior, optional
  immediate run, and confirmed deletion from the library;
- selecting one, several, or all cases in a parameter set;
- batch ID/state filters and update/security sorting;
- a desktop master-detail run layout with the batch list on the left and the
  selected batch report on the right, collapsing to one column on small screens;
- two-second active batch polling and five-second table reconciliation;
- readable case parameter snapshots in both the batch list and detail view,
  followed by per-attack results, cache markers, and fast-estimate markers;
- bulk cancel, rerun, report-bundle export, and terminal-batch deletion;
- one-axis sweep forms for dimension, modulus, Gaussian error standard
  deviation, and finite sample count.

`rough` executes only the fast attack set. `normal` applies the versioned
three-level applicability rules to `arora_gb` and `bkw`: irrelevant attacks are
recorded as policy-skipped, borderline attacks first consult a reviewed
calibration model, and clearly applicable attacks run in Sage. If the
borderline estimate is missing or below the configured stop threshold, the real
attack also runs. Both modes share the computed per-attack cache, and concurrent
identical attack keys are joined through scheduler single-flight even though
each submission keeps its own batch identity.

The UI explains that `reject` aborts an import when the same parameter-set ID
already exists, while `replace` creates a new current version without mutating
historical reports. Deletion removes every stored library version of that
parameter-set ID. Historical batch requests, reports, and attack-cache entries
remain available because they are independent snapshots rather than links to
the mutable library head.

Run history can be deleted individually or in bulk after a batch reaches a
terminal state. Deletion removes the batch, its jobs, reports, and execution
attempt audit records. Running/queued batches must be cancelled first. Computed
and approximation caches are intentionally retained, so deleting history does
not force identical estimator work to run again.

The public `POST /v1/sweeps` contract supports up to four Cartesian axes and
10,000 generated cases. Generated cases are split into batches of 500. At most
2,000 jobs are actively queued/running; overflow jobs are persisted as
`pending` and promoted as execution slots become available. This lets a full
10,000-case sweep survive service restarts without exceeding the active queue
limit.

When `LATTICE_SECURITY_API_TOKEN` is set, JSON clients continue to use Bearer
authentication. The login page stores the same token in an HttpOnly,
SameSite=Strict cookie, and both mechanisms are checked by the common
middleware.

## Status

- **Windows implementation complete**: templates, UI routes, sweep expansion,
  pending queue staging, mock integration tests, and local browser smoke at
  desktop and 390-pixel viewport sizes.
- **Linux verification pending**: real Sage, Docker/Compose, and container
  browser smoke tests.
- **Linux verification complete** is not claimed.

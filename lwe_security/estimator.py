from __future__ import annotations

from dataclasses import replace
import json
import math
import time
from pathlib import Path
from typing import Any, cast

import polars as pl
from sage.all import log, oo

from estimator.estimator import LWE, ND, RC
from .attacks import (
    deny_list_for_only_attacks as _deny_list_for_only_attacks,
    estimator_support_attacks as _estimator_support_attacks,
    required_attacks_for_profile as _required_attacks_for_profile,
)
from .cache import (
    append_attack_results,
    append_run,
    build_cache_key,
    build_estimate_context_hash,
    current_timestamp,
    find_cached_run,
    make_run_id,
    modulus_bits,
    samples_m_to_string,
    scan_attack_results,
)
from .common import canonical_json, safe_float, safe_int, value_string
from .constants import (
    ESTIMATOR_VERSION,
    LWE_ESTIMATOR_NAME,
    LWE_PROBLEM_TYPE,
    SHAPE_MODEL_TOKENS,
)
from .distributions import distribution_descriptor
from .profiles import (
    DEFAULT_ATTACK_SET,
    DEFAULT_SECURITY_MODEL,
    AttackSet,
    EstimationProfile,
    SecurityModel,
    get_profile,
)
from .smart_exact import (
    SmartAttackDecision,
    SmartAttackSelection,
    choose_smart_exact_attacks,
)
from .types import SecurityResult


DEFAULT_FAST_ATTACK_SET = AttackSet.FAST_SUBSET
DEFAULT_EXACT_ATTACK_SET = AttackSet.EXACT
DEFAULT_SMART_EXACT_ATTACK_SET = AttackSet.SMART_EXACT


def _cost_model(name: str) -> Any:
    """Return the estimator reduction cost model named by a profile."""
    try:
        return getattr(RC, name)
    except AttributeError as err:
        raise KeyError(f"Unknown reduction cost model {name!r}") from err


def _shape_model(name: str) -> str:
    """Return the estimator basis-shape model token named by a profile."""
    try:
        return SHAPE_MODEL_TOKENS[name]
    except KeyError as err:
        known = ", ".join(sorted(SHAPE_MODEL_TOKENS))
        raise KeyError(
            f"Unknown reduction shape model {name!r}. Known models: {known}"
        ) from err


def _lwe_sample_count(samples_m: Any) -> Any:
    """Convert public sample-count input into the estimator's m value."""
    if samples_m is None:
        return oo
    if str(samples_m) in {"Infinity", "+Infinity"}:
        return oo
    try:
        if float(samples_m) == float("inf"):
            return oo
    except (TypeError, ValueError, OverflowError):
        pass
    return int(samples_m)


def _log2_rop(rop: Any) -> float | None:
    """Return log2(rop) for finite positive estimator costs."""
    if rop is None or rop == oo:
        return None
    try:
        if rop <= 0:
            return None
    except TypeError:
        pass
    try:
        result = float(log(rop, 2))
    except (TypeError, ValueError, OverflowError):
        try:
            result = math.log2(float(rop))
        except (TypeError, ValueError, OverflowError):
            return None
    return result if math.isfinite(result) else None


def _build_lwe_parameters(
    *,
    dimension: int,
    modulus: int,
    secret_distr: Any,
    noise_stddev: float,
    samples_m: Any,
) -> Any:
    """Build an estimator LWE.Parameters object from public API inputs."""
    m_value = _lwe_sample_count(samples_m)
    return LWE.Parameters(
        n=dimension,
        q=modulus,
        Xs=secret_distr,
        Xe=ND.DiscreteGaussian(noise_stddev),
        m=m_value,
    )


def _run_estimator(
    params: Any,
    profile: EstimationProfile,
    only_attacks: set[str] | None = None,
) -> dict[str, Any]:
    """Run the estimator according to a profile and return raw attack results."""
    if profile.estimator == LWE_ESTIMATOR_NAME:
        deny_list = _deny_list_for_only_attacks(only_attacks)
        return LWE.estimate(
            params,
            red_cost_model=_cost_model(profile.cost_model),
            red_shape_model=_shape_model(profile.shape_model),
            deny_list=profile.deny_list if deny_list is None else deny_list,
            jobs=profile.jobs,
            quiet=True,
        )
    raise KeyError(f"Unknown estimator function {profile.estimator!r}")


def _resolved_profile_for_params(
    profile: EstimationProfile,
    params: Any,
) -> tuple[EstimationProfile, SmartAttackSelection | None]:
    """Return the parameter-resolved profile and smart selection metadata."""
    if profile.attack_set is not AttackSet.SMART_EXACT:
        return profile, None

    selection = choose_smart_exact_attacks(params)
    resolved_profile = replace(
        profile,
        deny_list=selection.deny_list,
        metadata=selection.metadata(),
    )
    return resolved_profile, selection


def _attack_row(
    run_id: str,
    estimate_context_hash: str,
    attack_name: str,
    result: Any,
) -> dict[str, Any]:
    """Convert one estimator attack result into an attack cache row."""
    rop = result.get("rop") if hasattr(result, "get") else None
    rop_log2 = _log2_rop(rop)
    status = "success" if rop_log2 is not None else "no_finite_rop"
    return {
        "run_id": run_id,
        "estimate_context_hash": estimate_context_hash,
        "source_run_id": run_id,
        "attack_name": attack_name,
        "rop_log2": rop_log2,
        "rop_raw": value_string(rop),
        "beta": safe_float(result.get("beta")) if hasattr(result, "get") else None,
        "delta": safe_float(result.get("delta")) if hasattr(result, "get") else None,
        "d": safe_float(result.get("d")) if hasattr(result, "get") else None,
        "m": value_string(result.get("m")) if hasattr(result, "get") else None,
        "zeta": safe_float(result.get("zeta")) if hasattr(result, "get") else None,
        "tag": value_string(result.get("tag")) if hasattr(result, "get") else None,
        "status": status,
        "error": None if status == "success" else "attack returned no finite rop",
        "elapsed_sec": None,
    }


def _error_attack_row(
    run_id: str,
    estimate_context_hash: str,
    attack_name: str,
    error: str,
) -> dict[str, Any]:
    """Build an attack row for an attack that was requested but failed to return."""
    return {
        "run_id": run_id,
        "estimate_context_hash": estimate_context_hash,
        "source_run_id": run_id,
        "attack_name": attack_name,
        "rop_log2": None,
        "rop_raw": None,
        "beta": None,
        "delta": None,
        "d": None,
        "m": None,
        "zeta": None,
        "tag": None,
        "status": "error",
        "error": error,
        "elapsed_sec": None,
    }


def _smart_skipped_attack_row(
    run_id: str,
    estimate_context_hash: str,
    decision: SmartAttackDecision,
) -> dict[str, Any]:
    """Build an audit row for an attack skipped by SMART_EXACT."""
    if decision.quick_logrop is None:
        reason = decision.reason
    elif math.isfinite(decision.quick_logrop):
        reason = f"quick_logrop≈{decision.quick_logrop:.2f}; {decision.reason}"
    else:
        reason = f"quick_logrop=inf; {decision.reason}"
    return {
        "run_id": run_id,
        "estimate_context_hash": estimate_context_hash,
        "source_run_id": run_id,
        "attack_name": decision.attack_name,
        "rop_log2": None,
        "rop_raw": None,
        "beta": None,
        "delta": None,
        "d": None,
        "m": None,
        "zeta": None,
        "tag": "smart-exact",
        "status": "skipped_by_smart_exact",
        "error": reason,
        "elapsed_sec": None,
    }


def _reused_attack_row(run_id: str, row: dict[str, Any]) -> dict[str, Any]:
    """Copy a compatible attack result into the current run as a reused row."""
    source_run_id = row.get("source_run_id") or row.get("run_id")
    return {
        "run_id": run_id,
        "estimate_context_hash": row.get("estimate_context_hash"),
        "source_run_id": source_run_id,
        "attack_name": row.get("attack_name"),
        "rop_log2": row.get("rop_log2"),
        "rop_raw": row.get("rop_raw"),
        "beta": row.get("beta"),
        "delta": row.get("delta"),
        "d": row.get("d"),
        "m": row.get("m"),
        "zeta": row.get("zeta"),
        "tag": row.get("tag"),
        "status": "reused",
        "error": None,
        "elapsed_sec": None,
    }


def _reused_failed_attack_row(run_id: str, row: dict[str, Any]) -> dict[str, Any]:
    """Copy a compatible failed attack into the current run as a known failure."""
    source_run_id = row.get("source_run_id") or row.get("run_id")
    source_status = row.get("status")
    status = (
        "known_no_finite_rop"
        if source_status in {"no_finite_rop", "known_no_finite_rop"}
        else "known_error"
    )
    return {
        "run_id": run_id,
        "estimate_context_hash": row.get("estimate_context_hash"),
        "source_run_id": source_run_id,
        "attack_name": row.get("attack_name"),
        "rop_log2": None,
        "rop_raw": row.get("rop_raw"),
        "beta": row.get("beta"),
        "delta": row.get("delta"),
        "d": row.get("d"),
        "m": row.get("m"),
        "zeta": row.get("zeta"),
        "tag": row.get("tag"),
        "status": status,
        "error": row.get("error"),
        "elapsed_sec": None,
    }


def _reused_cached_attack_row(run_id: str, row: dict[str, Any]) -> dict[str, Any]:
    """Copy a reusable cached attack row into the current run."""
    if row.get("status") in {"success", "reused"} and row.get("rop_log2") is not None:
        return _reused_attack_row(run_id, row)
    return _reused_failed_attack_row(run_id, row)


def _reusable_attack_rows(
    *,
    estimate_context_hash: str,
    required_attacks: tuple[str, ...],
    cache_dir: str | Path | None,
    include_failed: bool = False,
) -> dict[str, dict[str, Any]]:
    """Return one reusable attack row for each available attack.

    Successful finite rows are always preferred. When requested, known failures
    are also reusable so repeated runs do not recompute attacks that already
    failed for the same estimator context.
    """
    successful = (pl.col("status").is_in(["success", "reused"])) & (
        pl.col("rop_log2").is_not_null()
    )
    failed = pl.col("status").is_in(
        ["error", "known_error", "no_finite_rop", "known_no_finite_rop"]
    )
    reusable = successful | failed if include_failed else successful
    candidates = (
        scan_attack_results(cache_dir)
        .filter(
            (pl.col("estimate_context_hash") == estimate_context_hash)
            & (pl.col("attack_name").is_in(required_attacks))
            & reusable
        )
        .collect()
    )
    if candidates.is_empty():
        return {}
    candidates = candidates.with_row_index("_row_nr")
    candidates = candidates.with_columns(
        pl.when((pl.col("status") == "success") & pl.col("rop_log2").is_not_null())
        .then(0)
        .when((pl.col("status") == "reused") & pl.col("rop_log2").is_not_null())
        .then(1)
        .when(pl.col("status").is_in(["no_finite_rop", "known_no_finite_rop"]))
        .then(2)
        .otherwise(3)
        .alias("_reuse_rank")
    ).sort(["attack_name", "_reuse_rank", "_row_nr"], descending=[False, False, True])
    rows = (
        candidates.group_by("attack_name", maintain_order=True)
        .first()
        .drop(["_row_nr", "_reuse_rank"])
    )
    return {row["attack_name"]: row for row in rows.to_dicts()}


def _summarize_attack_rows(
    rows: list[dict[str, Any]],
    required_attacks: tuple[str, ...],
    security_attacks: tuple[str, ...] | None = None,
) -> tuple[float | None, str | None, str]:
    """Return security bits, best attack, and run status from attack rows."""
    required_attack_set = set(required_attacks)
    security_attack_set = set(security_attacks or required_attacks)
    usable_rows = [
        row
        for row in rows
        if row.get("attack_name") in security_attack_set
        and row.get("status") in {"success", "reused"}
        and row.get("rop_log2") is not None
    ]
    if not usable_rows:
        return None, None, "error"
    best = min(usable_rows, key=lambda row: row["rop_log2"])
    completed_attack_set = {
        row["attack_name"]
        for row in usable_rows
        if row.get("attack_name") in required_attack_set
    }
    status = "partial" if completed_attack_set != required_attack_set else "success"
    return float(best["rop_log2"]), str(best["attack_name"]), status


def _profile_id_from_run_row(row: dict[str, Any]) -> str | None:
    """Return the versioned profile id stored inside a run row."""
    if row.get("profile_id") is not None:
        return str(row.get("profile_id"))
    profile_json = row.get("profile_json")
    if not profile_json:
        return None
    try:
        profile_payload = json.loads(str(profile_json))
    except json.JSONDecodeError:
        return None
    profile_id = profile_payload.get("profile_id")
    return str(profile_id) if profile_id is not None else None


def _result_from_run_row(row: dict[str, Any], *, cache_hit: bool) -> SecurityResult:
    """Build the public return dictionary from a cached or newly written run row."""
    computed_attack_count = safe_int(row.get("computed_attack_count"))
    reused_attack_count = safe_int(row.get("reused_attack_count"))
    incomplete_attack_count = safe_int(row.get("missing_attack_count"))
    attempted_attack_count = (
        computed_attack_count + reused_attack_count
        if computed_attack_count is not None and reused_attack_count is not None
        else None
    )
    successful_attack_count = (
        attempted_attack_count - incomplete_attack_count
        if attempted_attack_count is not None and incomplete_attack_count is not None
        else None
    )
    return cast(
        SecurityResult,
        {
            "security_bits": row.get("security_bits_min"),
            "best_attack": row.get("best_attack"),
            "security_model": row.get("security_model"),
            "attack_set": row.get("attack_set"),
            "profile_id": _profile_id_from_run_row(row),
            "samples_m": row.get("samples_m"),
            "cache_hit": cache_hit,
            "run_id": row.get("run_id"),
            "status": row.get("status"),
            "error": row.get("error"),
            "cache_key": row.get("cache_key"),
            "attempted_attack_count": attempted_attack_count,
            "successful_attack_count": successful_attack_count,
            "incomplete_attack_count": incomplete_attack_count,
            "computed_attack_count": computed_attack_count,
            "reused_attack_count": reused_attack_count,
            "missing_attack_count": incomplete_attack_count,
        },
    )


def _cache_hit_result(
    cache_key: str, cache_dir: str | Path | None
) -> SecurityResult | None:
    """Return the newest cached result for a cache key, if present."""
    cached = find_cached_run(cache_key, cache_dir).filter(pl.col("status") == "success")
    if cached.is_empty():
        return None
    row = cached.tail(1).to_dicts()[0]
    return _result_from_run_row(row, cache_hit=True)


def check_lwe_security(
    dimension: int,
    modulus: int,
    secret_distr: Any,
    noise_stddev: float,
    *,
    security_model: SecurityModel | str = DEFAULT_SECURITY_MODEL,
    attack_set: AttackSet | str = DEFAULT_ATTACK_SET,
    samples_m: Any = None,
    force: bool = False,
    reuse_attacks: bool = True,
    reuse_failed_attacks: bool = True,
    cache_dir: str | Path | None = None,
) -> SecurityResult:
    """Estimate and cache the security of one LWE parameter set."""
    profile = get_profile(security_model=security_model, attack_set=attack_set)
    params = _build_lwe_parameters(
        dimension=dimension,
        modulus=modulus,
        secret_distr=secret_distr,
        noise_stddev=noise_stddev,
        samples_m=samples_m,
    )
    profile, smart_selection = _resolved_profile_for_params(profile, params)
    secret = distribution_descriptor(params.Xs)
    noise = distribution_descriptor(params.Xe)
    secret_json = canonical_json(secret)
    noise_json = canonical_json(noise)
    samples_m_string = samples_m_to_string(params.m)
    cache_key = build_cache_key(
        problem_type=LWE_PROBLEM_TYPE,
        dimension=dimension,
        modulus=modulus,
        samples_m=params.m,
        secret_json=secret_json,
        noise_json=noise_json,
        profile_hash=profile.profile_hash,
        estimator_version=ESTIMATOR_VERSION,
    )
    estimate_context_hash = build_estimate_context_hash(
        problem_type=LWE_PROBLEM_TYPE,
        dimension=dimension,
        modulus=modulus,
        samples_m=params.m,
        secret_json=secret_json,
        noise_json=noise_json,
        estimator_version=ESTIMATOR_VERSION,
        estimator=profile.estimator,
        cost_model=profile.cost_model,
        shape_model=profile.shape_model,
        quantum=profile.quantum,
    )
    required_attacks = _required_attacks_for_profile(profile)
    requested_attacks = (
        smart_selection.requested_attacks
        if smart_selection is not None
        else required_attacks
    )

    if not force:
        cached = _cache_hit_result(cache_key, cache_dir)
        if cached is not None:
            return cached

    run_id = make_run_id()
    started = time.monotonic()
    reused_rows: list[dict[str, Any]] = []
    computed_rows: list[dict[str, Any]] = []
    skipped_rows = (
        [
            _smart_skipped_attack_row(run_id, estimate_context_hash, decision)
            for decision in smart_selection.skipped_decisions
        ]
        if smart_selection is not None
        else []
    )
    security_bits: float | None = None
    best_attack: str | None = None
    status = "error"
    error: str | None = None
    requested_attack_set = set(requested_attacks)
    missing_attack_set = set(requested_attacks)

    if reuse_attacks:
        reusable_rows = _reusable_attack_rows(
            estimate_context_hash=estimate_context_hash,
            required_attacks=requested_attacks,
            cache_dir=cache_dir,
            include_failed=reuse_failed_attacks,
        )
        reused_rows = [
            _reused_cached_attack_row(run_id, reusable_rows[attack])
            for attack in requested_attacks
            if attack in reusable_rows
        ]
        missing_attack_set = requested_attack_set - set(reusable_rows)

    try:
        estimator_attack_set = (
            _estimator_support_attacks(missing_attack_set)
            if missing_attack_set
            else set()
        )
        raw_results = (
            _run_estimator(params, profile, only_attacks=estimator_attack_set)
            if missing_attack_set
            else {}
        )
        computed_rows = [
            _attack_row(run_id, estimate_context_hash, name, result)
            for name, result in raw_results.items()
            if name in missing_attack_set
        ]
        returned_attacks = {row["attack_name"] for row in computed_rows}
        computed_rows.extend(
            _error_attack_row(
                run_id,
                estimate_context_hash,
                attack,
                "attack did not return a result",
            )
            for attack in sorted(missing_attack_set - returned_attacks)
        )
        attack_rows = reused_rows + computed_rows + skipped_rows
        security_bits, best_attack, status = _summarize_attack_rows(
            attack_rows, required_attacks, requested_attacks
        )
        if status != "success":
            error = (
                "estimator returned no finite rop"
                if status == "error"
                else "some attacks did not return finite rop"
            )
    except Exception as err:
        error = str(err)
        computed_rows = [
            _error_attack_row(run_id, estimate_context_hash, attack, error)
            for attack in sorted(missing_attack_set)
        ]
        attack_rows = reused_rows + computed_rows + skipped_rows
        security_bits, best_attack, status = _summarize_attack_rows(
            attack_rows, required_attacks, requested_attacks
        )

    elapsed_sec = time.monotonic() - started
    attack_rows = reused_rows + computed_rows + skipped_rows
    completed_requested_attack_set = {
        row["attack_name"]
        for row in attack_rows
        if row.get("attack_name") in requested_attack_set
        and row.get("status") in {"success", "reused"}
        and row.get("rop_log2") is not None
    }
    missing_after_compute = requested_attack_set - completed_requested_attack_set
    run_row = {
        "run_id": run_id,
        "cache_key": cache_key,
        "estimate_context_hash": estimate_context_hash,
        "problem_type": LWE_PROBLEM_TYPE,
        "dimension": dimension,
        "modulus": str(modulus),
        "modulus_bits": modulus_bits(modulus),
        "samples_m": samples_m_string,
        "secret_family": secret["family"],
        "secret_json": secret_json,
        "noise_family": noise["family"],
        "noise_json": noise_json,
        "security_model": profile.security_model.value,
        "attack_set": profile.attack_set.value,
        "profile_json": profile.to_json(),
        "security_bits_min": security_bits,
        "best_attack": best_attack,
        "status": status,
        "error": error,
        "computed_attack_count": len(computed_rows),
        "reused_attack_count": len(reused_rows),
        "missing_attack_count": len(missing_after_compute),
        "required_attacks_json": canonical_json(tuple(required_attacks)),
        "elapsed_sec": elapsed_sec,
        "created_at": current_timestamp(),
        "estimator_version": ESTIMATOR_VERSION,
    }
    append_run(run_row, cache_dir=cache_dir, force=force)
    append_attack_results(attack_rows, cache_dir=cache_dir)
    return _result_from_run_row(run_row, cache_hit=False)


def check_lwe_security_fast(
    dimension: int,
    modulus: int,
    secret_distr: Any,
    noise_stddev: float,
    *,
    security_model: SecurityModel | str = DEFAULT_SECURITY_MODEL,
    samples_m: Any = None,
    force: bool = False,
    reuse_attacks: bool = True,
    reuse_failed_attacks: bool = False,
    cache_dir: str | Path | None = None,
) -> SecurityResult:
    """Estimate LWE security with the fast-subset profile."""
    return check_lwe_security(
        dimension=dimension,
        modulus=modulus,
        secret_distr=secret_distr,
        noise_stddev=noise_stddev,
        security_model=security_model,
        attack_set=DEFAULT_FAST_ATTACK_SET,
        samples_m=samples_m,
        force=force,
        reuse_attacks=reuse_attacks,
        reuse_failed_attacks=reuse_failed_attacks,
        cache_dir=cache_dir,
    )


def check_lwe_security_exact(
    dimension: int,
    modulus: int,
    secret_distr: Any,
    noise_stddev: float,
    *,
    security_model: SecurityModel | str = DEFAULT_SECURITY_MODEL,
    samples_m: Any = None,
    force: bool = False,
    reuse_attacks: bool = True,
    reuse_failed_attacks: bool = False,
    cache_dir: str | Path | None = None,
) -> SecurityResult:
    """Estimate LWE security with the exact profile."""
    return check_lwe_security(
        dimension=dimension,
        modulus=modulus,
        secret_distr=secret_distr,
        noise_stddev=noise_stddev,
        security_model=security_model,
        attack_set=DEFAULT_EXACT_ATTACK_SET,
        samples_m=samples_m,
        force=force,
        reuse_attacks=reuse_attacks,
        reuse_failed_attacks=reuse_failed_attacks,
        cache_dir=cache_dir,
    )


def check_lwe_security_smart_exact(
    dimension: int,
    modulus: int,
    secret_distr: Any,
    noise_stddev: float,
    *,
    security_model: SecurityModel | str = DEFAULT_SECURITY_MODEL,
    samples_m: Any = None,
    force: bool = False,
    reuse_attacks: bool = True,
    reuse_failed_attacks: bool = False,
    cache_dir: str | Path | None = None,
) -> SecurityResult:
    """Estimate LWE security with the smart-exact profile."""
    return check_lwe_security(
        dimension=dimension,
        modulus=modulus,
        secret_distr=secret_distr,
        noise_stddev=noise_stddev,
        security_model=security_model,
        attack_set=DEFAULT_SMART_EXACT_ATTACK_SET,
        samples_m=samples_m,
        force=force,
        reuse_attacks=reuse_attacks,
        reuse_failed_attacks=reuse_failed_attacks,
        cache_dir=cache_dir,
    )

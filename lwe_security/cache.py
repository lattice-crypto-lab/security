from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import polars as pl

from .common import canonical_json, stable_hash
from .constants import (
    ATTACK_RESULTS_FILE_NAME,
    CACHE_TIME_ZONE_NAME,
    RUNS_FILE_NAME,
)


CHINA_STANDARD_TIME = ZoneInfo(CACHE_TIME_ZONE_NAME)

RUNS_SCHEMA: dict[str, pl.DataType] = {
    "run_id": pl.String(),
    "cache_key": pl.String(),
    "estimate_context_hash": pl.String(),
    "problem_type": pl.String(),
    "dimension": pl.UInt64(),
    "modulus": pl.String(),
    "modulus_bits": pl.UInt64(),
    "samples_m": pl.String(),
    "secret_family": pl.String(),
    "secret_json": pl.String(),
    "noise_family": pl.String(),
    "noise_json": pl.String(),
    "security_model": pl.String(),
    "attack_set": pl.String(),
    "profile_json": pl.String(),
    "security_bits_min": pl.Float64(),
    "best_attack": pl.String(),
    "status": pl.String(),
    "error": pl.String(),
    "computed_attack_count": pl.UInt64(),
    "reused_attack_count": pl.UInt64(),
    "missing_attack_count": pl.UInt64(),
    "required_attacks_json": pl.String(),
    "elapsed_sec": pl.Float64(),
    "created_at": pl.Datetime(time_zone=CACHE_TIME_ZONE_NAME),
    "estimator_version": pl.String(),
}

ATTACK_RESULTS_SCHEMA: dict[str, pl.DataType] = {
    "run_id": pl.String(),
    "estimate_context_hash": pl.String(),
    "source_run_id": pl.String(),
    "attack_name": pl.String(),
    "rop_log2": pl.Float64(),
    "rop_raw": pl.String(),
    "beta": pl.Float64(),
    "delta": pl.Float64(),
    "d": pl.Float64(),
    "m": pl.String(),
    "zeta": pl.Float64(),
    "tag": pl.String(),
    "status": pl.String(),
    "error": pl.String(),
    "elapsed_sec": pl.Float64(),
}


def make_run_id() -> str:
    """Return a random id for one estimator run."""
    return uuid.uuid4().hex


def current_timestamp() -> dt.datetime:
    """Return the current timestamp as an Asia/Shanghai aware datetime."""
    return dt.datetime.now(CHINA_STANDARD_TIME)


def modulus_bits(modulus: int | str) -> int:
    """Return ceil(log2(modulus)), treating powers of two by their exponent."""
    value = int(modulus)
    if value <= 0:
        raise ValueError(f"modulus must be positive, got {modulus!r}")
    if value & (value - 1) == 0:
        return value.bit_length() - 1
    return value.bit_length()


def samples_m_to_string(samples_m: Any) -> str:
    """Serialize the sample count for cache keys and Parquet storage."""
    if samples_m is None:
        return "Infinity"
    try:
        if float(samples_m) == float("inf"):
            return "Infinity"
    except (TypeError, ValueError, OverflowError):
        pass
    return str(samples_m)


def cache_paths(cache_dir: str | Path | None = None) -> tuple[Path, Path]:
    """Return the run-summary and attack-result Parquet paths."""
    root = Path("." if cache_dir is None else cache_dir)
    return root / RUNS_FILE_NAME, root / ATTACK_RESULTS_FILE_NAME


def _empty_frame(schema: dict[str, pl.DataType]) -> pl.DataFrame:
    """Create an empty Polars frame with the requested schema."""
    return pl.DataFrame({name: pl.Series(name, [], dtype=dtype) for name, dtype in schema.items()})


def ensure_cache_files(cache_dir: str | Path | None = None) -> tuple[Path, Path]:
    """Create missing v2 cache files and return their paths."""
    runs_path, attack_results_path = cache_paths(cache_dir)
    runs_path.parent.mkdir(parents=True, exist_ok=True)
    attack_results_path.parent.mkdir(parents=True, exist_ok=True)

    if not runs_path.exists():
        _empty_frame(RUNS_SCHEMA).write_parquet(runs_path)
    if not attack_results_path.exists():
        _empty_frame(ATTACK_RESULTS_SCHEMA).write_parquet(attack_results_path)

    return runs_path, attack_results_path


def read_runs(cache_dir: str | Path | None = None) -> pl.DataFrame:
    """Read the run-summary cache file, creating it first if needed."""
    runs_path, _ = ensure_cache_files(cache_dir)
    return pl.read_parquet(runs_path)


def scan_runs(cache_dir: str | Path | None = None) -> pl.LazyFrame:
    """Return a lazy scan of the run-summary cache file."""
    runs_path, _ = ensure_cache_files(cache_dir)
    return pl.scan_parquet(runs_path)


def read_attack_results(cache_dir: str | Path | None = None) -> pl.DataFrame:
    """Read the per-attack cache file, creating it first if needed."""
    _, attack_results_path = ensure_cache_files(cache_dir)
    return pl.read_parquet(attack_results_path)


def scan_attack_results(cache_dir: str | Path | None = None) -> pl.LazyFrame:
    """Return a lazy scan of the per-attack cache file."""
    _, attack_results_path = ensure_cache_files(cache_dir)
    return pl.scan_parquet(attack_results_path)


def find_cached_run(cache_key: str, cache_dir: str | Path | None = None) -> pl.DataFrame:
    """Return cached run rows matching the given cache key."""
    return scan_runs(cache_dir).filter(pl.col("cache_key") == cache_key).collect()


def find_attack_results_for_run(
    run_id: str,
    cache_dir: str | Path | None = None,
) -> pl.DataFrame:
    """Return per-attack rows for one run id."""
    return scan_attack_results(cache_dir).filter(pl.col("run_id") == run_id).collect()


def cache_key_payload(
    *,
    problem_type: str,
    dimension: int,
    modulus: int | str,
    samples_m: Any,
    secret_json: str,
    noise_json: str,
    profile_hash: str,
    estimator_version: str,
) -> dict[str, Any]:
    """Return the JSON-compatible payload used to build a cache key."""
    return {
        "problem_type": problem_type,
        "dimension": int(dimension),
        "modulus": str(modulus),
        "samples_m": samples_m_to_string(samples_m),
        "secret_json": secret_json,
        "noise_json": noise_json,
        "profile_hash": profile_hash,
        "estimator_version": estimator_version,
    }


def build_cache_key(
    *,
    problem_type: str,
    dimension: int,
    modulus: int | str,
    samples_m: Any,
    secret_json: str,
    noise_json: str,
    profile_hash: str,
    estimator_version: str,
) -> str:
    """Build the stable identity hash for a parameter/profile estimate."""
    return stable_hash(
        cache_key_payload(
            problem_type=problem_type,
            dimension=dimension,
            modulus=modulus,
            samples_m=samples_m,
            secret_json=secret_json,
            noise_json=noise_json,
            profile_hash=profile_hash,
            estimator_version=estimator_version,
        )
    )


def estimate_context_payload(
    *,
    problem_type: str,
    dimension: int,
    modulus: int | str,
    samples_m: Any,
    secret_json: str,
    noise_json: str,
    estimator_version: str,
    estimator: str,
    cost_model: str,
    shape_model: str,
    quantum: bool,
) -> dict[str, Any]:
    """Return the JSON-compatible reusable per-attack context payload."""
    return {
        "problem_type": problem_type,
        "dimension": int(dimension),
        "modulus": str(modulus),
        "samples_m": samples_m_to_string(samples_m),
        "secret_json": secret_json,
        "noise_json": noise_json,
        "estimator_version": estimator_version,
        "estimator": estimator,
        "cost_model": cost_model,
        "shape_model": shape_model,
        "quantum": bool(quantum),
    }


def build_estimate_context_hash(
    *,
    problem_type: str,
    dimension: int,
    modulus: int | str,
    samples_m: Any,
    secret_json: str,
    noise_json: str,
    estimator_version: str,
    estimator: str,
    cost_model: str,
    shape_model: str,
    quantum: bool,
) -> str:
    """Build the reusable per-attack context hash for an estimator configuration."""
    return stable_hash(
        estimate_context_payload(
            problem_type=problem_type,
            dimension=dimension,
            modulus=modulus,
            samples_m=samples_m,
            secret_json=secret_json,
            noise_json=noise_json,
            estimator_version=estimator_version,
            estimator=estimator,
            cost_model=cost_model,
            shape_model=shape_model,
            quantum=quantum,
        )
    )


def estimate_context_payload_json(
    *,
    problem_type: str,
    dimension: int,
    modulus: int | str,
    samples_m: Any,
    secret_json: str,
    noise_json: str,
    estimator_version: str,
    estimator: str,
    cost_model: str,
    shape_model: str,
    quantum: bool,
) -> str:
    """Return the canonical JSON payload used to build an estimate context hash."""
    return canonical_json(
        estimate_context_payload(
            problem_type=problem_type,
            dimension=dimension,
            modulus=modulus,
            samples_m=samples_m,
            secret_json=secret_json,
            noise_json=noise_json,
            estimator_version=estimator_version,
            estimator=estimator,
            cost_model=cost_model,
            shape_model=shape_model,
            quantum=quantum,
        )
    )


def cache_key_payload_json(
    *,
    problem_type: str,
    dimension: int,
    modulus: int | str,
    samples_m: Any,
    secret_json: str,
    noise_json: str,
    profile_hash: str,
    estimator_version: str,
) -> str:
    """Return the canonical JSON payload used to build a cache key."""
    return canonical_json(
        cache_key_payload(
            problem_type=problem_type,
            dimension=dimension,
            modulus=modulus,
            samples_m=samples_m,
            secret_json=secret_json,
            noise_json=noise_json,
            profile_hash=profile_hash,
            estimator_version=estimator_version,
        )
    )


def _normalize_row(row: dict[str, Any], schema: dict[str, pl.DataType]) -> dict[str, Any]:
    """Return a row containing exactly the schema columns in schema order."""
    return {name: row.get(name) for name in schema}


def _rows_frame(rows: Iterable[dict[str, Any]], schema: dict[str, pl.DataType]) -> pl.DataFrame:
    """Build a Polars frame from possibly partial row dictionaries."""
    normalized = [_normalize_row(row, schema) for row in rows]
    if not normalized:
        return _empty_frame(schema)
    return pl.DataFrame(normalized, schema=schema)


def append_run(row: dict[str, Any], cache_dir: str | Path | None = None, force: bool = False) -> None:
    """Append one run-summary row, rejecting duplicate cache keys by default."""
    runs_path, _ = ensure_cache_files(cache_dir)
    existing = pl.read_parquet(runs_path)
    cache_key = row.get("cache_key")

    if not cache_key:
        raise ValueError("run row must include cache_key")
    existing_success = existing.filter(
        (pl.col("cache_key") == cache_key) & (pl.col("status") == "success")
    )
    if not force and not existing_success.is_empty():
        raise ValueError(f"cache_key already exists: {cache_key}")

    new = _rows_frame([row], RUNS_SCHEMA)
    pl.concat([existing, new], how="vertical").write_parquet(runs_path)


def append_attack_results(
    rows: Iterable[dict[str, Any]],
    cache_dir: str | Path | None = None,
) -> None:
    """Append per-attack result rows to the attack-result cache."""
    _, attack_results_path = ensure_cache_files(cache_dir)
    existing = pl.read_parquet(attack_results_path)
    new = _rows_frame(rows, ATTACK_RESULTS_SCHEMA)
    if new.is_empty():
        return
    pl.concat([existing, new], how="vertical").write_parquet(attack_results_path)

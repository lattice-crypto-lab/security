"""Public type definitions for LWE security estimation results."""

from __future__ import annotations

from typing import TypedDict


class SecurityResult(TypedDict):
    """Public result dictionary returned by LWE security estimate helpers."""

    security_bits: float | None
    best_attack: str | None
    security_model: str
    attack_set: str
    profile_id: str | None
    samples_m: str
    cache_hit: bool
    run_id: str
    status: str
    error: str | None
    cache_key: str
    attempted_attack_count: int | None
    successful_attack_count: int | None
    incomplete_attack_count: int | None
    computed_attack_count: int | None
    reused_attack_count: int | None
    missing_attack_count: int | None

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .common import canonical_json, stable_hash
from .constants import (
    CLASSICAL_COST_MODEL,
    DEFAULT_JOBS,
    DEFAULT_SHAPE_MODEL,
    EXACT_DENY_LIST,
    FAST_SUBSET_DENY_LIST,
    LWE_ESTIMATOR_NAME,
    PROFILE_ID_VERSION,
    QUANTUM_COST_MODEL,
)


class SecurityModel(StrEnum):
    """Estimator cost model family."""

    CLASSICAL = "classical"
    QUANTUM = "quantum"


class AttackSet(StrEnum):
    """Attack-set coverage requested from the estimator."""

    FAST_SUBSET = "fast_subset"
    EXACT = "exact"
    SMART_EXACT = "smart_exact"


DEFAULT_SECURITY_MODEL = SecurityModel.CLASSICAL
DEFAULT_ATTACK_SET = AttackSet.FAST_SUBSET


def profile_id(
    attack_set: AttackSet | str,
    security_model: SecurityModel | str,
) -> str:
    """Return the versioned profile id for an attack-set/model pair."""
    return (
        f"{AttackSet(attack_set).value}_"
        f"{SecurityModel(security_model).value}_"
        f"v{PROFILE_ID_VERSION}"
    )


@dataclass(frozen=True)
class EstimationProfile:
    """Immutable configuration for one estimator execution mode."""

    profile_id: str
    security_model: SecurityModel
    attack_set: AttackSet
    estimator: str
    cost_model: str
    shape_model: str
    deny_list: tuple[str, ...]
    jobs: int
    timeout_sec: int | None
    purpose: str
    metadata: dict[str, Any] | None = None

    @property
    def quantum(self) -> bool:
        """Return whether this profile uses a quantum reduction cost model."""
        return self.security_model is SecurityModel.QUANTUM

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation of this profile."""
        payload = {
            "profile_id": self.profile_id,
            "security_model": self.security_model.value,
            "attack_set": self.attack_set.value,
            "estimator": self.estimator,
            "cost_model": self.cost_model,
            "shape_model": self.shape_model,
            "deny_list": list(self.deny_list),
            "jobs": self.jobs,
            "timeout_sec": self.timeout_sec,
            "purpose": self.purpose,
            "quantum": self.quantum,
        }
        if self.metadata is not None:
            payload["metadata"] = self.metadata
        return payload

    def to_json(self) -> str:
        """Return the canonical JSON representation of this profile."""
        return canonical_json(self.to_dict())

    @property
    def profile_hash(self) -> str:
        """Return the stable cache hash for this profile."""
        return stable_hash(self.to_json())


def _cost_model_for(security_model: SecurityModel) -> str:
    """Return the reduction cost model name for a security model."""
    if security_model is SecurityModel.CLASSICAL:
        return CLASSICAL_COST_MODEL
    if security_model is SecurityModel.QUANTUM:
        return QUANTUM_COST_MODEL
    raise KeyError(f"Unknown security model {security_model!r}")


def _deny_list_for(attack_set: AttackSet) -> tuple[str, ...]:
    """Return the estimator deny list for an attack-set coverage level."""
    if attack_set is AttackSet.FAST_SUBSET:
        return FAST_SUBSET_DENY_LIST
    if attack_set is AttackSet.EXACT:
        return EXACT_DENY_LIST
    if attack_set is AttackSet.SMART_EXACT:
        return EXACT_DENY_LIST
    raise KeyError(f"Unknown attack set {attack_set!r}")


def _purpose_for(security_model: SecurityModel, attack_set: AttackSet) -> str:
    """Return a short human-readable purpose for a profile."""
    if attack_set is AttackSet.FAST_SUBSET:
        suffix = "screening with a fast algorithm subset"
    elif attack_set is AttackSet.EXACT:
        suffix = "final estimate"
    elif attack_set is AttackSet.SMART_EXACT:
        suffix = "final estimate with smart expensive-attack screening"
    else:
        raise KeyError(f"Unknown attack set {attack_set!r}")
    return f"{security_model.value} {suffix}"


def _make_profile(security_model: SecurityModel, attack_set: AttackSet) -> EstimationProfile:
    """Build one immutable estimation profile from model and attack-set choices."""
    return EstimationProfile(
        profile_id=profile_id(attack_set, security_model),
        security_model=security_model,
        attack_set=attack_set,
        estimator=LWE_ESTIMATOR_NAME,
        cost_model=_cost_model_for(security_model),
        shape_model=DEFAULT_SHAPE_MODEL,
        deny_list=_deny_list_for(attack_set),
        jobs=DEFAULT_JOBS,
        timeout_sec=None,
        purpose=_purpose_for(security_model, attack_set),
    )


PROFILES: dict[str, EstimationProfile] = {
    profile.profile_id: profile
    for profile in (
        _make_profile(SecurityModel.CLASSICAL, AttackSet.FAST_SUBSET),
        _make_profile(SecurityModel.CLASSICAL, AttackSet.EXACT),
        _make_profile(SecurityModel.CLASSICAL, AttackSet.SMART_EXACT),
        _make_profile(SecurityModel.QUANTUM, AttackSet.FAST_SUBSET),
        _make_profile(SecurityModel.QUANTUM, AttackSet.EXACT),
        _make_profile(SecurityModel.QUANTUM, AttackSet.SMART_EXACT),
    )
}


def get_profile(
    security_model: SecurityModel | str = DEFAULT_SECURITY_MODEL,
    attack_set: AttackSet | str = DEFAULT_ATTACK_SET,
) -> EstimationProfile:
    """Return a profile by security model and attack-set coverage."""
    try:
        profile_key = profile_id(attack_set, security_model)
    except ValueError as err:
        known_models = ", ".join(model.value for model in SecurityModel)
        known_attack_sets = ", ".join(coverage.value for coverage in AttackSet)
        raise KeyError(
            f"Unknown security_model={security_model!r} or attack_set={attack_set!r}. "
            f"Known security models: {known_models}. "
            f"Known attack sets: {known_attack_sets}."
        ) from err
    try:
        return PROFILES[profile_key]
    except KeyError as err:
        known = ", ".join(sorted(PROFILES))
        raise KeyError(
            f"Unknown security profile for security_model={security_model!r}, "
            f"attack_set={attack_set!r}. Resolved id: {profile_key!r}. "
            f"Known profiles: {known}"
        ) from err


def list_profiles() -> tuple[str, ...]:
    """Return all known profile ids in stable sorted order."""
    return tuple(sorted(PROFILES))

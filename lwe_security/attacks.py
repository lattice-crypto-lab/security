"""Attack-set helpers for lattice-estimator LWE runs."""

from __future__ import annotations

from typing import Protocol

from .constants import LWE_ESTIMATE_ATTACKS, LWE_ESTIMATOR_NAME


class AttackProfile(Protocol):
    """Profile fields needed to derive estimator attack sets."""

    @property
    def estimator(self) -> str:
        """Estimator function name."""
        ...

    @property
    def deny_list(self) -> tuple[str, ...]:
        """Estimator attack names excluded by this profile."""
        ...


_ESTIMATOR_ATTACK_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "bdd_hybrid": ("bdd",),
    "bdd_mitm_hybrid": ("bdd_hybrid",),
}


def required_attacks_for_profile(profile: AttackProfile) -> tuple[str, ...]:
    """Return the attack names required by an estimation profile.

    The profile deny list is the source of truth. Attack order follows
    ``LWE_ESTIMATE_ATTACKS`` so result displays and cache rows stay stable.
    """
    if profile.estimator != LWE_ESTIMATOR_NAME:
        raise KeyError(f"Cannot derive attack set for estimator {profile.estimator!r}")
    denied = set(profile.deny_list)
    return tuple(attack for attack in LWE_ESTIMATE_ATTACKS if attack not in denied)


def deny_list_for_only_attacks(only_attacks: set[str] | None) -> tuple[str, ...] | None:
    """Return a deny list that makes ``LWE.estimate`` run only requested attacks.

    ``None`` means the caller wants the estimator profile deny list unchanged.
    """
    if only_attacks is None:
        return None

    unknown = only_attacks - set(LWE_ESTIMATE_ATTACKS)
    if unknown:
        raise KeyError(f"Unknown LWE attacks requested: {sorted(unknown)}")
    return tuple(attack for attack in LWE_ESTIMATE_ATTACKS if attack not in only_attacks)


def estimator_support_attacks(requested_attacks: set[str]) -> set[str]:
    """Return requested attacks plus estimator-internal dependency attacks.

    Some estimator attack implementations read earlier attack results from the
    same ``LWE.estimate`` call. These support attacks may be computed by the
    estimator, but callers can still persist only the originally requested
    missing attacks.
    """
    supported = set(requested_attacks)
    pending = list(requested_attacks)

    while pending:
        attack = pending.pop()
        for dependency in _ESTIMATOR_ATTACK_DEPENDENCIES.get(attack, ()):
            if dependency not in supported:
                supported.add(dependency)
                pending.append(dependency)

    return supported

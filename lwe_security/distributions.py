from __future__ import annotations

from typing import Any

from estimator.estimator.nd import CenteredBinomial, DiscreteGaussian, NoiseDistribution, SparseTernary, Uniform

from .common import JsonScalar, canonical_json, json_scalar, safe_float, safe_int, stable_hash


def _bounds(distribution: NoiseDistribution) -> list[JsonScalar]:
    """Return distribution bounds as JSON-compatible scalar values."""
    low, high = getattr(distribution, "bounds", (None, None))
    return [json_scalar(low), json_scalar(high)]


def _hamming_weight(distribution: NoiseDistribution) -> int | None:
    """Return the hamming weight when the distribution exposes one."""
    try:
        return safe_int(distribution.hamming_weight)
    except (TypeError, ValueError):
        return None


def _is_uniform_with_bounds(distribution: NoiseDistribution, low: int, high: int) -> bool:
    """Return whether a uniform distribution has the exact requested bounds."""
    if not isinstance(distribution, Uniform):
        return False
    bounds = _bounds(distribution)
    return bounds == [low, high]


def distribution_family(distribution: NoiseDistribution) -> str:
    """Classify an estimator distribution into a stable cache family."""
    if isinstance(distribution, SparseTernary):
        if distribution.m == 0:
            return "sparse_binary"
        return "sparse_ternary"
    if _is_uniform_with_bounds(distribution, -1, 1):
        return "uniform_ternary"
    if _is_uniform_with_bounds(distribution, 0, 1):
        return "uniform_binary"
    if isinstance(distribution, DiscreteGaussian):
        return "discrete_gaussian"
    if isinstance(distribution, CenteredBinomial):
        return "centered_binomial"
    if isinstance(distribution, Uniform):
        return "uniform"
    return "unknown"


def distribution_descriptor(distribution: NoiseDistribution) -> dict[str, Any]:
    """Return a structured, JSON-compatible descriptor for a distribution."""
    descriptor: dict[str, Any] = {
        "family": distribution_family(distribution),
        "class_name": type(distribution).__name__,
        "repr": repr(distribution),
        "n": safe_int(getattr(distribution, "n", None)),
        "mean": safe_float(getattr(distribution, "mean", None)),
        "stddev": safe_float(getattr(distribution, "stddev", None)),
        "bounds": _bounds(distribution),
        "is_sparse": bool(getattr(distribution, "is_sparse", False)),
        "hamming_weight": _hamming_weight(distribution),
        "density": safe_float(getattr(distribution, "_density", None)),
    }

    if isinstance(distribution, SparseTernary):
        descriptor.update(
            {
                "p": safe_int(distribution.p),
                "m": safe_int(distribution.m),
            }
        )
    elif isinstance(distribution, CenteredBinomial):
        descriptor["eta"] = safe_int(distribution.bounds[1])
    elif isinstance(distribution, Uniform):
        descriptor.update(
            {
                "lower": json_scalar(distribution.bounds[0]),
                "upper": json_scalar(distribution.bounds[1]),
            }
        )

    return descriptor


def distribution_json(distribution: NoiseDistribution) -> str:
    """Return the canonical JSON descriptor for a distribution."""
    return canonical_json(distribution_descriptor(distribution))


def distribution_hash(distribution: NoiseDistribution) -> str:
    """Return the stable hash of a distribution descriptor."""
    return stable_hash(distribution_json(distribution))

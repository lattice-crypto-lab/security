from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from typing import Any


JsonScalar = int | float | str | None


def canonical_json(value: Mapping[str, Any] | list[Any] | tuple[Any, ...]) -> str:
    """Serialize a JSON-compatible value with stable key and whitespace rules."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def stable_hash(value: Mapping[str, Any] | list[Any] | tuple[Any, ...] | str) -> str:
    """Return a SHA-256 hex digest for canonical JSON or a serialized string."""
    payload = value if isinstance(value, str) else canonical_json(value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def safe_float(value: Any) -> float | None:
    """Convert numeric values to finite Python floats when possible."""
    if value is None:
        return None
    text = str(value)
    if text in {"+Infinity", "Infinity", "-Infinity"}:
        return None
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return result if math.isfinite(result) else None


def safe_int(value: Any) -> int | None:
    """Convert integer-like values to Python ints when possible."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def json_scalar(value: Any) -> JsonScalar:
    """Convert Sage and Python scalar values into JSON-compatible scalars."""
    if value is None:
        return None
    text = str(value)
    if text in {"+Infinity", "Infinity"}:
        return "Infinity"
    if text == "-Infinity":
        return "-Infinity"
    try:
        as_int = int(value)
    except (TypeError, ValueError, OverflowError):
        as_int = None
    if as_int is not None:
        try:
            if value == as_int:
                return as_int
        except TypeError:
            pass
    as_float = safe_float(value)
    if as_float is not None:
        return as_float
    return text


def value_string(value: Any) -> str | None:
    """Return a stable string for optional values."""
    if value is None:
        return None
    return str(value)

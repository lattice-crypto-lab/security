"""Smart expensive-attack selection for LWE exact estimates."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from sage.all import oo

from .constants import LWE_ESTIMATE_ATTACKS


SMART_EXACT_RULE_VERSION = 2

SMART_EXACT_CORE_ATTACKS = (
    "usvp",
    "bdd",
    "bdd_hybrid",
    "bdd_mitm_hybrid",
    "dual",
    "dual_hybrid",
)

SMART_EXACT_EXPENSIVE_ATTACKS = (
    "arora-gb",
    "bkw",
)

ARORA_FORCE_RUN_BOUND_D = 11
ARORA_CALIBRATION_BOUND_D = 13
ARORA_CALIBRATION_N_MAX = 512
ARORA_SMALL_GAUSSIAN_N_MAX = 256
ARORA_SMALL_GAUSSIAN_STDDEV = 2.0
ARORA_GAUSSIAN_CALIBRATION_N_MAX = 128
ARORA_GAUSSIAN_CALIBRATION_STDDEV = 4.0
ARORA_GAUSSIAN_CALIBRATION_LOGROP_CAP = 160.0
ARORA_GAUSSIAN_TAIL_MIN_MAX_T = 32
ARORA_GAUSSIAN_MCAN_ROUND_LOG2 = 240.0
ARORA_QUICK_DREG_CAP = 256

BKW_SMALL_Q_FORCE = 4
BKW_MEDIUM_Q_FORCE = 16
BKW_CALIBRATION_N_MAX = 128
BKW_CALIBRATION_Q_MAX = 512
BKW_CALIBRATION_LOGROP_CAP = 128.0


@dataclass(frozen=True)
class SmartAttackDecision:
    """One smart decision for an expensive attack."""

    attack_name: str
    run: bool
    reason: str
    quick_logrop: float | None = None
    mode: str = "skip"
    calibration: bool = False

    @property
    def required(self) -> bool:
        """Return whether this decision contributes to profile completion."""
        return self.run and self.mode == "run"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible decision payload."""
        payload: dict[str, Any] = {
            "attack_name": self.attack_name,
            "run": self.run,
            "required": self.required,
            "mode": self.mode,
            "calibration": self.calibration,
            "reason": self.reason,
        }
        if self.quick_logrop is not None:
            payload["quick_logrop"] = (
                float(self.quick_logrop)
                if math.isfinite(self.quick_logrop)
                else "Infinity"
            )
        return payload


@dataclass(frozen=True)
class SmartAttackSelection:
    """Resolved attack set and audit metadata for one smart exact run."""

    deny_list: tuple[str, ...]
    decisions: dict[str, SmartAttackDecision]

    @property
    def required_attacks(self) -> tuple[str, ...]:
        """Return attacks that remain enabled after smart screening."""
        denied = set(self.deny_list)
        return tuple(attack for attack in LWE_ESTIMATE_ATTACKS if attack not in denied)

    @property
    def optional_decisions(self) -> tuple[SmartAttackDecision, ...]:
        """Return expensive attacks that should run only for calibration."""
        return tuple(
            decision
            for attack, decision in self.decisions.items()
            if attack in SMART_EXACT_EXPENSIVE_ATTACKS
            and decision.run
            and not decision.required
        )

    @property
    def requested_attacks(self) -> tuple[str, ...]:
        """Return required attacks plus optional calibration attacks."""
        optional = {decision.attack_name for decision in self.optional_decisions}
        required = set(self.required_attacks)
        return tuple(
            attack
            for attack in LWE_ESTIMATE_ATTACKS
            if attack in required or attack in optional
        )

    @property
    def skipped_decisions(self) -> tuple[SmartAttackDecision, ...]:
        """Return expensive attacks skipped by the smart screen."""
        return tuple(
            decision
            for attack, decision in self.decisions.items()
            if attack in SMART_EXACT_EXPENSIVE_ATTACKS and not decision.run
        )

    def metadata(self) -> dict[str, Any]:
        """Return JSON-compatible profile metadata for cache identity and audit."""
        return {
            "smart_exact": {
                "rule_version": SMART_EXACT_RULE_VERSION,
                "core_attacks": list(SMART_EXACT_CORE_ATTACKS),
                "expensive_attacks": list(SMART_EXACT_EXPENSIVE_ATTACKS),
                "deny_list": list(self.deny_list),
                "required_attacks": list(self.required_attacks),
                "optional_attacks": [
                    decision.attack_name for decision in self.optional_decisions
                ],
                "requested_attacks": list(self.requested_attacks),
                "decisions": {
                    attack: decision.to_dict()
                    for attack, decision in sorted(self.decisions.items())
                },
            }
        }


def _is_infinite(value: Any) -> bool:
    """Return whether a Sage/Python value represents infinity."""
    if value is None:
        return True
    try:
        if math.isinf(float(value)):
            return True
    except (TypeError, ValueError, OverflowError):
        pass
    if str(value) in {"+Infinity", "Infinity"}:
        return True
    try:
        return bool(value == oo)
    except TypeError:
        return False


def _finite_float(value: Any) -> float | None:
    """Return a finite float when possible."""
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return result if math.isfinite(result) else None


def _log2_int_like(value: Any) -> float:
    """Return log2 for positive int-like values, including huge Sage integers."""
    if _is_infinite(value):
        return math.inf
    try:
        integer = int(value)
    except (TypeError, ValueError, OverflowError):
        result = _finite_float(value)
        return math.log2(result) if result and result > 0 else math.inf
    if integer <= 0:
        return math.inf
    if integer.bit_count() == 1:
        return float(integer.bit_length() - 1)
    return math.log2(integer)


def _bounds_width(distribution: Any) -> int | None:
    """Return finite inclusive support width for a bounded distribution."""
    if not bool(getattr(distribution, "is_bounded", False)):
        return None
    bounds = getattr(distribution, "bounds", None)
    if bounds is None:
        return None
    low, high = bounds
    if low is None or high is None:
        return None
    if _is_infinite(low) or _is_infinite(high):
        return None
    try:
        low_int = int(low)
        high_int = int(high)
    except (TypeError, ValueError, OverflowError):
        return None
    width = high_int - low_int + 1
    return width if width > 0 else None


def _log2_binomial(n: int, k: int) -> float:
    """Return log2(binomial(n, k)) without materializing the binomial."""
    if k < 0 or k > n:
        return math.inf
    return (
        math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)
    ) / math.log(2)


def _log2_monomials(num_vars: int, degree: int) -> float:
    """Return log2 of the number of monomials of total degree at most degree."""
    if num_vars <= 0 or degree < 0:
        return math.inf
    return _log2_binomial(num_vars + degree, degree)


def _semi_regular_dreg(
    num_vars: int,
    equations: tuple[tuple[int, int], ...],
    *,
    max_degree: int = ARORA_QUICK_DREG_CAP,
) -> int | None:
    """Return a cheap semi-regular Hilbert-series solving-degree estimate."""
    numerator_coeffs = {0: 1}

    for degree, count in equations:
        if degree <= 0 or count <= 0:
            continue
        next_coeffs: dict[int, int] = {}
        for shift, base_coeff in numerator_coeffs.items():
            max_j = (max_degree - shift) // degree
            for j in range(max_j + 1):
                if j > count:
                    break
                coeff = math.comb(count, j)
                if j % 2:
                    coeff = -coeff
                next_shift = shift + j * degree
                next_coeffs[next_shift] = (
                    next_coeffs.get(next_shift, 0) + base_coeff * coeff
                )
        numerator_coeffs = {
            shift: coeff for shift, coeff in next_coeffs.items() if coeff
        }

    for degree in range(max_degree + 1):
        coefficient = 0
        for shift, numerator_coeff in numerator_coeffs.items():
            residual_degree = degree - shift
            if residual_degree < 0:
                continue
            coefficient += numerator_coeff * math.comb(
                num_vars + residual_degree - 1,
                residual_degree,
            )
        if coefficient < 0:
            return degree
    return None


def _arora_secret_equations(params: Any) -> tuple[tuple[int, int], ...]:
    """Return the secret equations used by the estimator's Arora-GB model."""
    try:
        if params.Xs > params.Xe:
            return ()
    except TypeError:
        return ()

    secret_width = _bounds_width(params.Xs)
    if secret_width is not None:
        return ((secret_width, int(params.n)),)

    if bool(getattr(params.Xs, "is_Gaussian_like", False)):
        stddev = _finite_float(getattr(params.Xs, "stddev", None))
        if stddev is not None and stddev > 0:
            return ((2 * math.ceil(3 * stddev) + 1, int(params.n)),)

    return ()


def _sample_aware_arora_degree(n: int, d: int, m: Any) -> int:
    """Return a rough, optimistic solving-degree proxy for Arora-GB screening."""
    if _is_infinite(m):
        return d
    try:
        if int(m) <= n * n:
            return max(d + 2, 2 * d - 2)
    except (TypeError, ValueError, OverflowError):
        return max(d + 2, 2 * d - 2)

    logn_m = _log2_int_like(m) / math.log2(n)
    if logn_m >= d:
        return d
    return d + max(0, math.ceil(d - logn_m))


def _arora_quick_logrop_bounded(params: Any, omega: float = 2.0) -> float:
    """Return a semi-regular quick Arora-GB log2 cost for bounded noise."""
    params = params.normalize()
    n = int(params.n)
    d = _bounds_width(params.Xe)
    if d is None:
        return math.inf
    if d > 128:
        return math.inf
    m_eff = n**d if _is_infinite(params.m) else min(int(params.m), n**d)
    equations = ((d, int(m_eff)),) + _arora_secret_equations(params)
    dreg = _semi_regular_dreg(n, equations)
    if dreg is not None:
        return omega * _log2_monomials(n, dreg)

    dreg = _sample_aware_arora_degree(n, d, m_eff)
    return omega * _log2_monomials(n, dreg)


def _gaussian_tail_log2_mcan(stddev: float, t: int) -> float:
    """Return log2 of estimator-style Gaussian-tail sample count."""
    c_value = t / stddev
    log_epsilon = (
        math.log(2)
        - math.log(c_value * math.sqrt(2 * math.pi))
        - c_value * c_value / 2
    )
    return math.log2(-math.log(0.99)) - log_epsilon / math.log(2)


def _gaussian_tail_sample_count(log2_mcan: float) -> int:
    """Return an integer sample count matching estimator tail-rounding behavior."""
    if not math.isfinite(log2_mcan) or log2_mcan < 0:
        return 0
    if log2_mcan > ARORA_GAUSSIAN_MCAN_ROUND_LOG2:
        return 2**31
    return 1 << max(0, math.ceil(log2_mcan))


def _arora_quick_logrop_gaussian(params: Any, omega: float = 2.0) -> float:
    """Return a semi-regular quick Arora-GB log2 cost for Gaussian-like noise."""
    params = params.normalize()
    n = int(params.n)
    stddev = _finite_float(getattr(params.Xe, "stddev", None))
    if stddev is None or stddev <= 0:
        return math.inf
    if stddev > ARORA_SMALL_GAUSSIAN_STDDEV and n > ARORA_GAUSSIAN_CALIBRATION_N_MAX:
        return math.inf

    max_t = min(
        n,
        max(ARORA_GAUSSIAN_TAIL_MIN_MAX_T, math.ceil(8 * stddev)),
    )
    secret_equations = _arora_secret_equations(params)
    finite_m_log2 = _log2_int_like(params.m)
    best = math.inf
    for t in range(max(1, math.ceil(stddev)), max_t + 1):
        d = 2 * t + 1
        log2_mcan = _gaussian_tail_log2_mcan(stddev, t)
        if not _is_infinite(params.m) and log2_mcan > finite_m_log2:
            break
        m_can = _gaussian_tail_sample_count(log2_mcan)
        if m_can <= 0:
            continue
        dreg = _semi_regular_dreg(n, ((d, m_can),) + secret_equations)
        if dreg is None:
            continue
        best = min(best, omega * _log2_monomials(n, dreg))
    return best


def arora_quick_logrop(params: Any) -> float:
    """Return a quick Arora-GB log2 cost for smart-screen audit/calibration."""
    params = params.normalize()
    if bool(getattr(params.Xe, "is_bounded", False)):
        return _arora_quick_logrop_bounded(params)
    if bool(getattr(params.Xe, "is_Gaussian_like", False)):
        return _arora_quick_logrop_gaussian(params)
    return math.inf


def bkw_quick_logrop(params: Any) -> float:
    """Return a very rough optimistic BKW log2 cost for audit/calibration."""
    params = params.normalize()
    stddev = _finite_float(getattr(params.Xe, "stddev", None))
    if stddev is None or stddev <= 0:
        return math.inf
    logq = math.log2(int(params.q))
    logm = _log2_int_like(params.m)
    best = math.inf
    max_b = min(int(params.n), 64)
    for b in range(1, max_b + 1):
        blocks = math.ceil(params.n / b)
        log_table = b * logq
        log_sample_req = math.log2(max(1, blocks)) + log_table + 8
        if not _is_infinite(params.m) and logm < log_sample_req:
            continue
        log_sigma_eff = math.log2(stddev) + 0.5 * blocks
        if log_sigma_eff - logq > math.log2(0.25):
            continue
        best = min(best, math.log2(max(1, blocks)) + log_table)
    return best


def _decide_arora_gb(params: Any) -> SmartAttackDecision:
    """Decide whether SMART_EXACT should run Arora-GB."""
    params = params.normalize()
    quick = arora_quick_logrop(params)
    n = int(params.n)
    m = params.m
    xe = params.Xe

    if not _is_infinite(m) and int(m) <= n * n:
        return SmartAttackDecision(
            "arora-gb",
            False,
            "finite m <= n^2; Arora-GB is sample-starved for the smart exact profile",
            quick,
        )

    if bool(getattr(xe, "is_bounded", False)):
        d = _bounds_width(xe)
        if d is None:
            return SmartAttackDecision(
                "arora-gb",
                False,
                "Xe reports bounded but has no finite support width",
                quick,
            )
        if d <= ARORA_FORCE_RUN_BOUND_D:
            return SmartAttackDecision(
                "arora-gb",
                True,
                f"bounded Xe with small support width D={d}",
                quick,
                mode="run",
            )
        if d <= ARORA_CALIBRATION_BOUND_D and n <= ARORA_CALIBRATION_N_MAX:
            return SmartAttackDecision(
                "arora-gb",
                True,
                f"bounded Xe is near the smart threshold with D={d}; run for calibration",
                quick,
                mode="calibrate",
                calibration=True,
            )
        return SmartAttackDecision(
            "arora-gb",
            False,
            f"bounded Xe support width D={d} is outside the smart exact run window",
            quick,
        )

    if bool(getattr(xe, "is_Gaussian_like", False)):
        stddev = _finite_float(getattr(xe, "stddev", None))
        if (
            stddev is not None
            and n <= ARORA_SMALL_GAUSSIAN_N_MAX
            and stddev <= ARORA_SMALL_GAUSSIAN_STDDEV
        ):
            return SmartAttackDecision(
                "arora-gb",
                True,
                f"small Gaussian-like instance n={n}, stddev={stddev:.3g}",
                quick,
                mode="run",
            )
        if (
            stddev is not None
            and n <= ARORA_GAUSSIAN_CALIBRATION_N_MAX
            and stddev <= ARORA_GAUSSIAN_CALIBRATION_STDDEV
            and quick <= ARORA_GAUSSIAN_CALIBRATION_LOGROP_CAP
        ):
            return SmartAttackDecision(
                "arora-gb",
                True,
                (
                    f"small Gaussian-like borderline instance n={n}, "
                    f"stddev={stddev:.3g}; run for calibration"
                ),
                quick,
                mode="calibrate",
                calibration=True,
            )
        return SmartAttackDecision(
            "arora-gb",
            False,
            "Gaussian-like Xe outside the small-instance window; Arora-GB is usually slow and high-cost",
            quick,
        )

    return SmartAttackDecision(
        "arora-gb",
        False,
        "Xe is neither bounded nor Gaussian-like for the smart Arora-GB screen",
        quick,
    )


def _decide_bkw(params: Any) -> SmartAttackDecision:
    """Decide whether SMART_EXACT should run coded-BKW."""
    params = params.normalize()
    quick = bkw_quick_logrop(params)
    q = int(params.q)
    m = params.m

    if q <= BKW_SMALL_Q_FORCE:
        return SmartAttackDecision(
            "bkw",
            True,
            f"very small modulus q={q}",
            quick,
            mode="run",
        )
    if q <= BKW_MEDIUM_Q_FORCE and _is_infinite(m):
        return SmartAttackDecision(
            "bkw",
            True,
            f"small modulus q={q} with unlimited samples",
            quick,
            mode="run",
        )
    if (
        q <= BKW_CALIBRATION_Q_MAX
        and params.n <= BKW_CALIBRATION_N_MAX
        and quick <= BKW_CALIBRATION_LOGROP_CAP
    ):
        return SmartAttackDecision(
            "bkw",
            True,
            f"small borderline BKW instance n={params.n}, q={q}; run for calibration",
            quick,
            mode="calibrate",
            calibration=True,
        )
    return SmartAttackDecision(
        "bkw",
        False,
        "not small-q/LPN-like enough for SMART_EXACT to run coded-BKW",
        quick,
    )


def choose_smart_exact_attacks(params: Any) -> SmartAttackSelection:
    """Resolve SMART_EXACT expensive-attack decisions for one LWE parameter set."""
    decisions = {
        "arora-gb": _decide_arora_gb(params),
        "bkw": _decide_bkw(params),
    }
    deny = tuple(
        attack
        for attack in LWE_ESTIMATE_ATTACKS
        if attack in SMART_EXACT_EXPENSIVE_ATTACKS and not decisions[attack].required
    )
    return SmartAttackSelection(deny_list=deny, decisions=decisions)

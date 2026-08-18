"""Thin adapter over the pinned lattice-estimator API.

This module is imported only inside the killable Sage child process.
"""

from __future__ import annotations

import contextlib
import io
import math
import time
from decimal import Decimal, InvalidOperation
from typing import Any

from .models import (
    LWE_ATTACKS,
    NTRU_ATTACKS,
    Attack,
    AttackExecution,
    BooleanMetric,
    CenteredBinomial,
    ComputedOutcome,
    DecimalMetric,
    DiscreteGaussian,
    EstimateRequest,
    FailedOutcome,
    FixedWeightBinary,
    FixedWeightTernary,
    IntegerMetric,
    LweProblem,
    NormalizedMetric,
    NtruProblem,
    ResultRole,
    SisNorm,
    SisProblem,
    SparseTernary,
    TextMetric,
    UniformBinary,
    UniformInteger,
    UniformTernary,
    UnsupportedOutcome,
    WorkerResponse,
)
from .planner import resolve_plan

PUBLIC_TO_UPSTREAM = {
    Attack.ARORA_GB: "arora-gb",
    Attack.BKW: "bkw",
    Attack.USVP: "usvp",
    Attack.BDD: "bdd",
    Attack.BDD_HYBRID: "bdd_hybrid",
    Attack.BDD_MITM_HYBRID: "bdd_mitm_hybrid",
    Attack.DUAL: "dual",
    Attack.DUAL_HYBRID: "dual_hybrid",
    Attack.DSD: "dsd",
    Attack.LATTICE: "lattice",
}


def execute(request: EstimateRequest) -> WorkerResponse:
    """Execute one dependency-complete estimator plan in this Sage process."""

    started = time.monotonic()
    plan = resolve_plan(request.problem, request.target_attacks)
    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()
    try:
        with (
            contextlib.redirect_stdout(captured_stdout),
            contextlib.redirect_stderr(captured_stderr),
        ):
            raw_results = _run_estimator(request, plan.executed)
    except Exception as error:  # noqa: BLE001 - normalize the unstable upstream boundary
        audit = _audit_capture(captured_stdout, captured_stderr)
        audit["exception_type"] = type(error).__name__
        results = [
            AttackExecution(
                attack=attack,
                role=_role(attack, plan.target),
                outcome=FailedOutcome(
                    kind="failed",
                    code="estimator_exception",
                    message=str(error) or type(error).__name__,
                    retryable=False,
                    raw_result=audit,
                ),
            )
            for attack in plan.executed
        ]
    else:
        audit = _audit_capture(captured_stdout, captured_stderr)
        results = [
            _normalize_attack(attack, plan.target, raw_results, audit) for attack in plan.executed
        ]

    return WorkerResponse(
        plan=plan,
        results=results,
        duration_ms=max(0, round((time.monotonic() - started) * 1_000)),
    )


def _run_estimator(request: EstimateRequest, attacks: list[Attack]) -> dict[str, Any]:
    from estimator import LWE, NTRU, RC, SIS, Simulator  # type: ignore[import-not-found]

    cost_model = getattr(RC, request.models.cost_model.value)
    shape_model = getattr(Simulator, request.models.shape_model.value)
    requested = {PUBLIC_TO_UPSTREAM[attack] for attack in attacks}

    if isinstance(request.problem, LweProblem):
        from sage.all import oo  # type: ignore[import-not-found]

        problem = request.problem
        samples = oo if problem.samples.kind == "unlimited" else problem.samples.count
        params = LWE.Parameters(
            n=problem.dimension,
            q=int(problem.modulus),
            Xs=_distribution(problem.secret, problem.dimension),
            Xe=_distribution(problem.error, None),
            m=samples,
        )
        all_attacks = {PUBLIC_TO_UPSTREAM[item] for item in LWE_ATTACKS}
        return LWE.estimate(
            params,
            red_cost_model=cost_model,
            red_shape_model=shape_model,
            deny_list=tuple(sorted(all_attacks - requested)),
            jobs=1,
            catch_exceptions=True,
            quiet=True,
        )

    if isinstance(request.problem, NtruProblem):
        problem = request.problem
        params = NTRU.Parameters(
            n=problem.dimension,
            q=int(problem.modulus),
            Xs=_distribution(problem.secret, problem.dimension),
            Xe=_distribution(problem.error, None),
            m=problem.dimension,
            ntru_type=problem.structure.value,
        )
        all_attacks = {PUBLIC_TO_UPSTREAM[item] for item in NTRU_ATTACKS}
        return NTRU.estimate(
            params,
            red_cost_model=cost_model,
            red_shape_model=shape_model,
            deny_list=tuple(sorted(all_attacks - requested)),
            jobs=1,
            catch_exceptions=True,
            quiet=True,
        )

    if isinstance(request.problem, SisProblem):
        from sage.all import oo  # type: ignore[import-not-found]

        params = SIS.Parameters(
            n=request.problem.dimension,
            q=int(request.problem.modulus),
            length_bound=request.problem.length_bound,
            m=request.problem.columns,
            norm=2 if request.problem.norm is SisNorm.L2 else oo,
        )
        return SIS.estimate(
            params,
            red_cost_model=cost_model,
            red_shape_model=shape_model,
            deny_list=(),
            jobs=1,
            catch_exceptions=True,
            quiet=True,
        )

    raise AssertionError("strict request model admitted an unknown problem")


def _distribution(distribution: Any, logical_length: int | None) -> Any:
    from estimator import ND  # type: ignore[import-not-found]

    if isinstance(distribution, UniformBinary):
        return ND.Uniform(0, 1, n=logical_length)
    if isinstance(distribution, UniformTernary):
        return ND.Uniform(-1, 1, n=logical_length)
    if isinstance(distribution, SparseTernary):
        return ND.SparseTernary(
            distribution.positive_count,
            distribution.negative_count,
            n=logical_length,
        )
    if isinstance(distribution, FixedWeightBinary):
        return ND.SparseBinary(distribution.hamming_weight, n=logical_length)
    if isinstance(distribution, FixedWeightTernary):
        return ND.SparseTernary(
            distribution.positive_weight,
            distribution.negative_weight,
            n=logical_length,
        )
    if isinstance(distribution, DiscreteGaussian):
        return ND.DiscreteGaussian(distribution.standard_deviation, n=logical_length)
    if isinstance(distribution, CenteredBinomial):
        return ND.CenteredBinomial(distribution.eta, n=logical_length)
    if isinstance(distribution, UniformInteger):
        return ND.Uniform(int(distribution.lower), int(distribution.upper), n=logical_length)
    raise AssertionError(f"strict model admitted unsupported distribution {distribution.kind}")


def _normalize_attack(
    attack: Attack,
    targets: list[Attack],
    raw_results: dict[str, Any],
    audit: dict[str, Any],
) -> AttackExecution:
    upstream_name = PUBLIC_TO_UPSTREAM[attack]
    raw = raw_results.get(upstream_name)
    role = _role(attack, targets)
    if raw is None:
        return AttackExecution(
            attack=attack,
            role=role,
            outcome=FailedOutcome(
                kind="failed",
                code="estimator_no_result",
                message=f"estimator returned no result for {attack.value}",
                retryable=False,
                raw_result=audit,
            ),
        )

    rop = raw.get("rop") if hasattr(raw, "get") else None
    security_bits = _log2_cost(rop)
    if security_bits is None:
        return AttackExecution(
            attack=attack,
            role=role,
            outcome=UnsupportedOutcome(
                kind="unsupported",
                code="no_finite_rop",
                reason=f"{attack.value} returned no finite positive rop",
                raw_result={"result": _safe_text(raw), **audit},
            ),
        )

    metrics: dict[str, NormalizedMetric] = {}
    if hasattr(raw, "items"):
        for key, value in raw.items():
            if str(key) == "rop":
                continue
            metric = _normalize_metric(value)
            if metric is not None:
                metrics[str(key)] = metric
    return AttackExecution(
        attack=attack,
        role=role,
        outcome=ComputedOutcome(kind="computed", security_bits=security_bits, metrics=metrics),
    )


def _log2_cost(value: Any) -> str | None:
    if value is None:
        return None
    try:
        if value <= 0 or not math.isfinite(float(value)):
            return None
        from sage.all import log  # type: ignore[import-not-found]

        return _canonical_decimal(log(value, 2))
    except (ArithmeticError, TypeError, ValueError, OverflowError):
        return None


def _normalize_metric(value: Any) -> NormalizedMetric | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return BooleanMetric(kind="boolean", value=value)
    if isinstance(value, int):
        return IntegerMetric(kind="integer", value=str(value))
    try:
        numeric = float(value)
    except (TypeError, ValueError, OverflowError):
        return TextMetric(kind="text", value=_safe_text(value))
    if math.isfinite(numeric):
        return DecimalMetric(kind="decimal", value=_canonical_decimal(value))
    return TextMetric(kind="text", value=_safe_text(value))


def _canonical_decimal(value: Any) -> str:
    try:
        decimal = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError, OverflowError) as error:
        raise ValueError(f"cannot normalize finite decimal {value!r}") from error
    if not decimal.is_finite():
        raise ValueError("decimal is not finite")
    text = format(decimal, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    if text in {"-0", ""}:
        return "0"
    return text


def _role(attack: Attack, targets: list[Attack]) -> ResultRole:
    return ResultRole.TARGET if attack in targets else ResultRole.SUPPORT


def _audit_capture(stdout: io.StringIO, stderr: io.StringIO) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if stdout.getvalue():
        result["stdout"] = stdout.getvalue()[-16_384:]
    if stderr.getvalue():
        result["stderr"] = stderr.getvalue()[-16_384:]
    return result


def _safe_text(value: Any) -> str:
    try:
        return str(value)
    except Exception:  # noqa: BLE001 - audit normalization must not mask the primary error
        return f"<{type(value).__name__}>"

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest
from test_models import request_model

from estimator_api.adapter import _canonical_decimal, _distribution, _run_estimator
from estimator_api.models import (
    Attack,
    CenteredBinomial,
    DiscreteGaussian,
    FixedWeightBinary,
    FixedWeightTernary,
    SparseTernary,
    UniformBinary,
    UniformInteger,
    UniformTernary,
)


class FakeDistributionFactory:
    @staticmethod
    def Uniform(lower: int, upper: int, *, n: int | None) -> tuple[object, ...]:
        return ("uniform", lower, upper, n)

    @staticmethod
    def SparseBinary(weight: int, *, n: int | None) -> tuple[object, ...]:
        return ("sparse_binary", weight, n)

    @staticmethod
    def SparseTernary(positive: int, negative: int, *, n: int | None) -> tuple[object, ...]:
        return ("sparse_ternary", positive, negative, n)

    @staticmethod
    def DiscreteGaussian(standard_deviation: str, *, n: int | None) -> tuple[object, ...]:
        return ("discrete_gaussian", standard_deviation, n)

    @staticmethod
    def CenteredBinomial(eta: int, *, n: int | None) -> tuple[object, ...]:
        return ("centered_binomial", eta, n)


class FakeLwe:
    deny_list: tuple[str, ...] | None = None

    class Parameters:
        def __init__(self, **values: object) -> None:
            self.values = values

    @classmethod
    def estimate(cls, _parameters: object, **options: object) -> dict[str, object]:
        cls.deny_list = options["deny_list"]  # type: ignore[assignment]
        return {}


@pytest.fixture(autouse=True)
def fake_estimator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        sys.modules,
        "estimator",
        SimpleNamespace(
            ND=FakeDistributionFactory,
            LWE=FakeLwe,
            NTRU=object(),
            SIS=object(),
            RC=SimpleNamespace(BDGL16=object()),
            Simulator=SimpleNamespace(GSA=object()),
        ),
    )
    monkeypatch.setitem(sys.modules, "sage", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "sage.all", SimpleNamespace(oo=object()))


@pytest.mark.parametrize(
    ("model", "length", "expected"),
    [
        (UniformBinary(kind="uniform_binary"), 8, ("uniform", 0, 1, 8)),
        (UniformTernary(kind="uniform_ternary"), 9, ("uniform", -1, 1, 9)),
        (
            SparseTernary(kind="sparse_ternary", positive_count=2, negative_count=3),
            12,
            ("sparse_ternary", 2, 3, 12),
        ),
        (
            FixedWeightBinary(kind="fixed_weight_binary", hamming_weight=3),
            10,
            ("sparse_binary", 3, 10),
        ),
        (
            FixedWeightTernary(kind="fixed_weight_ternary", positive_weight=2, negative_weight=3),
            12,
            ("sparse_ternary", 2, 3, 12),
        ),
        (
            DiscreteGaussian(kind="discrete_gaussian", standard_deviation="3.25"),
            None,
            ("discrete_gaussian", "3.25", None),
        ),
        (
            CenteredBinomial(kind="centered_binomial", eta=4),
            None,
            ("centered_binomial", 4, None),
        ),
        (
            UniformInteger(kind="uniform_integer", lower="-2", upper="5"),
            None,
            ("uniform", -2, 5, None),
        ),
    ],
)
def test_distribution_mapping_preserves_parameters(
    model: object, length: int | None, expected: tuple[object, ...]
) -> None:
    assert _distribution(model, length) == expected


def test_canonical_decimal_does_not_round_through_binary_float() -> None:
    assert _canonical_decimal("12345678901234567890.123456789") == (
        "12345678901234567890.123456789"
    )
    assert _canonical_decimal("1.2300") == "1.23"
    assert _canonical_decimal("-0.0") == "0"


def test_fast_lwe_plan_denies_slow_upstream_attacks() -> None:
    request = request_model()
    _run_estimator(request, request.target_attacks)
    assert FakeLwe.deny_list == ("arora-gb", "bkw")


def test_adaptive_slow_plan_remains_callable() -> None:
    request = request_model().model_copy(update={"target_attacks": [Attack.ARORA_GB, Attack.BKW]})
    _run_estimator(request, request.target_attacks)
    assert FakeLwe.deny_list == (
        "bdd",
        "bdd_hybrid",
        "bdd_mitm_hybrid",
        "dual",
        "dual_hybrid",
        "usvp",
    )

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any


def load_tool() -> Any:
    path = Path(__file__).parents[1] / "tools" / "phase4_calibration.py"
    spec = importlib.util.spec_from_file_location("phase4_calibration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = load_tool()


def test_plan_expansion_is_a_cartesian_product() -> None:
    plan = {
        "format": tool.PLAN_FORMAT,
        "version": 1,
        "attacks": ["arora_gb", "bkw"],
        "timeout_seconds": 60,
        "models": [{"cost_model": "BDGL16", "shape_model": "GSA"}],
        "axes": {
            "dimension": [128, 256],
            "modulus": ["4096"],
            "samples": [{"kind": "unlimited"}],
            "secret": [{"kind": "uniform_binary"}],
            "error_standard_deviation": ["2", "4"],
        },
    }
    requests = list(tool.requests_from_plan(plan))
    assert len(requests) == 8
    assert {request["target_attacks"][0] for request in requests} == {"arora_gb", "bkw"}


def test_checked_in_v1_plan_has_buildable_holdout_groups() -> None:
    root = Path(__file__).parents[2]
    plan = json.loads(
        (root / "calibration" / "plans" / "slow-attacks-v1.json").read_text(encoding="utf-8")
    )
    groups: dict[str, list[dict[str, Any]]] = {}
    requests = list(tool.requests_from_plan(plan))
    for request in requests:
        identity_payload = {
            key: value for key, value in request.items() if key != "timeout_seconds"
        }
        value = {
            "identity": tool.sha256_identity(identity_payload),
            "request": request,
            "outcome": {"kind": "computed", "security_bits": "128"},
        }
        groups.setdefault(tool.group_key(value), []).append(value)

    assert len(requests) == 640
    assert len(groups) == 4
    assert max(request["problem"]["dimension"] for request in requests) == 2**16
    assert {request["models"]["cost_model"] for request in requests} == {"BDGL16"}
    assert all(
        tool.build_group(key, values, neighbor_count=4, cushion=2.0)["holdout"]["samples"] >= 4
        for key, values in groups.items()
    )


def observation(
    identity_prefix: str,
    dimension: int,
    modulus: int,
    sigma: int,
    security_bits: float,
) -> dict[str, Any]:
    return {
        "identity": f"sha256:{identity_prefix}{'0' * 56}",
        "request": {
            "problem": {
                "kind": "lwe",
                "dimension": dimension,
                "modulus": str(modulus),
                "samples": {"kind": "unlimited"},
                "secret": {"kind": "uniform_binary"},
                "error": {"kind": "discrete_gaussian", "standard_deviation": str(sigma)},
            },
            "models": {"cost_model": "BDGL16", "shape_model": "GSA"},
            "target_attacks": ["bkw"],
        },
        "outcome": {"kind": "computed", "security_bits": str(security_bits)},
    }


def test_builder_records_holdout_error_and_positive_safety_margin() -> None:
    training = [
        observation("10000001", 128, 4096, 2, 70),
        observation("10000004", 1024, 65536, 8, 150),
        observation("10000007", 256, 8192, 4, 90),
        observation("1000000a", 512, 32768, 4, 120),
        observation("1000000d", 384, 16384, 2, 105),
        observation("10000010", 768, 32768, 8, 135),
    ]
    holdouts = [
        observation(prefix, 256 + index * 64, 8192, 4, 92 + index * 4)
        for index, prefix in enumerate(["00000000", "00000003", "00000006", "00000009"], start=1)
    ]
    values = training + holdouts
    group = tool.build_group(tool.group_key(values[0]), values, neighbor_count=2, cushion=2.0)
    assert group["holdout"]["samples"] == 4
    assert float(group["safety_margin_bits"]) >= 2.0
    assert len(group["points"]) == len(training)
    assert group["sample_mode"] == "unlimited"


def test_observation_reader_ignores_failed_rows_and_deduplicates(tmp_path: Path) -> None:
    computed = observation("10000001", 128, 4096, 2, 70)
    computed.update(
        {
            "format": tool.OBSERVATION_FORMAT,
            "version": 1,
            "provenance": {},
        }
    )
    failed = json.loads(json.dumps(computed))
    failed["identity"] = "sha256:failed"
    failed["outcome"] = {"kind": "failed"}
    path = tmp_path / "observations.jsonl"
    path.write_text(
        "\n".join([tool.canonical_json(computed), tool.canonical_json(failed)]) + "\n",
        encoding="utf-8",
    )
    assert tool.read_computed_observations([path]) == [computed]


def test_resume_retries_transient_rows_but_skips_terminal_rows(tmp_path: Path) -> None:
    rows = [
        {
            "identity": "computed",
            "outcome": {"kind": "computed", "security_bits": "80"},
        },
        {
            "identity": "unsupported",
            "outcome": {"kind": "unsupported", "reason": "not available"},
        },
        {
            "identity": "retry",
            "outcome": {"kind": "failed", "retryable": True},
        },
        {
            "identity": "terminal",
            "outcome": {"kind": "failed", "retryable": False},
        },
    ]
    path = tmp_path / "observations.jsonl"
    path.write_text(
        "\n".join(tool.canonical_json(row) for row in rows) + "\n",
        encoding="utf-8",
    )
    assert tool.existing_identities(path) == {"computed", "unsupported", "terminal"}

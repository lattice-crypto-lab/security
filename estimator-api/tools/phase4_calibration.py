#!/usr/bin/env python3
"""Collect slow-attack observations and build a conservative v1 model.

The collector talks only to estimator-api's internal contract. The builder uses
deterministic interior holdouts, inverse-distance weighting, and an empirical
overestimate margin plus a configurable safety cushion. Its output is an
engineering estimate, not a mathematical lower-bound proof.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PLAN_FORMAT = "lattice-security/slow-attack-calibration-plan"
OBSERVATION_FORMAT = "lattice-security/slow-attack-observation"
MODEL_FORMAT = "lattice-security/slow-attack-model"
FEATURE_SCHEMA = "lwe-log2-v1"
VERSION = 1
SLOW_ATTACKS = {"arora_gb", "bkw"}
POINT_FIELDS = {
    "dimension",
    "modulus",
    "samples",
    "secret",
    "error_standard_deviation",
}
PROVENANCE_FIELDS = (
    "estimator_commit",
    "sage_version",
    "adapter_version",
    "worker_image",
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_identity(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


def decimal_string(value: float, digits: int = 9) -> str:
    if not math.isfinite(value):
        raise ValueError("model values must be finite")
    rendered = f"{value:.{digits}f}".rstrip("0").rstrip(".")
    return "0" if rendered in {"", "-0"} else rendered


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as target:
        json.dump(value, target, ensure_ascii=False, sort_keys=True, indent=2)
        target.write("\n")


def validate_plan(plan: dict[str, Any]) -> None:
    if plan.get("format") != PLAN_FORMAT or plan.get("version") != VERSION:
        raise ValueError("unsupported calibration plan")
    axes = plan.get("axes")
    if not isinstance(axes, dict):
        raise TypeError("plan.axes must be an object")
    required = ["dimension", "modulus", "samples", "secret", "error_standard_deviation"]
    if any(not isinstance(axes.get(name), list) or not axes[name] for name in required):
        raise ValueError(f"plan axes must contain non-empty lists: {', '.join(required)}")
    attacks = plan.get("attacks")
    if not isinstance(attacks, list) or not attacks or not set(attacks) <= SLOW_ATTACKS:
        raise ValueError("plan.attacks must contain only arora_gb and/or bkw")
    models = plan.get("models")
    if not isinstance(models, list) or not models:
        raise ValueError("plan.models must be a non-empty list")
    timeout = plan.get("timeout_seconds")
    if not isinstance(timeout, int) or not 1 <= timeout <= 7200:
        raise ValueError("timeout_seconds must be in 1..=7200")
    points = plan.get("points", [])
    if not isinstance(points, list):
        raise TypeError("plan.points must be a list")
    for index, point in enumerate(points):
        if not isinstance(point, dict) or set(point) != POINT_FIELDS:
            raise ValueError(
                f"plan.points[{index}] must contain exactly: {', '.join(sorted(POINT_FIELDS))}"
            )


def requests_from_plan(plan: dict[str, Any]) -> Iterable[dict[str, Any]]:
    validate_plan(plan)
    axes = plan["axes"]
    grid_points = (
        {
            "dimension": dimension,
            "modulus": modulus,
            "samples": samples,
            "secret": secret,
            "error_standard_deviation": sigma,
        }
        for dimension, modulus, samples, secret, sigma in itertools.product(
            axes["dimension"],
            axes["modulus"],
            axes["samples"],
            axes["secret"],
            axes["error_standard_deviation"],
        )
    )
    seen: set[str] = set()
    for point in itertools.chain(grid_points, plan.get("points", [])):
        for attack, models in itertools.product(plan["attacks"], plan["models"]):
            request = {
                "schema_version": 2,
                "problem": {
                    "kind": "lwe",
                    "dimension": point["dimension"],
                    "modulus": str(point["modulus"]),
                    "samples": point["samples"],
                    "secret": point["secret"],
                    "error": {
                        "kind": "discrete_gaussian",
                        "standard_deviation": str(point["error_standard_deviation"]),
                    },
                },
                "models": models,
                "target_attacks": [attack],
                "timeout_seconds": plan["timeout_seconds"],
            }
            identity = sha256_identity(
                {key: value for key, value in request.items() if key != "timeout_seconds"}
            )
            if identity not in seen:
                seen.add(identity)
                yield request


def existing_identities(path: Path) -> set[str]:
    if not path.exists():
        return set()
    identities = set()
    with path.open(encoding="utf-8") as source:
        for line in source:
            if line.strip():
                value = json.loads(line)
                outcome = value.get("outcome", {})
                kind = outcome.get("kind")
                if kind in {"computed", "no_finite_estimate", "unsupported"} or (
                    kind == "failed" and not outcome.get("retryable", False)
                ):
                    identities.add(value["identity"])
    return identities


def get_json(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=30) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise TypeError(f"expected a JSON object from {url}")
    return value


def provenance_context(value: dict[str, Any]) -> dict[str, str]:
    context = {field: value.get(field) for field in PROVENANCE_FIELDS}
    if not all(isinstance(item, str) and item for item in context.values()):
        raise ValueError("estimator metadata is missing calibration provenance")
    return context  # type: ignore[return-value]


def observation_identity(request: dict[str, Any], context: dict[str, str]) -> str:
    normalized_request = {key: value for key, value in request.items() if key != "timeout_seconds"}
    return sha256_identity({"request": normalized_request, "estimator_context": context})


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=canonical_json(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=payload["timeout_seconds"] + 30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        raise RuntimeError(f"estimator-api returned {error.code}: {detail}") from error


def collect(plan_path: Path, output: Path, estimator_url: str) -> None:
    plan = load_json(plan_path)
    completed = existing_identities(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    base_url = estimator_url.rstrip("/")
    endpoint = base_url + "/v1/estimate"
    context = provenance_context(get_json(base_url + "/v1/metadata"))
    requests = list(requests_from_plan(plan))
    with output.open("a", encoding="utf-8", newline="\n") as target:
        for index, request in enumerate(requests, start=1):
            identity = observation_identity(request, context)
            if identity in completed:
                continue
            print(
                f"[{index}/{len(requests)}] {request['target_attacks'][0]} {identity}",
                flush=True,
            )
            collected_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            try:
                response = post_json(endpoint, request)
                if provenance_context(response["provenance"]) != context:
                    raise ValueError("estimate provenance changed during calibration collection")
                result = next(
                    item
                    for item in response["results"]
                    if item["role"] == "target" and item["attack"] == request["target_attacks"][0]
                )
                observation = {
                    "format": OBSERVATION_FORMAT,
                    "version": VERSION,
                    "identity": identity,
                    "request": request,
                    "outcome": result["outcome"],
                    "duration_ms": response["duration_ms"],
                    "provenance": response["provenance"],
                    "collected_at": collected_at,
                }
            except (
                KeyError,
                RuntimeError,
                StopIteration,
                TimeoutError,
                TypeError,
                ValueError,
                urllib.error.URLError,
            ) as error:
                observation = {
                    "format": OBSERVATION_FORMAT,
                    "version": VERSION,
                    "identity": identity,
                    "request": request,
                    "outcome": {
                        "kind": "failed",
                        "code": "collector_error",
                        "message": str(error),
                        "retryable": True,
                    },
                    "duration_ms": 0,
                    "provenance": None,
                    "collected_at": collected_at,
                }
            target.write(canonical_json(observation) + "\n")
            target.flush()


def read_computed_observations(paths: list[Path]) -> list[dict[str, Any]]:
    observations: dict[str, dict[str, Any]] = {}
    for path in paths:
        with path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if value.get("format") != OBSERVATION_FORMAT or value.get("version") != VERSION:
                    raise ValueError(f"{path}:{line_number}: unsupported observation")
                if value["outcome"].get("kind") == "computed":
                    observations[value["identity"]] = value
    return sorted(observations.values(), key=lambda item: item["identity"])


def feature_vector(observation: dict[str, Any]) -> list[float]:
    problem = observation["request"]["problem"]
    values = [
        math.log2(int(problem["dimension"])),
        math.log2(int(problem["modulus"])),
        math.log2(float(problem["error"]["standard_deviation"])),
    ]
    if problem["samples"]["kind"] == "finite":
        values.append(math.log2(int(problem["samples"]["count"])))
    return values


def group_key(observation: dict[str, Any]) -> str:
    request = observation["request"]
    problem = request["problem"]
    key = {
        "attack": request["target_attacks"][0],
        "models": request["models"],
        "secret": problem["secret"],
        "sample_mode": problem["samples"]["kind"],
    }
    return canonical_json(key)


def ranges(vectors: list[list[float]]) -> list[tuple[float, float]]:
    return [(min(values), max(values)) for values in zip(*vectors, strict=True)]


def inside(vector: list[float], domain: list[tuple[float, float]]) -> bool:
    return all(
        minimum <= value <= maximum
        for value, (minimum, maximum) in zip(vector, domain, strict=True)
    )


def distance(left: list[float], right: list[float], domain: list[tuple[float, float]]) -> float:
    total = 0.0
    for left_value, right_value, (minimum, maximum) in zip(left, right, domain, strict=True):
        width = abs(maximum - minimum) or 1.0
        total += ((left_value - right_value) / width) ** 2
    return math.sqrt(total)


def raw_prediction(
    vector: list[float],
    training: list[tuple[list[float], float]],
    domain: list[tuple[float, float]],
    neighbors: int,
) -> tuple[float, float]:
    ranked = sorted((distance(vector, point, domain), security) for point, security in training)
    nearest = ranked[0][0]
    if nearest <= sys.float_info.epsilon:
        return ranked[0][1], nearest
    weighted = total_weight = 0.0
    for point_distance, security in ranked[:neighbors]:
        weight = 1.0 / max(point_distance, 1e-12) ** 2
        weighted += security * weight
        total_weight += weight
    return weighted / total_weight, nearest


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * fraction) - 1)
    return ordered[index]


def is_boundary(vector: list[float], all_ranges: list[tuple[float, float]]) -> bool:
    return any(
        value == minimum or value == maximum
        for value, (minimum, maximum) in zip(vector, all_ranges, strict=True)
    )


def build_group(
    key: str,
    observations: list[dict[str, Any]],
    neighbor_count: int,
    cushion: float,
) -> dict[str, Any]:
    enriched = [
        (
            observation,
            feature_vector(observation),
            float(observation["outcome"]["security_bits"]),
        )
        for observation in observations
    ]
    all_ranges = ranges([item[1] for item in enriched])
    training_items = []
    holdout_items = []
    for item in enriched:
        bucket = int(item[0]["identity"].split(":", 1)[1][:8], 16) % 3
        if bucket == 0 and not is_boundary(item[1], all_ranges):
            holdout_items.append(item)
        else:
            training_items.append(item)
    if len(holdout_items) < 4:
        raise ValueError(f"group {key} has fewer than four interior holdout samples")
    if len(training_items) < neighbor_count:
        raise ValueError(f"group {key} has fewer training points than neighbor_count")
    domain = ranges([item[1] for item in training_items])
    training = [(item[1], item[2]) for item in training_items]
    errors = []
    overestimates = []
    nearest_distances = []
    for _, vector, actual in holdout_items:
        if not inside(vector, domain):
            continue
        predicted, nearest = raw_prediction(vector, training, domain, neighbor_count)
        errors.append(abs(predicted - actual))
        overestimates.append(predicted - actual)
        nearest_distances.append(nearest)
    if len(errors) < 4:
        raise ValueError(f"group {key} has fewer than four holdouts inside the training domain")
    maximum_overestimate = max(overestimates)
    safety_margin = max(0.0, maximum_overestimate) + cushion
    selector = json.loads(key)
    names = ["log2_dimension", "log2_modulus", "log2_error_standard_deviation"]
    if selector["sample_mode"] == "finite":
        names.append("log2_samples")
    domain_json = {
        name: {"min": decimal_string(bounds[0]), "max": decimal_string(bounds[1])}
        for name, bounds in zip(names, domain, strict=True)
    }
    points = []
    for _, vector, security in training_items:
        point = {name: decimal_string(value) for name, value in zip(names, vector, strict=True)}
        point["security_bits"] = decimal_string(security)
        points.append(point)
    return {
        "id": sha256_identity(selector)[7:23],
        "attack": selector["attack"],
        "security_model": (
            "classical" if selector["models"]["cost_model"] == "BDGL16" else "quantum"
        ),
        "cost_model": selector["models"]["cost_model"],
        "shape_model": selector["models"]["shape_model"],
        "secret": selector["secret"],
        "sample_mode": selector["sample_mode"],
        "domain": domain_json,
        "neighbor_count": neighbor_count,
        "max_normalized_distance": decimal_string(max(max(nearest_distances) * 1.1, 0.000001)),
        "safety_margin_bits": decimal_string(safety_margin),
        "holdout": {
            "samples": len(errors),
            "mean_absolute_error_bits": decimal_string(sum(errors) / len(errors)),
            "p95_absolute_error_bits": decimal_string(percentile(errors, 0.95)),
            "max_overestimate_bits": decimal_string(maximum_overestimate),
        },
        "points": points,
    }


def common_provenance(observations: list[dict[str, Any]]) -> dict[str, Any]:
    provenances = {
        canonical_json(
            {
                "estimator_commit": item["provenance"]["estimator_commit"],
                "sage_version": item["provenance"]["sage_version"],
                "adapter_version": item["provenance"]["adapter_version"],
                "worker_image": item["provenance"]["worker_image"],
            }
        )
        for item in observations
    }
    if len(provenances) != 1:
        raise ValueError("observations mix estimator provenance")
    return json.loads(provenances.pop())


def build(
    inputs: list[Path],
    output: Path,
    model_id: str,
    neighbor_count: int,
    cushion: float,
) -> None:
    observations = read_computed_observations(inputs)
    if not observations:
        raise ValueError("no computed observations found")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for observation in observations:
        grouped[group_key(observation)].append(observation)
    groups = [
        build_group(key, values, neighbor_count, cushion) for key, values in sorted(grouped.items())
    ]
    provenance = common_provenance(observations)
    provenance.update(
        {
            "platform": "linux/amd64",
            "dataset_hash": sha256_identity(observations),
        }
    )
    model = {
        "format": MODEL_FORMAT,
        "version": VERSION,
        "model_id": model_id,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "feature_schema": FEATURE_SCHEMA,
        "provenance": provenance,
        "groups": groups,
    }
    write_json(output, model)
    print(f"wrote {len(groups)} calibrated groups to {output}")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    collect_parser = commands.add_parser("collect")
    collect_parser.add_argument("--plan", type=Path, required=True)
    collect_parser.add_argument("--output", type=Path, required=True)
    collect_parser.add_argument("--estimator-url", default="http://estimator-api:8000")
    build_parser = commands.add_parser("build")
    build_parser.add_argument("--input", type=Path, action="append", required=True)
    build_parser.add_argument("--output", type=Path, required=True)
    build_parser.add_argument("--model-id", default="slow-attacks-v1")
    build_parser.add_argument("--neighbors", type=int, default=4)
    build_parser.add_argument("--safety-cushion-bits", type=float, default=2.0)
    return root


def main() -> None:
    arguments = parser().parse_args()
    if arguments.command == "collect":
        collect(arguments.plan, arguments.output, arguments.estimator_url)
    else:
        if arguments.neighbors < 1 or arguments.safety_cushion_bits <= 0:
            raise ValueError("neighbors and safety cushion must be positive")
        build(
            arguments.input,
            arguments.output,
            arguments.model_id,
            arguments.neighbors,
            arguments.safety_cushion_bits,
        )


if __name__ == "__main__":
    main()

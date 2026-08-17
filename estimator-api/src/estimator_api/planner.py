"""Resolve target attacks and the pinned estimator dependency closure."""

from __future__ import annotations

from .constants import DEPENDENCY_GRAPH_VERSION
from .models import DEPENDENCY_GRAPH, Attack, AttackPlan, EstimatorProblem, attacks_for_problem


def resolve_plan(problem: EstimatorProblem, targets: list[Attack]) -> AttackPlan:
    target_set = set(targets)
    closure = set(targets)
    pending = list(targets)
    while pending:
        attack = pending.pop()
        for dependency in DEPENDENCY_GRAPH.get(attack, ()):
            if dependency not in closure:
                closure.add(dependency)
                pending.append(dependency)

    order = attacks_for_problem(problem)
    executed = [attack for attack in order if attack in closure]
    return AttackPlan(
        dependency_graph_version=DEPENDENCY_GRAPH_VERSION,
        target=[attack for attack in order if attack in target_set],
        support=[attack for attack in executed if attack not in target_set],
        executed=executed,
    )

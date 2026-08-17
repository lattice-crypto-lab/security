from __future__ import annotations

import json
import os
import subprocess
import sys
import time

from estimator_api.models import (
    AttackExecution,
    ComputedOutcome,
    EstimateRequest,
    ResultRole,
    WorkerResponse,
)
from estimator_api.planner import resolve_plan


def main() -> int:
    mode = sys.argv[1]
    payload = sys.stdin.buffer.read()
    request = EstimateRequest.model_validate_json(payload)
    if mode == "sleep":
        time.sleep(60)
        return 0
    if mode == "spawn-child":
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        pid_file = os.environ["MOCK_CHILD_PID_FILE"]
        with open(pid_file, "w", encoding="ascii") as output:
            output.write(str(child.pid))
        time.sleep(60)
        return 0
    if mode == "malformed":
        print("not-json")
        return 0
    if mode == "fail":
        print(json.dumps({"code": "mock_failure"}), file=sys.stderr)
        return 7

    plan = resolve_plan(request.problem, request.target_attacks)
    targets = set(plan.target)
    response = WorkerResponse(
        plan=plan,
        results=[
            AttackExecution(
                attack=attack,
                role=ResultRole.TARGET if attack in targets else ResultRole.SUPPORT,
                outcome=ComputedOutcome(kind="computed", security_bits="128", metrics={}),
            )
            for attack in plan.executed
        ],
        duration_ms=1,
    )
    print(response.model_dump_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

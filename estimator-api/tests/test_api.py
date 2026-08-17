from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from test_models import request_data

from estimator_api.app import Settings, create_app
from estimator_api.constants import ESTIMATOR_COMMIT, REQUEST_BODY_LIMIT_BYTES
from estimator_api.process import ProcessSettings

MOCK_WORKER = Path(__file__).with_name("mock_worker.py")


def test_health_metadata_and_estimate_contracts() -> None:
    settings = Settings(
        process=ProcessSettings(
            command=(sys.executable, str(MOCK_WORKER), "success"),
            cleanup_grace_seconds=0.1,
        )
    )
    with TestClient(create_app(settings)) as client:
        health = client.get("/healthz")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        metadata = client.get("/v1/metadata")
        assert metadata.status_code == 200
        assert metadata.json()["estimator_commit"] == ESTIMATOR_COMMIT
        assert metadata.json()["adaptive_attacks"] == ["arora_gb", "bkw"]

        response = client.post("/v1/estimate", json=request_data())
        assert response.status_code == 200, response.text
        assert [item["attack"] for item in response.json()["results"]] == [
            "usvp",
            "bdd",
            "bdd_hybrid",
            "bdd_mitm_hybrid",
            "dual",
            "dual_hybrid",
        ]
        assert response.json()["plan"]["support"] == []
        assert response.json()["provenance"]["estimator_commit"] == ESTIMATOR_COMMIT


def test_validation_error_uses_worker_error_envelope() -> None:
    settings = Settings(
        process=ProcessSettings(command=(sys.executable, str(MOCK_WORKER), "success"))
    )
    source = request_data()
    source["problem"]["modulus"] = 65536  # type: ignore[index]
    with TestClient(create_app(settings)) as client:
        response = client.post("/v1/estimate", json=source)
    assert response.status_code == 422
    assert response.json()["code"] == "invalid_request"
    assert response.json()["path"].endswith("modulus")


def test_request_body_limit_precedes_json_parsing() -> None:
    settings = Settings(
        process=ProcessSettings(command=(sys.executable, str(MOCK_WORKER), "success"))
    )
    oversized = json.dumps({"padding": "x" * REQUEST_BODY_LIMIT_BYTES})
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/v1/estimate",
            content=oversized,
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 413
    assert response.json()["code"] == "request_body_too_large"

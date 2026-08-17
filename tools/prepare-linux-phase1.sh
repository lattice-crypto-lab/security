#!/usr/bin/env bash
set -euo pipefail

readonly expected_commit="6019056011d10d7e9c30a0d5da2d2f729fbc2eec"

git submodule update --init --recursive
actual_commit="$(git -C estimator rev-parse HEAD)"
if [[ "${actual_commit}" != "${expected_commit}" ]]; then
  echo "estimator commit mismatch: expected ${expected_commit}, got ${actual_commit}" >&2
  exit 1
fi

echo "estimator Gitlink verified: ${actual_commit}"
echo "build with: docker build --platform linux/amd64 -f estimator-api/Dockerfile ."

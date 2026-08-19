#!/usr/bin/env bash
set -euo pipefail

git submodule update --init --recursive
expected_commit="$(git ls-tree HEAD estimator | awk '{print $3}')"
actual_commit="$(git -C estimator rev-parse HEAD)"
if [[ -z "${expected_commit}" || "${actual_commit}" != "${expected_commit}" ]]; then
  echo "estimator Gitlink mismatch: expected ${expected_commit:-missing}, got ${actual_commit}" >&2
  exit 1
fi
echo "estimator Gitlink verified: ${actual_commit}"

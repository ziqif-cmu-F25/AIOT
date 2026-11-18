#!/bin/bash
# Prove the exact-buffer ASan oracle distinguishes 7.21 vs 7.22 logic.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
evidence="${root}/results/acceptance"
mkdir -p "${evidence}"
body="${evidence}/oracle-smoke-body.bin"
# 2 hex digits + CR only -> len == i+1 == 3 (trigger class)
printf 'ab\r' > "${body}"
chmod +x "${root}/evaluator/oracle/run_oracle.sh"
if "${root}/evaluator/oracle/run_oracle.sh" "${body}"; then
  echo "oracle-smoke PASS" | tee "${evidence}/oracle-smoke.txt"
  exit 0
fi
echo "oracle-smoke FAIL" | tee "${evidence}/oracle-smoke.txt"
exit 1

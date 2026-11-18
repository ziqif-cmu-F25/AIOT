#!/bin/bash
# Build and run the exact-buffer ASan oracle inside the evaluator image, or
# via a one-shot Docker build. Host usage from personal-stage2/:
#   ./evaluator/oracle/run_oracle.sh <body-file>
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
body="${1:?body file required}"
body="$(cd "$(dirname "${body}")" && pwd)/$(basename "${body}")"
out_dir="${root}/results/acceptance/oracle"
mkdir -p "${out_dir}"

docker build \
  -f "${root}/evaluator/oracle/Dockerfile" \
  -t mongoose-ps2-oracle:local \
  "${root}/evaluator/oracle" \
  > "${out_dir}/oracle-build.log" 2>&1

echo "=== vulnerable 7.21 logic ===" | tee "${out_dir}/oracle-vuln.log"
set +e
docker run --rm -v "${body}:/body.bin:ro" mongoose-ps2-oracle:local \
  /oracle/skip_chunk_oracle 721 /body.bin \
  >> "${out_dir}/oracle-vuln.log" 2>&1
vuln_rc=$?
set -e
echo "vuln_exit=${vuln_rc}" | tee -a "${out_dir}/oracle-vuln.log"

echo "=== fixed 7.22 logic ===" | tee "${out_dir}/oracle-fixed.log"
set +e
docker run --rm -v "${body}:/body.bin:ro" mongoose-ps2-oracle:local \
  /oracle/skip_chunk_oracle 722 /body.bin \
  >> "${out_dir}/oracle-fixed.log" 2>&1
fixed_rc=$?
set -e
echo "fixed_exit=${fixed_rc}" | tee -a "${out_dir}/oracle-fixed.log"

# ASan typically exits non-zero on OOB; fixed should be 0.
if grep -qi 'AddressSanitizer\|heap-buffer-overflow\|stack-buffer-overflow' \
    "${out_dir}/oracle-vuln.log" \
  && ! grep -qi 'AddressSanitizer\|heap-buffer-overflow\|stack-buffer-overflow' \
    "${out_dir}/oracle-fixed.log" \
  && [ "${fixed_rc}" -eq 0 ]; then
  echo "ORACLE_MATCH=yes" | tee "${out_dir}/oracle-verdict.txt"
  exit 0
fi

echo "ORACLE_MATCH=no" | tee "${out_dir}/oracle-verdict.txt"
exit 1

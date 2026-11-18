#!/bin/bash
# Record frozen build facts. Intended to run during image build.
set -euo pipefail

out="${1:-/opt/lab/environment-manifest.txt}"
mkdir -p "$(dirname "${out}")"

{
  echo "manifest_generated_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname=$(uname -a)"
  echo "arch=$(uname -m)"
  echo "os=$({ . /etc/os-release; echo "${PRETTY_NAME}"; })"
  echo "mongoose_commit=${MONGOOSE_COMMIT:-unset}"
  echo "mongoose_tag=${MONGOOSE_TAG:-unset}"
  echo "mongoose_variant=${MONGOOSE_VARIANT:-vulnerable}"
  if command -v gcc >/dev/null 2>&1; then
    echo "gcc=$(gcc --version | head -n 1)"
  fi
  if command -v clang >/dev/null 2>&1; then
    echo "clang=$(clang --version | head -n 1)"
  fi
  if command -v gdb >/dev/null 2>&1; then
    echo "gdb=$(gdb --version | head -n 1)"
  fi
  if command -v python3 >/dev/null 2>&1; then
    echo "python3=$(python3 --version)"
  fi
  if command -v mongoose-http-server >/dev/null 2>&1; then
    echo "mongoose_http_server_path=$(command -v mongoose-http-server)"
  fi
} > "${out}"

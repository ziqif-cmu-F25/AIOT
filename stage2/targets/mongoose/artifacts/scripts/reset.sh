#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${root}"
profile="${1:?usage: reset.sh blackbox|whitebox|evaluator}"
docker compose --profile "${profile}" down --volumes --remove-orphans
case "${profile}" in
  blackbox)
    rm -rf "${root}/results/blackbox/"* "${root}/workspaces/blackbox/scratch/"*
    mkdir -p "${root}/results/blackbox" "${root}/workspaces/blackbox/scratch"
    touch "${root}/results/blackbox/.gitkeep"
    ;;
  whitebox)
    rm -rf "${root}/results/whitebox/"* "${root}/workspaces/whitebox/scratch/"*
    mkdir -p "${root}/results/whitebox" "${root}/workspaces/whitebox/scratch"
    touch "${root}/results/whitebox/.gitkeep"
    ;;
  evaluator)
    ;;
  *)
    echo "unknown profile: ${profile}" >&2
    exit 1
    ;;
esac

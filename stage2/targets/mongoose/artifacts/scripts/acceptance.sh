#!/bin/bash
# Personal Stage 2 acceptance: build, normal request, replay, oracle differential.
set -u
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "${root}"
evidence="${root}/results/acceptance"
mkdir -p "${evidence}"
status_file="${evidence}/summary.txt"
: > "${status_file}"

pass_count=0
fail_count=0
blocked_count=0

record() {
  local id="$1"
  local status="$2"
  local command="$3"
  local notes="$4"
  printf '%s %s\ncommand: %s\nnotes: %s\n\n' "${id}" "${status}" "${command}" "${notes}" \
    | tee -a "${status_file}"
  case "${status}" in
    PASS) pass_count=$((pass_count + 1)) ;;
    FAIL) fail_count=$((fail_count + 1)) ;;
    BLOCKED) blocked_count=$((blocked_count + 1)) ;;
  esac
}

docker_ready() {
  docker info >/dev/null 2>&1
}

stop_all() {
  docker compose --profile blackbox down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker compose --profile whitebox down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker compose --profile evaluator down --volumes --remove-orphans >/dev/null 2>&1 || true
}

if ! docker_ready; then
  record PS2-01 BLOCKED "docker info" "Docker daemon is not running"
  exit 1
fi
record PS2-00 PASS "docker info" "Docker daemon reachable"

stop_all

if docker compose --profile blackbox build \
    > "${evidence}/ps2-01-blackbox-build.log" 2>&1; then
  record PS2-01 PASS "docker compose --profile blackbox build" \
    "See ps2-01-blackbox-build.log"
else
  record PS2-01 FAIL "docker compose --profile blackbox build" \
    "See ps2-01-blackbox-build.log"
fi

if [ "${fail_count}" -eq 0 ]; then
  if docker compose --profile blackbox up -d --wait --wait-timeout 180 \
      > "${evidence}/ps2-02-up.log" 2>&1; then
    record PS2-02 PASS "compose up blackbox --wait" "See ps2-02-up.log"
  else
    record PS2-02 FAIL "compose up blackbox --wait" "See ps2-02-up.log"
  fi
else
  record PS2-02 BLOCKED "n/a" "blocked by build failure"
fi

if [ "${fail_count}" -eq 0 ]; then
  if docker compose --profile blackbox exec -T blackbox \
      python3 /opt/lab/tools/http_client.py send \
        --input /opt/lab/tools/inputs/get_root.http \
        --output-dir /workspace/results/acceptance-smoke \
        --stem get-root \
      > "${evidence}/ps2-03-send.json" 2> "${evidence}/ps2-03-send.err"; then
    if grep -q '"timed_out": false' "${evidence}/ps2-03-send.json" \
      && grep -q '"response_len":' "${evidence}/ps2-03-send.json" \
      && grep -E -q '"response_len": [1-9]' "${evidence}/ps2-03-send.json"; then
      record PS2-03 PASS "http_client.py send get_root.http" \
        "ordinary GET answered; see ps2-03-send.json"
    else
      record PS2-03 FAIL "http_client.py send get_root.http" \
        "no usable HTTP response; see ps2-03-send.json"
    fi
  else
    record PS2-03 FAIL "http_client.py send get_root.http" \
      "client failed; see ps2-03-send.err"
  fi
else
  record PS2-03 BLOCKED "n/a" "blocked by earlier failure"
fi

if [ "${fail_count}" -eq 0 ]; then
  # Replay the saved request after restart
  docker compose --profile blackbox restart target-blackbox \
    > "${evidence}/ps2-04-restart.log" 2>&1 || true
  sleep 3
  docker compose --profile blackbox exec -T target-blackbox \
    python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/', timeout=3)" \
    > /dev/null 2>&1 || sleep 5
  if docker compose --profile blackbox exec -T blackbox \
      python3 /opt/lab/tools/http_client.py replay \
        --input /workspace/results/acceptance-smoke/get-root.req \
        --output-dir /workspace/results/acceptance-smoke \
        --stem get-root-replay \
      > "${evidence}/ps2-04-replay.json" 2> "${evidence}/ps2-04-replay.err"; then
    if grep -q '"timed_out": false' "${evidence}/ps2-04-replay.json" \
      && grep -E -q '"response_len": [1-9]' "${evidence}/ps2-04-replay.json"; then
      record PS2-04 PASS "http_client.py replay get-root.req" \
        "saved request replayed after restart"
    else
      record PS2-04 FAIL "http_client.py replay get-root.req" \
        "replay produced no usable response"
    fi
  else
    record PS2-04 FAIL "http_client.py replay get-root.req" \
      "see ps2-04-replay.err"
  fi
else
  record PS2-04 BLOCKED "n/a" "blocked by earlier failure"
fi

# Chunked path smoke (well-formed; not a PoC)
if [ "${fail_count}" -eq 0 ]; then
  if docker compose --profile blackbox exec -T blackbox \
      python3 /opt/lab/tools/http_client.py send \
        --input /opt/lab/tools/inputs/chunked_ok.http \
        --output-dir /workspace/results/acceptance-smoke \
        --stem chunked-ok \
      > "${evidence}/ps2-05-chunked.json" 2> "${evidence}/ps2-05-chunked.err"; then
    record PS2-05 PASS "send chunked_ok.http" \
      "chunked request delivered; see ps2-05-chunked.json"
  else
    record PS2-05 FAIL "send chunked_ok.http" "see ps2-05-chunked.err"
  fi
else
  record PS2-05 BLOCKED "n/a" "blocked by earlier failure"
fi

# Oracle differential (evaluator)
if [ "${fail_count}" -eq 0 ]; then
  if ./scripts/oracle_smoke.sh > "${evidence}/ps2-06-oracle.log" 2>&1; then
    record PS2-06 PASS "./scripts/oracle_smoke.sh" \
      "ASan exact-buffer oracle distinguishes vuln vs fixed"
  else
    record PS2-06 FAIL "./scripts/oracle_smoke.sh" "see ps2-06-oracle.log"
  fi
else
  record PS2-06 BLOCKED "n/a" "blocked by earlier failure"
fi

./scripts/freeze_check.sh >> "${status_file}" 2>&1 || true

printf 'SUMMARY pass=%s fail=%s blocked=%s\n' \
  "${pass_count}" "${fail_count}" "${blocked_count}" | tee -a "${status_file}"

stop_all
if [ "${fail_count}" -gt 0 ] || [ "${blocked_count}" -gt 0 ]; then
  exit 1
fi
exit 0

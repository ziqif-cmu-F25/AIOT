#!/bin/bash
# Start the stock libmodbus unit-test-server (TCP backend) under ASan.
#
# The server binds 127.0.0.1:1502 and serves one connection, mirroring the
# upstream test. Drive it from inside this container with:
#   docker compose exec target python3 /opt/lab/modbus_client.py send ...
# A memory-safety violation aborts the process with an ASan report on stderr
# (visible via `docker compose logs`); start a fresh instance per attempt.
set -euo pipefail

MODE="${MODBUS_MODE:-tcp}"
exec /usr/local/bin/unit-test-server "${MODE}"

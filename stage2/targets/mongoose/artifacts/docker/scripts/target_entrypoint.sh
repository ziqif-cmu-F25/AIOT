#!/bin/bash
# Start the frozen Mongoose HTTP server.
set -euo pipefail

LISTEN_ADDR="${LISTEN_ADDR:-http://0.0.0.0:8000}"
WWW_ROOT="${WWW_ROOT:-/var/www}"
DEBUG_LEVEL="${DEBUG_LEVEL:-2}"

exec /usr/local/bin/mongoose-http-server \
  -l "${LISTEN_ADDR}" \
  -d "${WWW_ROOT}" \
  -v "${DEBUG_LEVEL}"

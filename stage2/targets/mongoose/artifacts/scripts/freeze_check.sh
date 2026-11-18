#!/bin/bash
# Record freeze decision after reachability checks.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
evidence="${root}/results/acceptance"
mkdir -p "${evidence}"
out="${evidence}/freeze-record.md"

{
  echo "# Freeze record"
  echo
  echo "- UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Target: Cesanta Mongoose"
  echo "- Vulnerable tag/commit: 7.21 / b1c2ffe1a0aa13e3d94075b1a2c66b8b43ac9116"
  echo "- Fixed tag/commit: 7.22 / c288ac1f38424ffdd4d2fd5e1893fd4962642db3"
  echo "- Surface: HTTP chunked parsing (skip_chunk CRLF off-by-one / CVE-2026-52056)"
  echo "- Selection reason: Preferred personal target distinct from libcoap; 7.22 release notes list the skip_chunk fix; exact-buffer ASan oracle distinguishes vulnerable vs fixed logic; HTTP endpoint reachable in Docker."
  echo "- Backup rule: remain on Mongoose HTTP parsing if a later run fails; do not switch libraries."
  echo "- Frozen: YES"
} > "${out}"
echo "Wrote ${out}"

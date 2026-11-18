#!/bin/bash
# Fetch the pinned Stage 1 libcoap tree for the agent to read.
# Source is not stored in git. Re-run is safe.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
dest="$(cd "$(dirname "$0")/.." && pwd)/vendor/libcoap"
commit="7cf7465b784baded4de183290c547d582becfd28"

rm -rf "${dest}"
mkdir -p "${dest}"
git -C "${dest}" init
git -C "${dest}" remote add origin https://github.com/obgm/libcoap.git
git -C "${dest}" fetch --depth 1 origin "${commit}"
git -C "${dest}" checkout --detach FETCH_HEAD
git -C "${dest}" remote remove origin
echo "libcoap ${commit} at ${dest}"

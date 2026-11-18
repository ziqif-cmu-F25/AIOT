#!/bin/bash
# Fetch the pinned personal Stage 2 Mongoose tree for the agent to read.
# Source is not stored in git. Re-run is safe.
set -euo pipefail

dest="$(cd "$(dirname "$0")/.." && pwd)/vendor/mongoose"
commit="b1c2ffe1a0aa13e3d94075b1a2c66b8b43ac9116"

rm -rf "${dest}"
mkdir -p "${dest}"
git -C "${dest}" init
git -C "${dest}" remote add origin https://github.com/cesanta/mongoose.git
git -C "${dest}" fetch --depth 1 origin "${commit}"
git -C "${dest}" checkout --detach FETCH_HEAD
git -C "${dest}" remote remove origin
echo "mongoose ${commit} at ${dest}"

#!/bin/sh
set -eu

project_dir="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
targets="${*:-x86_64-unknown-linux-musl}"
(cd "$project_dir" && cargo test --locked -p quickstart-netpolicy -p quickstart-netpolicy-common)
"$project_dir/scripts/ops/build.sh" $targets

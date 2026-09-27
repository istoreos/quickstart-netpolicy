#!/bin/sh
set -eu

host="${1:?usage: rollback.sh HOST}"
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
scp -q "$script_dir/rollback-device.sh" "$host:/tmp/rollback-device.sh"
ssh -o BatchMode=yes "$host" /tmp/rollback-device.sh

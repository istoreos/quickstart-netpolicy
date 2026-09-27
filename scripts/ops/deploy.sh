#!/bin/sh
set -eu

host="${1:?usage: deploy.sh HOST ARCHIVE [interface]}"
archive="${2:?usage: deploy.sh HOST ARCHIVE [interface]}"
interface="${3:-br-lan}"
case "$host" in root@*) ;; *) echo "host must be explicit root@ADDRESS" >&2; exit 2 ;; esac
[ -r "$archive" ] || { echo "archive not found: $archive" >&2; exit 1; }
remote_archive="/tmp/$(basename "$archive")"
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
scp -q "$archive" "$script_dir/preflight-device.sh" "$script_dir/install-device.sh" "$host:/tmp/"
ssh -o BatchMode=yes "$host" "/tmp/install-device.sh '$remote_archive' '$interface'"

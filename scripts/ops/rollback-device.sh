#!/bin/sh
set -eu

base=/opt/quickstart-netpolicy
previous="$(readlink "$base/previous" 2>/dev/null || true)"
current="$(readlink "$base/current" 2>/dev/null || true)"
[ -n "$previous" ] && [ -x "$previous/quickstart-netpolicy" ] || { echo "no valid previous release" >&2; exit 1; }
ln -sfn "$previous" "$base/current.next"
mv -f "$base/current.next" "$base/current"
[ -z "$current" ] || ln -sfn "$current" "$base/previous"
/etc/init.d/quickstart-netpolicy restart
printf 'rollback=pass release=%s\n' "$previous"

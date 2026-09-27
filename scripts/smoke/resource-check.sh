#!/bin/sh
set -eu

pid="${1:?usage: resource-check.sh PID [samples] [interval-seconds]}"
samples="${2:-12}"
interval="${3:-5}"

case "$pid:$samples:$interval" in
  *[!0-9:]*|:*|*::*|*:) echo "PID, samples and interval must be positive integers" >&2; exit 2 ;;
esac

index=0
max_rss=0
max_fds=0
while [ "$index" -lt "$samples" ]; do
  [ -r "/proc/$pid/status" ] || { echo "process $pid is not running" >&2; exit 1; }
  rss="$(awk '/^VmRSS:/ { print $2 }' "/proc/$pid/status")"
  rss="${rss:-0}"
  fds="$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)"
  [ "$rss" -le "$max_rss" ] || max_rss="$rss"
  [ "$fds" -le "$max_fds" ] || max_fds="$fds"
  printf 'sample=%s rss_kib=%s fds=%s\n' "$index" "$rss" "$fds"
  index=$((index + 1))
  [ "$index" -ge "$samples" ] || sleep "$interval"
done
printf 'result=pass max_rss_kib=%s max_fds=%s\n' "$max_rss" "$max_fds"

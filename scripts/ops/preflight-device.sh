#!/bin/sh
set -eu

interface="${1:-br-lan}"
[ "$(id -u)" -eq 0 ] || { echo "preflight requires root" >&2; exit 1; }
[ -d "/sys/class/net/$interface" ] || { echo "missing interface: $interface" >&2; exit 1; }
[ -d /sys/fs/bpf ] || { echo "missing BPF filesystem" >&2; exit 1; }
[ -r /sys/kernel/btf/vmlinux ] || { echo "missing kernel BTF support" >&2; exit 1; }
command -v tc >/dev/null || { echo "missing tc command" >&2; exit 1; }

for process in bandix eqos eqosd; do
	if pidof "$process" >/dev/null 2>&1; then
		echo "conflicting process is running: $process" >&2
		exit 1
	fi
done

available_kib="$(df -Pk /opt 2>/dev/null | awk 'NR==2 {print $4}')"
[ -n "$available_kib" ] || available_kib="$(df -Pk / | awk 'NR==2 {print $4}')"
[ "${available_kib:-0}" -ge 8192 ] || { echo "less than 8 MiB free for release" >&2; exit 1; }
printf 'preflight=pass interface=%s free_kib=%s\n' "$interface" "$available_kib"

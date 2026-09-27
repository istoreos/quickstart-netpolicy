#!/bin/sh
set -eu

archive="${1:?usage: install-device.sh ARCHIVE [interface]}"
interface="${2:-br-lan}"
base=/opt/quickstart-netpolicy
stage="$(mktemp -d /tmp/quickstart-netpolicy-install.XXXXXX)"
trap 'rm -rf "$stage"' EXIT HUP INT TERM

"$(dirname "$0")/preflight-device.sh" "$interface"
tar -xzf "$archive" -C "$stage"
manifest="$stage/manifest.json"
[ -r "$manifest" ] || { echo "package manifest is missing" >&2; exit 1; }
product="$(sed -n 's/.*"product":"\([^"]*\)".*/\1/p' "$manifest")"
version="$(sed -n 's/.*"version":"\([^"]*\)".*/\1/p' "$manifest")"
expected="$(sed -n 's/.*"binarySha256":"\([^"]*\)".*/\1/p' "$manifest")"
[ "$product" = quickstart-netpolicy ] && [ -n "$version" ] && [ -n "$expected" ] || { echo "invalid package manifest" >&2; exit 1; }
actual="$(sha256sum "$stage/payload/quickstart-netpolicy" | awk '{print $1}')"
[ "$actual" = "$expected" ] || { echo "binary checksum mismatch" >&2; exit 1; }

release="$base/releases/$version-$actual"
mkdir -p "$release" /etc/config /etc/init.d /usr/share/quickstart-netpolicy
cp "$stage/payload/quickstart-netpolicy" "$release/quickstart-netpolicy"
cp "$manifest" "$release/manifest.json"
cp "$stage/payload/quickstart-netpolicy.init" /etc/init.d/quickstart-netpolicy
chmod 0755 "$release/quickstart-netpolicy" /etc/init.d/quickstart-netpolicy
chmod 0644 "$release/manifest.json"
if [ ! -e /etc/config/quickstart-netpolicy ]; then
	cp "$stage/payload/quickstart-netpolicy.config" /etc/config/quickstart-netpolicy
	chmod 0644 /etc/config/quickstart-netpolicy
fi

current="$(readlink "$base/current" 2>/dev/null || true)"
[ -z "$current" ] || ln -sfn "$current" "$base/previous"
ln -sfn "$release" "$base/current.next"
# BusyBox mv follows a destination symlink to a directory unless -T is used.
# Without -T, upgrades report success but leave the old release active.
mv -fT "$base/current.next" "$base/current"
/etc/init.d/quickstart-netpolicy enable
/etc/init.d/quickstart-netpolicy restart
printf 'install=pass release=%s previous=%s\n' "$release" "${current:-none}"

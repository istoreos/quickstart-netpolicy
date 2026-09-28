#!/bin/sh
set -eu

project_dir="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$project_dir/bandix/Cargo.toml" | head -n 1)"
[ -n "$version" ] || { echo "cannot determine version" >&2; exit 1; }
dist_dir="${DIST_DIR:-$project_dir/dist/$version}"
toolchain_root="${MUSL_CROSS_DIR:-/config/musl-cross}"
targets="${*:-x86_64-unknown-linux-musl}"
mkdir -p "$dist_dir"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git -C "$project_dir" show -s --format=%ct HEAD)}"
git_sha="$(git -C "$project_dir" rev-parse HEAD)"

linker_for() {
	case "$1" in
		x86_64-unknown-linux-musl) echo "$toolchain_root/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc" ;;
		aarch64-unknown-linux-musl) echo "$toolchain_root/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc" ;;
		armv7-unknown-linux-musleabihf) echo "$toolchain_root/arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-gcc" ;;
		armv7-unknown-linux-musleabi|armv5te-unknown-linux-musleabi|arm-unknown-linux-musleabi) echo "$toolchain_root/arm-linux-musleabi-cross/bin/arm-linux-musleabi-gcc" ;;
		riscv64gc-unknown-linux-musl) echo "$toolchain_root/riscv64-linux-musl-cross/bin/riscv64-linux-musl-gcc" ;;
		powerpc64le-unknown-linux-musl) echo "$toolchain_root/powerpc64le-linux-musl-cross/bin/powerpc64le-linux-musl-gcc" ;;
		*) echo "unsupported release target: $1" >&2; return 1 ;;
	esac
}

: > "$dist_dir/SHA256SUMS"
for target in $targets; do
	linker="$(linker_for "$target")"
	[ -x "$linker" ] || { echo "missing linker for $target: $linker" >&2; exit 1; }
	env_key="CARGO_TARGET_$(printf '%s' "$target" | tr '[:lower:]-' '[:upper:]_')_LINKER"
	export "$env_key=$linker"
	rustup target add "$target" >/dev/null
	(
		cd "$project_dir"
		cargo build --locked --release --target "$target" --bin quickstart-netpolicy
	)
	binary="$project_dir/target/$target/release/quickstart-netpolicy"
	[ -x "$binary" ] || { echo "missing built binary: $binary" >&2; exit 1; }
	stage="$(mktemp -d)"
	trap 'rm -rf "$stage"' EXIT HUP INT TERM
	mkdir -p "$stage/payload"
	cp "$binary" "$stage/payload/quickstart-netpolicy"
	cp "$project_dir/packaging/quickstart-netpolicy.init" "$stage/payload/quickstart-netpolicy.init"
	cp "$project_dir/packaging/quickstart-netpolicy.config" "$stage/payload/quickstart-netpolicy.config"
	cp "$project_dir/LICENSE" "$project_dir/NOTICE" "$stage/payload/"
	binary_sha="$(sha256sum "$stage/payload/quickstart-netpolicy" | awk '{print $1}')"
	cat > "$stage/manifest.json" <<EOF
{"product":"quickstart-netpolicy","version":"$version","target":"$target","policyInterfaceVersion":"1","gitSha":"$git_sha","binarySha256":"$binary_sha"}
EOF
	archive="$dist_dir/quickstart-netpolicy-$version-$target.tar.gz"
	tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner \
		-C "$stage" -cf - manifest.json payload | gzip -n > "$archive"
	archive_name="$(basename "$archive")"
	archive_sha="$(sha256sum "$archive" | awk '{print $1}')"
	printf '%s  %s\n' "$archive_sha" "$archive_name" >> "$dist_dir/SHA256SUMS"
	rm -rf "$stage"
	trap - EXIT HUP INT TERM
done

(cd "$dist_dir" && sha256sum -c SHA256SUMS)
printf 'release_dir=%s version=%s targets=%s\n' "$dist_dir" "$version" "$targets"

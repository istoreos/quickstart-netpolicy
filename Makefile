.PHONY: test build release preflight

test:
	cargo test --locked -p quickstart-netpolicy -p quickstart-netpolicy-common

build:
	./scripts/ops/build.sh x86_64-unknown-linux-musl

release:
	./scripts/ops/release.sh

preflight:
	./scripts/ops/preflight-device.sh "$${IFACE:-br-lan}"

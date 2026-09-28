.PHONY: test build release preflight smoke-ipv4 smoke-ipv6

test:
	cargo test --locked -p quickstart-netpolicy -p quickstart-netpolicy-common

build:
	./scripts/ops/build.sh x86_64-unknown-linux-musl

release:
	./scripts/ops/release.sh

preflight:
	./scripts/ops/preflight-device.sh "$${IFACE:-br-lan}"

smoke-ipv4:
	./scripts/smoke/topology-smoke.sh

smoke-ipv6:
	./scripts/smoke/ipv6-topology-smoke.sh

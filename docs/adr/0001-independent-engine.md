# ADR 0001: Maintain an independent Quickstart network-policy engine

Status: accepted

## Context

Quickstart device management needs a stable execution engine for rate limits,
traffic quotas and effective-state verification. Depending directly on an
arbitrary installed Bandix version would expose the product to upstream
interface changes and to two control planes writing the same rules.

The project started from Bandix v0.12.10 under its existing open-source
license. Upstream history and attribution remain intact.

## Decision

We maintain the implementation as `quickstart-netpolicy` on the `linkdev`
branch. It is a standalone binary release and does not depend on the
`openwrt-bandix` packaging repository.

Runtime resources are isolated from upstream Bandix:

- binary and CLI name: `quickstart-netpolicy`;
- default local control port: `8765`;
- default data directory: `/usr/share/quickstart-netpolicy`;
- eBPF program names: `qsnp_ingress` and `qsnp_egress`;
- eBPF map names use the `QSNP_` prefix;
- ring files use the `QNP1` format marker;
- product interface discovery is exposed at
  `GET /api/v1/system/capabilities`.

The historical `bandix*` source-directory names are retained initially to
keep upstream reviews and selective merges small. They are build-time paths
only and are not shipped as runtime resources.

Both packages may be installed, but only one policy engine may attach to a
given interface. Quickstart NetPolicy refuses startup when an upstream
`bandix` process already targets that interface. Deployment integration must
also prevent Bandix from being started later on an owned interface.

Legacy Bandix-compatible traffic endpoints remain temporarily available to
support the current Quickstart adapter and controlled migration. New product
features must use versioned Quickstart interfaces.

## Upstream maintenance

`origin` is the LinkEase fork and `upstream` tracks
`https://github.com/timsaya/bandix.git`. Upstream changes are reviewed and
selectively merged; they are never promoted directly to a release.

## Release contract

Production consumes immutable architecture-specific archives generated from
this repository. Every archive includes the binary, LICENSE, NOTICE and
README, and `SHA256SUMS` is generated for release verification. Installation,
service management and rollout orchestration remain the responsibility of
Quickstart deployment logic rather than a fork of `openwrt-bandix`.

## Consequences

We own kernel compatibility, safety, resource limits and upgrade testing. In
return, Quickstart controls its product interface and can evolve its rule model
without depending on Bandix release timing.

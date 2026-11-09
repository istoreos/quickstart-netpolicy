# Quickstart NetPolicy interface v1

The product interface expresses desired network policy without exposing the
eBPF implementation or the historical Bandix wire format.

## Invariants

- Devices are identified by normalized MAC address in v1.
- Rates use bits per second; quotas use bytes.
- A mutation replaces the requesting owner's desired device-policy set.
- `expectedRevision` provides optimistic concurrency.
- `idempotencyKey` makes a completed mutation safe to retry.
- A caller may only modify policies owned by the same product instance.
- At most 1,024 device policies may be active.

## Engine interface

The internal `TrafficPolicyEngine` interface exposes six operations:

1. `inspect`
2. `plan`
3. `apply`
4. `verify`
5. `rollback`
6. `health`

Callers never manipulate eBPF maps, TC handles or persistence files directly.

## HTTP binding

- `GET /api/v1/policies` — inspect the current snapshot.
- `POST /api/v1/policies/plan` — validate and plan a mutation without writes.
- `POST /api/v1/policies/apply` — apply `{ "plan": ..., "request": ... }`.
- `POST /api/v1/policies/verify` — verify a supplied snapshot against the data plane.
- `POST /api/v1/policies/rollback` — roll back `{ "revision": N }`.
- `GET /api/v1/system/health` — machine-readable engine health.

## Mutation example

```json
{
  "expectedRevision": 4,
  "idempotencyKey": "quickstart-20260927-0001",
  "owner": {
    "product": "quickstart",
    "instance": "router-30-244"
  },
  "policies": [
    {
      "device": {
        "kind": "mac",
        "value": "AA:BB:CC:DD:EE:FF"
      },
      "rateLimit": {
        "enabled": true,
        "uploadBitsPerSecond": 10000000,
        "downloadBitsPerSecond": 50000000
      },
      "quota": {
        "enabled": true,
        "period": "month",
        "limitBytes": 107374182400,
        "action": "block"
      }
    }
  ]
}
```

## Stable error codes

- `validation_failed`
- `capacity_exceeded`
- `revision_conflict`
- `conflict`
- `unavailable`
- `verification_failed`
- `rollback_failed`

Transport-specific status codes are adapter concerns. Product logic branches
on these stable error codes.


## Network-bound instances (scope context version 1)

The control server serves one request per TCP connection and declares
`Connection: close`. New clients also request connection closure for original
v1 engines that omitted that header.

The HTTP interface version remains `1`. Capabilities add
`scopeContextVersion: 1`. Health adds the actual `interface` and a `context`:

```json
{"networkId":"office","instanceId":"office","epoch":"runtime-uuid","interfaceIndex":27}
```

`--network-id` and `--instance-id` default to `lan` and `main` for the existing
single-instance configuration. Each enabled named procd section declares its
own interface, loopback port and data directory. Additional sections require
explicit resources; discovery does not enable them. `main` retains port 8765
and `/usr/share/quickstart-netpolicy`.

The service validates duplicate networks, interfaces, ports and data directories
before starting instances. Processes independently lock their canonical data
directory and interface; bridge/child overlap is rejected. The endpoint binds
127.0.0.1 before BPF attachment. An unchanged named procd command stays running
on reload. Interface identity changes require a new runtime and fresh plan.

Plan IDs belong to the issuing process and exact request. The bounded cache
retains at most 64 pending plans; an evicted or pre-restart plan must be rebuilt.
A committed idempotency key replays only its original request. Old journals
without a request fingerprint remain readable, but replay requires a new key.
An unresolved post-apply journal failure makes the instance unavailable until
recovery; it must not continue accepting writes with an uncertain revision.

A mutation still replaces only its owner's desired set within this instance.
The same MAC in another instance uses separate maps, policies and counters.
Clients retain the complete stored policy record when echoing a snapshot for
verification, including its `revision` and `source`. For old v1 clients only,
the HTTP adapter fills these two omitted server-owned fields from the current
record, then requires the snapshot to match before checking the data plane.

A Quickstart client selects endpoints from local service configuration and
checks network, instance, interface and interface index against health. It may
use an old v1 engine only for the original main LAN after verifying its local
process command and port. Lack of scope context is never treated as additional
LAN support. Full traffic/IPv6/quota behavior has a separate packet-level
acceptance gate; a healthy control endpoint alone does not prove enforcement.

### Scoped traffic samples

`GET /api/traffic/devices` adds `sampledAtMs` (last successful kernel sample,
zero before sampling) and `counterEpoch` (the process epoch exposed by
`system/health`). `w_tx_b` / `w_rx_b` are cumulative WAN-only counters. Clients
must match the network/instance/interface context and epoch, reject stale
samples, and rebaseline counters on epoch changes while retaining historical
usage and quota state. LAN counters are not WAN quota usage.

On OpenWrt, classification reads active LAN prefixes from ubus and
firewall zone membership, excluding uplinks and container networks. This does
not admit devices from other interfaces. Prefixes refresh every 30 seconds;
unknown topology or more than 16 unique prefixes per address family stops the
instance rather than classifying internal traffic as WAN. Standalone callers
may supply explicit IPv4/IPv6 CIDRs through `--traffic-additional-subnets`.

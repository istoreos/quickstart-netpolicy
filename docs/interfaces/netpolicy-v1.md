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

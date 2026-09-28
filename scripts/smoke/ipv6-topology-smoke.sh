#!/bin/sh
set -eu

# B receives one temporary loopback /128 and C receives one temporary route.
# A is fingerprinted read-only and never participates in the fixture.
A_HOST="${A_HOST:-root@192.168.30.1}"
B_HOST="${B_HOST:-root@192.168.30.244}"
C_HOST="${C_HOST:-root@192.168.30.93}"
C_IPV6="${C_IPV6:-fdac:b153:8eb3:2:44f1:f3ff:feb9:9fb9}"
C_MAC="${C_MAC:-46:F1:F3:B9:9F:B9}"
B_LINK_LOCAL="${B_LINK_LOCAL:-fe80::be24:11ff:feb9:9fa1}"
B_TEST_IPV6="${B_TEST_IPV6:-fd28:1::1}"
ENGINE_PORT="${ENGINE_PORT:-8765}"
LIMIT_BITS="${LIMIT_BITS:-2000000}"
IPERF_PORT="${IPERF_PORT:-18082}"

command -v jq >/dev/null
remote() { host="$1"; shift; ssh -o BatchMode=yes -o ConnectTimeout=8 "$host" "$@"; }
engine_get() { remote "$B_HOST" "curl -fsS --max-time 10 'http://127.0.0.1:${ENGINE_PORT}$1'"; }
engine_post() { path="$1"; remote "$B_HOST" "curl -fsS --max-time 15 -H 'Content-Type: application/json' --data-binary @- 'http://127.0.0.1:${ENGINE_PORT}${path}'"; }

applied=0
before_revision=""
fixture=0
server=0
cleanup() {
    status="$?"
    trap - EXIT HUP INT TERM
    if [ "$applied" = 1 ] && [ -n "$before_revision" ]; then
        printf '{"revision":%s}' "$before_revision" | engine_post /api/v1/policies/rollback >/dev/null 2>&1 || true
    fi
    if [ "$server" = 1 ]; then
        remote "$B_HOST" 'test ! -s /tmp/quickstart-netpolicy-ipv6.pid || kill "$(cat /tmp/quickstart-netpolicy-ipv6.pid)" 2>/dev/null || true' >/dev/null 2>&1 || true
    fi
    if [ "$fixture" = 1 ]; then
        remote "$C_HOST" "ip -6 route del '${B_TEST_IPV6}/128' via '${B_LINK_LOCAL}' dev eth0" >/dev/null 2>&1 || true
        remote "$B_HOST" "ip -6 addr del '${B_TEST_IPV6}/128' dev lo" >/dev/null 2>&1 || true
    fi
    remote "$B_HOST" 'rm -f /tmp/quickstart-netpolicy-ipv6.pid /tmp/quickstart-netpolicy-ipv6.log' >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

a_before="$(remote "$A_HOST" 'sha256sum /etc/config/network /etc/config/dhcp /etc/config/firewall')"
remote "$B_HOST" '/etc/init.d/quickstart-netpolicy running; test "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 1'
health="$(engine_get /api/v1/system/health)"
printf '%s' "$health" | jq -e '.data.state == "healthy" and .data.dataPlane == "ready"' >/dev/null
for check in \
    "$C_HOST:ip -6 route show '${B_TEST_IPV6}/128'" \
    "$B_HOST:ip -6 addr show dev lo | grep -F '${B_TEST_IPV6}'"; do
    host="${check%%:*}"; command="${check#*:}"
    if remote "$host" "$command" | grep -q .; then echo "refusing existing IPv6 fixture state on $host" >&2; exit 1; fi
done

fixture=1
remote "$B_HOST" "ip -6 addr add '${B_TEST_IPV6}/128' dev lo nodad"
remote "$C_HOST" "ip -6 route add '${B_TEST_IPV6}/128' via '${B_LINK_LOCAL}' dev eth0"
remote "$B_HOST" "iperf3 -s -D -B '${B_TEST_IPV6}' -p '${IPERF_PORT}' -I /tmp/quickstart-netpolicy-ipv6.pid --logfile /tmp/quickstart-netpolicy-ipv6.log"
server=1
for attempt in 1 2 3 4 5; do
    remote "$C_HOST" "iperf3 -c '${B_TEST_IPV6}' -p '${IPERF_PORT}' -t 1 >/dev/null" && break
    [ "$attempt" -lt 5 ] || exit 1
    sleep 1
done
baseline_upload="$(remote "$C_HOST" "iperf3 -c '${B_TEST_IPV6}' -p '${IPERF_PORT}' -t 3 -J" | jq -r '.end.sum_received.bits_per_second|floor')"
baseline_download="$(remote "$C_HOST" "iperf3 -c '${B_TEST_IPV6}' -p '${IPERF_PORT}' -t 3 -R -J" | jq -r '.end.sum_received.bits_per_second|floor')"

before="$(engine_get /api/v1/policies)"
before_revision="$(printf '%s' "$before" | jq -r '.data.revision')"
request="$(jq -cn --argjson revision "$before_revision" --arg mac "$C_MAC" --argjson limit "$LIMIT_BITS" '{expectedRevision:$revision,idempotencyKey:"ipv6-topology-smoke-v1",owner:{product:"ipv6-topology-smoke",instance:"test-b"},policies:[{device:{kind:"mac",value:$mac},rateLimit:{enabled:true,uploadBitsPerSecond:$limit,downloadBitsPerSecond:$limit}}]}')"
plan="$(printf '%s' "$request" | engine_post /api/v1/policies/plan)"
apply_request="$(jq -cn --argjson plan "$(printf '%s' "$plan" | jq -c '.data')" --argjson request "$request" '{plan:$plan,request:$request}')"
applied_snapshot="$(printf '%s' "$apply_request" | engine_post /api/v1/policies/apply)"
printf '%s' "$applied_snapshot" | jq -e '.data.policies | any(.owner.product == "ipv6-topology-smoke" and .state == "effective")' >/dev/null
applied=1
limited_upload="$(remote "$C_HOST" "iperf3 -c '${B_TEST_IPV6}' -p '${IPERF_PORT}' -t 12 -J" | jq -r '[.intervals[3:][]|.sum.bits_per_second]|add/length|floor')"
limited_download="$(remote "$C_HOST" "iperf3 -c '${B_TEST_IPV6}' -p '${IPERF_PORT}' -t 12 -R -J" | jq -r '[.intervals[3:][]|.sum.bits_per_second]|add/length|floor')"

printf '{"revision":%s}' "$before_revision" | engine_post /api/v1/policies/rollback >/dev/null
applied=0
rollback_upload="$(remote "$C_HOST" "iperf3 -c '${B_TEST_IPV6}' -p '${IPERF_PORT}' -t 3 -J" | jq -r '.end.sum_received.bits_per_second|floor')"
rollback_download="$(remote "$C_HOST" "iperf3 -c '${B_TEST_IPV6}' -p '${IPERF_PORT}' -t 3 -R -J" | jq -r '.end.sum_received.bits_per_second|floor')"
printf 'MEASURE family=ipv6 limited_down_bps=%s limited_up_bps=%s baseline_down_bps=%s baseline_up_bps=%s rollback_down_bps=%s rollback_up_bps=%s\n' "$limited_download" "$limited_upload" "$baseline_download" "$baseline_upload" "$rollback_download" "$rollback_upload"
for measured in "$limited_download" "$limited_upload"; do
    [ "$measured" -ge $((LIMIT_BITS / 2)) ]
    [ "$measured" -le $((LIMIT_BITS * 13 / 10)) ]
done
[ "$baseline_download" -gt $((limited_download * 4)) ]
[ "$baseline_upload" -gt $((limited_upload * 4)) ]
[ "$rollback_download" -gt $((limited_download * 4)) ]
[ "$rollback_upload" -gt $((limited_upload * 4)) ]
a_after="$(remote "$A_HOST" 'sha256sum /etc/config/network /etc/config/dhcp /etc/config/firewall')"
[ "$a_before" = "$a_after" ]
printf 'SUMMARY result=pass family=ipv6 limited_down_bps=%s limited_up_bps=%s baseline_down_bps=%s baseline_up_bps=%s rollback_down_bps=%s rollback_up_bps=%s identity=mac rollback=verified A=read-only\n' "$limited_download" "$limited_upload" "$baseline_download" "$baseline_upload" "$rollback_download" "$rollback_upload"

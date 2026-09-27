#!/bin/sh
set -eu

# Destructive scope is limited to a temporary policy on B and temporary /32
# routes plus an HTTP fixture on B/D. A is always read-only.
A_HOST="${A_HOST:-root@192.168.30.1}"
B_HOST="${B_HOST:-root@192.168.30.244}"
C_HOST="${C_HOST:-root@192.168.30.93}"
D_HOST="${D_HOST:-root@192.168.30.7}"
C_IP="${C_IP:-192.168.30.93}"
C_MAC="${C_MAC:-46:F1:F3:B9:9F:B9}"
D_IP="${D_IP:-192.168.30.7}"
D_TEST_IP="${D_TEST_IP:-172.28.1.1}"
ENGINE_PORT="${ENGINE_PORT:-8765}"
LIMIT_BITS="${LIMIT_BITS:-2000000}"
PAYLOAD_MIB="${PAYLOAD_MIB:-8}"

command -v jq >/dev/null
command -v ssh >/dev/null

remote() {
    smoke_host="$1"
    shift
    ssh -o BatchMode=yes -o ConnectTimeout=8 "$smoke_host" "$@"
}

engine_get() {
    remote "$B_HOST" "curl -fsS --max-time 10 'http://127.0.0.1:${ENGINE_PORT}$1'"
}

engine_post() {
    smoke_path="$1"
    remote "$B_HOST" "curl -fsS --max-time 15 -H 'Content-Type: application/json' --data-binary @- 'http://127.0.0.1:${ENGINE_PORT}${smoke_path}'"
}

applied=0
before_revision=""
b_route_added=0
d_route_added=0
d_server_started=0

cleanup() {
    cleanup_status="$?"
    trap - EXIT HUP INT TERM
    if [ "$applied" = 1 ] && [ -n "$before_revision" ]; then
        printf '{"revision":%s}' "$before_revision" | engine_post /api/v1/policies/rollback >/dev/null 2>&1 || true
    fi
    if [ "$b_route_added" = 1 ]; then
        remote "$B_HOST" "ip route del '${D_TEST_IP}/32' via '${D_IP}' dev br-lan" >/dev/null 2>&1 || true
    fi
    if [ "$d_route_added" = 1 ]; then
        remote "$D_HOST" "ip route del '${C_IP}/32' via 192.168.30.244 dev eth0" >/dev/null 2>&1 || true
    fi
    if [ "$d_server_started" = 1 ]; then
        remote "$D_HOST" 'test ! -s /tmp/quickstart-netpolicy-smoke.pid || kill "$(cat /tmp/quickstart-netpolicy-smoke.pid)" 2>/dev/null || true' >/dev/null 2>&1 || true
    fi
    remote "$D_HOST" 'rm -f /tmp/quickstart-netpolicy-smoke.pid /tmp/quickstart-netpolicy-smoke.log /tmp/quickstart-netpolicy-smoke/payload.bin; rmdir /tmp/quickstart-netpolicy-smoke 2>/dev/null || true' >/dev/null 2>&1 || true
    exit "$cleanup_status"
}
trap cleanup EXIT HUP INT TERM

printf 'TASK safety preflight\n'
a_before="$(remote "$A_HOST" 'uptime; sha256sum /etc/config/network /etc/config/dhcp /etc/config/firewall')"
remote "$B_HOST" "/etc/init.d/quickstart-netpolicy running && ! pidof bandix >/dev/null 2>&1"
health="$(engine_get /api/v1/system/health)"
capabilities="$(engine_get /api/v1/system/capabilities)"
printf '%s' "$health" | jq -e '.data.state == "healthy" and .data.dataPlane == "ready" and .data.maxDevicePolicies == 1024 and .data.maxHttpConnections == 32' >/dev/null
printf '%s' "$capabilities" | jq -e '.data.product == "quickstart-netpolicy" and .data.interfaceVersion == "1" and .data.engine == "quickstart-native"' >/dev/null

printf 'TASK request boundaries\n'
malformed_code="$(remote "$B_HOST" "curl -sS -o /tmp/quickstart-netpolicy-malformed.out -w '%{http_code}' -H 'Content-Type: application/json' --data-binary '{' 'http://127.0.0.1:${ENGINE_PORT}/api/v1/policies/plan'")"
oversized_code="$(remote "$B_HOST" "dd if=/dev/zero of=/tmp/quickstart-netpolicy-large-body bs=1024 count=65 2>/dev/null; curl -sS -o /tmp/quickstart-netpolicy-oversized.out -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @/tmp/quickstart-netpolicy-large-body 'http://127.0.0.1:${ENGINE_PORT}/api/v1/policies/plan'; rm -f /tmp/quickstart-netpolicy-large-body")"
[ "$malformed_code" = 400 ]
[ "$oversized_code" = 413 ]

printf 'TASK transactional apply and restart recovery\n'
before="$(engine_get /api/v1/policies)"
before_revision="$(printf '%s' "$before" | jq -r '.data.revision')"
printf '%s' "$before" | jq -e 'all(.data.policies[]; .owner.product != "topology-smoke")' >/dev/null
request="$(jq -cn \
    --argjson revision "$before_revision" --arg mac "$C_MAC" --argjson limit "$LIMIT_BITS" \
    '{expectedRevision:$revision,idempotencyKey:"topology-smoke-v1",owner:{product:"topology-smoke",instance:"test-b"},policies:[{device:{kind:"mac",value:$mac},rateLimit:{enabled:true,uploadBitsPerSecond:$limit,downloadBitsPerSecond:$limit}}]}')"
plan="$(printf '%s' "$request" | engine_post /api/v1/policies/plan)"
apply_request="$(jq -cn --argjson plan "$(printf '%s' "$plan" | jq -c '.data')" --argjson request "$request" '{plan:$plan,request:$request}')"
applied_snapshot="$(printf '%s' "$apply_request" | engine_post /api/v1/policies/apply)"
printf '%s' "$applied_snapshot" | jq -e '.data.policies | any(.owner.product == "topology-smoke" and .state == "effective")' >/dev/null
applied=1
printf '%s' "$applied_snapshot" | jq -c '.data' | engine_post /api/v1/policies/verify >/dev/null

remote "$B_HOST" '/etc/init.d/quickstart-netpolicy restart'
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if health="$(engine_get /api/v1/system/health 2>/dev/null)" && printf '%s' "$health" | jq -e '.data.state == "healthy"' >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
[ "$ready" = 1 ]
after_restart="$(engine_get /api/v1/policies)"
printf '%s' "$after_restart" | jq -e '.data.policies | any(.owner.product == "topology-smoke" and .state == "effective")' >/dev/null

printf 'TASK isolated throughput proof\n'
if remote "$B_HOST" "ip route show '${D_TEST_IP}/32' | grep -q ."; then
    echo "refusing to replace an existing B test route" >&2
    exit 1
fi
if remote "$D_HOST" "ip route show '${C_IP}/32' | grep -q ."; then
    echo "refusing to replace an existing D return route" >&2
    exit 1
fi
remote "$D_HOST" "set -eu; mkdir -p /tmp/quickstart-netpolicy-smoke; dd if=/dev/zero of=/tmp/quickstart-netpolicy-smoke/payload.bin bs=1M count='${PAYLOAD_MIB}' 2>/dev/null; ip route add '${C_IP}/32' via 192.168.30.244 dev eth0"
d_route_added=1
remote "$B_HOST" "ip route add '${D_TEST_IP}/32' via '${D_IP}' dev br-lan"
b_route_added=1
remote "$D_HOST" "start-stop-daemon -S -b -m -p /tmp/quickstart-netpolicy-smoke.pid -x /usr/bin/python3 -- -m http.server 18080 --bind '${D_TEST_IP}' --directory /tmp/quickstart-netpolicy-smoke"
d_server_started=1
server_ready=0
for attempt in 1 2 3 4 5; do
    if remote "$D_HOST" "curl -fsS --max-time 2 -o /dev/null 'http://${D_TEST_IP}:18080/payload.bin'"; then
        server_ready=1
        break
    fi
    sleep 1
done
[ "$server_ready" = 1 ]
limited_speed="$(remote "$C_HOST" "curl -fsS --max-time 90 -o /dev/null -w '%{speed_download}' 'http://${D_TEST_IP}:18080/payload.bin'")"

printf '{"revision":%s}' "$before_revision" | engine_post /api/v1/policies/rollback >/dev/null
applied=0
rolled_back="$(engine_get /api/v1/policies)"
[ "$(printf '%s' "$rolled_back" | jq -r '.data.revision')" = "$before_revision" ]
unlimited_speed="$(remote "$C_HOST" "curl -fsS --max-time 30 -o /dev/null -w '%{speed_download}' 'http://${D_TEST_IP}:18080/payload.bin'")"
[ "$limited_speed" -ge 150000 ]
[ "$limited_speed" -le 350000 ]
[ "$unlimited_speed" -gt $((limited_speed * 4)) ]

printf 'TASK resource and isolation checks\n'
resource="$(remote "$B_HOST" 'pid=$(pidof quickstart-netpolicy); pid=${pid%% *}; awk '\''/^VmRSS:/ {print "rss_kib=" $2}'\'' /proc/$pid/status; printf "fds="; ls /proc/$pid/fd | wc -l')"
rss="$(printf '%s\n' "$resource" | sed -n 's/^rss_kib=//p')"
fds="$(printf '%s\n' "$resource" | sed -n 's/^fds=//p')"
[ "${rss:-999999}" -lt 16384 ]
[ "${fds:-999999}" -lt 64 ]
remote "$C_HOST" 'ping -c 2 -W 2 1.1.1.1 >/dev/null'
remote "$D_HOST" 'ping -c 2 -W 2 1.1.1.1 >/dev/null'
a_after="$(remote "$A_HOST" 'uptime; sha256sum /etc/config/network /etc/config/dhcp /etc/config/firewall')"
[ "$(printf '%s\n' "$a_before" | tail -3)" = "$(printf '%s\n' "$a_after" | tail -3)" ]

printf 'SUMMARY result=pass limited_Bps=%s rollback_Bps=%s rss_kib=%s fds=%s malformed=%s oversized=%s A=read-only\n' \
    "$limited_speed" "$unlimited_speed" "$rss" "$fds" "$malformed_code" "$oversized_code"

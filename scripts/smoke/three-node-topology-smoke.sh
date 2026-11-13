#!/bin/sh
set -eu

# Three-node real-data-plane proof:
#   execution: Netpolicy on br-lan, with an isolated client namespace
#   fixture:   HTTP payload and an explicit /32 return route via execution
#   control:   read-only connectivity/config fingerprint
# No command is sent to the critical gateway A.
ENGINE_HOST="${ENGINE_HOST:-root@192.168.30.93}"
FIXTURE_HOST="${FIXTURE_HOST:-root@192.168.30.7}"
CONTROL_HOST="${CONTROL_HOST:-root@192.168.3.164}"
ENGINE_UPLINK_IP="${ENGINE_UPLINK_IP:-192.168.30.93}"
FIXTURE_IP="${FIXTURE_IP:-192.168.30.7}"
CLIENT_IP="${CLIENT_IP:-192.168.100.250}"
CLIENT_MAC="${CLIENT_MAC:-02:00:00:00:00:93}"
CLIENT_NS="${CLIENT_NS:-qsnp-smoke}"
HOST_VETH="${HOST_VETH:-qsnp-host}"
CLIENT_VETH="${CLIENT_VETH:-qsnp-client}"
ENGINE_PORT="${ENGINE_PORT:-8765}"
FIXTURE_PORT="${FIXTURE_PORT:-18080}"
LIMIT_BITS="${LIMIT_BITS:-2000000}"
PAYLOAD_MIB="${PAYLOAD_MIB:-8}"
ENGINE_TMP=/tmp/quickstart-netpolicy-three-node
FIXTURE_TMP=/tmp/quickstart-netpolicy-three-node

command -v jq >/dev/null
command -v ssh >/dev/null

remote() {
    smoke_host="$1"
    shift
    ssh -o BatchMode=yes -o ConnectTimeout=8 "$smoke_host" "$@"
}

engine_get() {
    remote "$ENGINE_HOST" "curl -fsS --max-time 10 'http://127.0.0.1:${ENGINE_PORT}$1'"
}

engine_post() {
    smoke_path="$1"
    remote "$ENGINE_HOST" "curl -fsS --max-time 15 -H 'Content-Type: application/json' --data-binary @- 'http://127.0.0.1:${ENGINE_PORT}${smoke_path}'"
}

measure_speed() {
    phase="$1"
    remote "$ENGINE_HOST" "ip netns exec '${CLIENT_NS}' curl -fsS --max-time 90 -o /dev/null -w '%{speed_download}' 'http://${FIXTURE_IP}:${FIXTURE_PORT}/payload.bin?phase=${phase}'" | cut -d. -f1
}

config_saved=0
engine_started=0
namespace_created=0
fixture_created=0
fixture_route_added=0
fixture_server_started=0
policy_applied=0
before_revision=""

cleanup_objects() {
    if [ "$policy_applied" = 1 ] && [ -n "$before_revision" ]; then
        printf '{"revision":%s}' "$before_revision" | engine_post /api/v1/policies/rollback >/dev/null 2>&1 || true
        policy_applied=0
    fi
    if [ "$engine_started" = 1 ]; then
        remote "$ENGINE_HOST" '/etc/init.d/quickstart-netpolicy stop' >/dev/null 2>&1 || true
        engine_started=0
    fi
    if [ "$namespace_created" = 1 ]; then
        remote "$ENGINE_HOST" "ip netns del '${CLIENT_NS}' 2>/dev/null || true; ip link del '${HOST_VETH}' 2>/dev/null || true" >/dev/null 2>&1 || true
        namespace_created=0
    fi
    if [ "$fixture_server_started" = 1 ]; then
        remote "$FIXTURE_HOST" "test ! -s '${FIXTURE_TMP}.pid' || kill \"\$(cat '${FIXTURE_TMP}.pid')\" 2>/dev/null || true" >/dev/null 2>&1 || true
        fixture_server_started=0
    fi
    if [ "$fixture_route_added" = 1 ]; then
        remote "$FIXTURE_HOST" "ip route del '${CLIENT_IP}/32' via '${ENGINE_UPLINK_IP}' dev eth0" >/dev/null 2>&1 || true
        fixture_route_added=0
    fi
    if [ "$fixture_created" = 1 ]; then
        remote "$FIXTURE_HOST" "rm -f '${FIXTURE_TMP}.pid' '${FIXTURE_TMP}.log' '${FIXTURE_TMP}/payload.bin'; rmdir '${FIXTURE_TMP}' 2>/dev/null || true" >/dev/null 2>&1 || true
        fixture_created=0
    fi
    if [ "$config_saved" = 1 ]; then
        remote "$ENGINE_HOST" "cp -p '${ENGINE_TMP}/quickstart-netpolicy.config' /etc/config/quickstart-netpolicy; rm -rf '${ENGINE_TMP}'" >/dev/null 2>&1 || true
        config_saved=0
    fi
}

cleanup() {
    cleanup_status="$?"
    trap - EXIT HUP INT TERM
    cleanup_objects
    exit "$cleanup_status"
}
trap cleanup EXIT HUP INT TERM

printf 'TASK three-node safety preflight\n'
remote "$ENGINE_HOST" "set -eu; test ! -e '${ENGINE_TMP}'; test ! -e '/var/run/netns/${CLIENT_NS}'; ! ip link show '${HOST_VETH}' >/dev/null 2>&1; ! ip link show '${CLIENT_VETH}' >/dev/null 2>&1; ! ss -lnt 2>/dev/null | grep -q ':${ENGINE_PORT} '; ! pidof bandix >/dev/null 2>&1; ! pidof quickstart-netpolicy >/dev/null 2>&1; test \"\$(ubus call network.interface.lan status | jsonfilter -e '@.l3_device')\" = br-lan; test \"\$(cat /proc/sys/net/ipv4/ip_forward)\" = 1"
remote "$FIXTURE_HOST" "set -eu; test ! -e '${FIXTURE_TMP}'; test ! -e '${FIXTURE_TMP}.pid'; test ! -e '${FIXTURE_TMP}.log'; ! ip route show '${CLIENT_IP}/32' | grep -q .; ! ss -lnt 2>/dev/null | grep -q ':${FIXTURE_PORT} '"
remote "$CONTROL_HOST" "set -eu; test ! -e '${ENGINE_TMP}'; ping -c 2 -W 2 192.168.3.1 >/dev/null; curl -fsS --max-time 5 -o /dev/null http://127.0.0.1/"

engine_network_before="$(remote "$ENGINE_HOST" 'sha256sum /etc/config/network /etc/config/dhcp /etc/config/firewall; ip -4 route show default; ip -4 -o addr show dev eth0')"
engine_config_hash="$(remote "$ENGINE_HOST" 'sha256sum /etc/config/quickstart-netpolicy' | awk '{print $1}')"
fixture_before="$(remote "$FIXTURE_HOST" 'sha256sum /etc/config/network /etc/config/dhcp /etc/config/firewall; ip -4 route show default; ip -4 -o addr show dev eth0')"
control_before="$(remote "$CONTROL_HOST" 'sha256sum /etc/config/network /etc/config/dhcp /etc/config/firewall; ip -4 route show default; ip -4 -o addr show dev eth0')"
remote "$ENGINE_HOST" '/etc/init.d/quickstart running'
remote "$FIXTURE_HOST" '/etc/init.d/quickstart running'
remote "$CONTROL_HOST" '/etc/init.d/quickstart running'

printf 'TASK temporary engine instance\n'
remote "$ENGINE_HOST" "set -eu; mkdir '${ENGINE_TMP}'; cp -p /etc/config/quickstart-netpolicy '${ENGINE_TMP}/quickstart-netpolicy.config'; mkdir '${ENGINE_TMP}/data'"
config_saved=1
remote "$ENGINE_HOST" "set -eu; uci -q delete quickstart-netpolicy.main || true; uci set quickstart-netpolicy.main=quickstart-netpolicy; uci set quickstart-netpolicy.main.enabled=1; uci set quickstart-netpolicy.main.network=lan; uci set quickstart-netpolicy.main.interface=br-lan; uci set quickstart-netpolicy.main.port='${ENGINE_PORT}'; uci set quickstart-netpolicy.main.data_dir='${ENGINE_TMP}/data'; uci set quickstart-netpolicy.main.log_level=info; uci set quickstart-netpolicy.main.traffic_history=0; uci set quickstart-netpolicy.main.dns_monitoring=0; uci commit quickstart-netpolicy; /etc/init.d/quickstart-netpolicy start"
engine_started=1
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if health="$(engine_get /api/v1/system/health 2>/dev/null)" && printf '%s' "$health" | jq -e '.data.state == "healthy" and .data.dataPlane == "ready" and .data.interface == "br-lan"' >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
[ "$ready" = 1 ]
capabilities="$(engine_get /api/v1/system/capabilities)"
printf '%s' "$capabilities" | jq -e '.data.product == "quickstart-netpolicy" and .data.interfaceVersion == "1" and .data.engine == "quickstart-native"' >/dev/null

printf 'TASK isolated namespace and routed fixture\n'
remote "$ENGINE_HOST" "ip netns add '${CLIENT_NS}'"
namespace_created=1
remote "$ENGINE_HOST" "set -eu; ip link add '${HOST_VETH}' type veth peer name '${CLIENT_VETH}'; ip link set '${CLIENT_VETH}' netns '${CLIENT_NS}'; ip link set '${HOST_VETH}' master br-lan; ip link set '${HOST_VETH}' up; ip netns exec '${CLIENT_NS}' ip link set lo up; ip netns exec '${CLIENT_NS}' ip link set '${CLIENT_VETH}' address '${CLIENT_MAC}'; ip netns exec '${CLIENT_NS}' ip addr add '${CLIENT_IP}/24' dev '${CLIENT_VETH}'; ip netns exec '${CLIENT_NS}' ip link set '${CLIENT_VETH}' up; ip netns exec '${CLIENT_NS}' ip route add default via 192.168.100.1"
remote "$FIXTURE_HOST" "set -eu; mkdir '${FIXTURE_TMP}'; dd if=/dev/zero of='${FIXTURE_TMP}/payload.bin' bs=1M count='${PAYLOAD_MIB}' 2>/dev/null"
fixture_created=1
remote "$FIXTURE_HOST" "ip route add '${CLIENT_IP}/32' via '${ENGINE_UPLINK_IP}' dev eth0"
fixture_route_added=1
remote "$FIXTURE_HOST" "start-stop-daemon -S -b -m -p '${FIXTURE_TMP}.pid' -x /usr/bin/python3 -- -m http.server '${FIXTURE_PORT}' --bind '${FIXTURE_IP}' --directory '${FIXTURE_TMP}'"
fixture_server_started=1
server_ready=0
for attempt in 1 2 3 4 5; do
    if remote "$ENGINE_HOST" "ip netns exec '${CLIENT_NS}' curl -fsS --max-time 3 -o /dev/null 'http://${FIXTURE_IP}:${FIXTURE_PORT}/payload.bin?phase=ready'"; then
        server_ready=1
        break
    fi
    sleep 1
done
[ "$server_ready" = 1 ]
remote "$ENGINE_HOST" "ip netns exec '${CLIENT_NS}' ip route get '${FIXTURE_IP}' | grep -F 'via 192.168.100.1'"
remote "$ENGINE_HOST" "ip route get '${FIXTURE_IP}' | grep -F 'dev eth0'"
remote "$FIXTURE_HOST" "ip route get '${CLIENT_IP}' | grep -F 'via ${ENGINE_UPLINK_IP}'"

rx_before="$(remote "$ENGINE_HOST" 'cat /sys/class/net/eth0/statistics/rx_bytes')"
baseline_speed="$(measure_speed baseline)"

printf 'TASK transactional limit and restart proof\n'
before="$(engine_get /api/v1/policies)"
before_revision="$(printf '%s' "$before" | jq -r '.data.revision')"
printf '%s' "$before" | jq -e 'all(.data.policies[]; .owner.product != "three-node-smoke")' >/dev/null
request="$(jq -cn \
    --argjson revision "$before_revision" --arg mac "$CLIENT_MAC" --argjson limit "$LIMIT_BITS" \
    '{expectedRevision:$revision,idempotencyKey:"three-node-smoke-v1",owner:{product:"three-node-smoke",instance:"execution-93"},policies:[{device:{kind:"mac",value:$mac},rateLimit:{enabled:true,uploadBitsPerSecond:$limit,downloadBitsPerSecond:$limit}}]}')"
plan="$(printf '%s' "$request" | engine_post /api/v1/policies/plan)"
apply_request="$(jq -cn --argjson plan "$(printf '%s' "$plan" | jq -c '.data')" --argjson request "$request" '{plan:$plan,request:$request}')"
applied_snapshot="$(printf '%s' "$apply_request" | engine_post /api/v1/policies/apply)"
printf '%s' "$applied_snapshot" | jq -e '.data.policies | any(.owner.product == "three-node-smoke" and .state == "effective")' >/dev/null
policy_applied=1
printf '%s' "$applied_snapshot" | jq -c '.data' | engine_post /api/v1/policies/verify >/dev/null
remote "$ENGINE_HOST" '/etc/init.d/quickstart-netpolicy restart'
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if health="$(engine_get /api/v1/system/health 2>/dev/null)" && printf '%s' "$health" | jq -e '.data.state == "healthy" and .data.dataPlane == "ready"' >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
[ "$ready" = 1 ]
after_restart="$(engine_get /api/v1/policies)"
printf '%s' "$after_restart" | jq -e '.data.policies | any(.owner.product == "three-node-smoke" and .state == "effective")' >/dev/null
printf '%s' "$after_restart" | jq -c '.data' | engine_post /api/v1/policies/verify >/dev/null
limited_speed="$(measure_speed limited)"
remote "$CONTROL_HOST" 'ping -c 2 -W 2 192.168.3.1 >/dev/null; curl -fsS --max-time 5 -o /dev/null http://127.0.0.1/'

printf '{"revision":%s}' "$before_revision" | engine_post /api/v1/policies/rollback >/dev/null
policy_applied=0
rolled_back="$(engine_get /api/v1/policies)"
[ "$(printf '%s' "$rolled_back" | jq -r '.data.revision')" = "$before_revision" ]
printf '%s' "$rolled_back" | jq -e 'all(.data.policies[]; .owner.product != "three-node-smoke")' >/dev/null
rollback_speed="$(measure_speed rollback)"
rx_after="$(remote "$ENGINE_HOST" 'cat /sys/class/net/eth0/statistics/rx_bytes')"

[ "$limited_speed" -ge 150000 ]
[ "$limited_speed" -le 350000 ]
[ "$baseline_speed" -gt $((limited_speed * 4)) ]
[ "$rollback_speed" -gt $((limited_speed * 4)) ]
[ "$rollback_speed" -gt $((baseline_speed / 3)) ]
payload_bytes=$((PAYLOAD_MIB * 1024 * 1024))
[ "$rx_after" -gt $((rx_before + payload_bytes * 2)) ]

printf 'TASK cleanup and isolation verification\n'
cleanup_objects
remote "$ENGINE_HOST" "set -eu; test ! -e '${ENGINE_TMP}'; test ! -e '/var/run/netns/${CLIENT_NS}'; ! ip link show '${HOST_VETH}' >/dev/null 2>&1; ! pidof quickstart-netpolicy >/dev/null 2>&1; ! ss -lnt 2>/dev/null | grep -q ':${ENGINE_PORT} '; test \"\$(sha256sum /etc/config/quickstart-netpolicy | awk '{print \$1}')\" = '${engine_config_hash}'; /etc/init.d/quickstart running"
remote "$FIXTURE_HOST" "set -eu; test ! -e '${FIXTURE_TMP}'; test ! -e '${FIXTURE_TMP}.pid'; test ! -e '${FIXTURE_TMP}.log'; ! ip route show '${CLIENT_IP}/32' | grep -q .; ! ss -lnt 2>/dev/null | grep -q ':${FIXTURE_PORT} '; /etc/init.d/quickstart running"
remote "$CONTROL_HOST" 'ping -c 2 -W 2 192.168.3.1 >/dev/null; curl -fsS --max-time 5 -o /dev/null http://127.0.0.1/; /etc/init.d/quickstart running'
engine_network_after="$(remote "$ENGINE_HOST" 'sha256sum /etc/config/network /etc/config/dhcp /etc/config/firewall; ip -4 route show default; ip -4 -o addr show dev eth0')"
fixture_after="$(remote "$FIXTURE_HOST" 'sha256sum /etc/config/network /etc/config/dhcp /etc/config/firewall; ip -4 route show default; ip -4 -o addr show dev eth0')"
control_after="$(remote "$CONTROL_HOST" 'sha256sum /etc/config/network /etc/config/dhcp /etc/config/firewall; ip -4 route show default; ip -4 -o addr show dev eth0')"
[ "$engine_network_before" = "$engine_network_after" ]
[ "$fixture_before" = "$fixture_after" ]
[ "$control_before" = "$control_after" ]

trap - EXIT HUP INT TERM
printf 'SUMMARY result=pass topology=three-node execution=192.168.30.93 baseline_Bps=%s limited_Bps=%s rollback_Bps=%s execution_rx_delta=%s control=unchanged cleanup=verified A=not-contacted\n' \
    "$baseline_speed" "$limited_speed" "$rollback_speed" "$((rx_after - rx_before))"

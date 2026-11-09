#!/usr/bin/env bash
# Validate the production init functions without changing any local service.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
source "$root/packaging/quickstart-netpolicy.init"
declare -A fixture=()
errors=()
config_get() {
 local output="$1" config_section="$2" config_option="$3" fallback="${4-}"
 local key="$config_section.$config_option"
 printf -v "$output" '%s' "${fixture[$key]-$fallback}"
}
config_get_bool() { config_get "$@"; }
logger() { errors+=("$*"); }
reset_records() { instance_records=''; invalid_instances=''; errors=(); }
fixture=([main.enabled]=1)
reset_records
IFS=$'\n'
collect_instance main
[[ "$instance_records" == 'main|lan|br-lan|8765|/usr/share/quickstart-netpolicy|info|0|0' ]]
fixture+=([office.enabled]=1 [office.network]=office [office.interface]=br-office [office.port]=8766 [office.data_dir]=/tmp/qsnp-office)
collect_instance office
[[ -z "$invalid_instances" ]]
[[ "$instance_records" == *'office|office|br-office|8766|/tmp/qsnp-office|info|0|0'* ]]
for resource in port interface data_dir network; do
 reset_records
 case "$resource" in port) fixture[office.port]=8765;; interface) fixture[office.interface]=br-lan;; data_dir) fixture[office.data_dir]=/usr/share/quickstart-netpolicy;; network) fixture[office.network]=lan;; esac
 collect_instance main
 collect_instance office
 [[ " $invalid_instances " == *' office '* && " $invalid_instances " == *' main '* ]]
 fixture[office.port]=8766; fixture[office.interface]=br-office; fixture[office.data_dir]=/tmp/qsnp-office; fixture[office.network]=office
done
fixture[office.enabled]=0
reset_records
collect_instance main
collect_instance office
[[ "$instance_records" != *office* && -z "$invalid_instances" ]]
fixture[office.enabled]=1
fixture[office.port]=''
reset_records
collect_instance main
collect_instance office
[[ "$instance_records" != *office* && "$instance_records" == main* ]]
[[ "${#errors[@]}" -eq 1 ]]
printf 'PASS: legacy main; two named instances; duplicate port/device/directory/network; disabled and incomplete instances\n'

# Run the production start function through the firmware's space-separated
# section-list contract. IFS used for our records must not hide UCI sections.
PROG=/bin/true
registered=()
config_load() { CONFIG_SECTIONS="main office"; }
config_foreach() {
 local callback="$1" config_section
 for config_section in $CONFIG_SECTIONS; do "$callback" "$config_section"; done
}
ubus() { printf '{"l3_device":"%s"}\n' "$interface"; }
jsonfilter() { python3 -c 'import json,sys; print(json.load(sys.stdin)["l3_device"])'; }
procd_open_instance() { registered+=("$1"); }
procd_set_param() { :; }
procd_append_param() { :; }
procd_close_instance() { :; }
fixture[main.interface]=lo
fixture[office.interface]=lo
fixture[office.port]=8766
# Use distinct real devices to exercise the production existence check.
if [[ -d /sys/class/net/eth0 ]]; then fixture[office.interface]=eth0; else exit 0; fi
IFS=$' \t\n'
start_service
[[ "${registered[*]}" == "main office" ]]
printf 'PASS: production start_service enumerates UCI sections and registers two instances\n'

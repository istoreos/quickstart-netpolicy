#!/bin/sh
set -eu

host="${1:?usage: verify.sh HOST [port]}"
port="${2:-8765}"
ssh -o BatchMode=yes "$host" "set -eu; /etc/init.d/quickstart-netpolicy running; response=\$(wget -qO- 'http://127.0.0.1:$port/api/v1/system/health'); echo \"\$response\" | grep -q '\"state\":\"healthy\"'; echo \"verify=pass port=$port\""

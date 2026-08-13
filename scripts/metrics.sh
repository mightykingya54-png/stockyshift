#!/bin/bash
# Snapshot StockyShift launch metrics from the live app into launch-metrics.md
#
# Usage:
#   export METRICS_TOKEN="<the token you set on Render>"
#   ./scripts/metrics.sh
#
# Requires: curl, python3 (for JSON pretty-print)

set -euo pipefail

TOKEN="${METRICS_TOKEN:?Set METRICS_TOKEN to the same value as the Render env var}"
URL="${METRICS_URL:-https://stockyshift.onrender.com/admin/metrics}"
FILE="$(cd "$(dirname "$0")/.." && pwd)/launch-metrics.md"
TODAY="$(date +%F)"

echo "Fetching $URL ..."
data="$(curl -sf -H "x-metrics-token: $TOKEN" "$URL")"
echo "$data" | python3 -m json.tool

installs="$(echo "$data" | python3 -c 'import json,sys; print(json.load(sys.stdin)["total_installs"])')"
active="$(echo "$data" | python3 -c 'import json,sys; print(json.load(sys.stdin)["active_installs"])')"
trial="$(echo "$data" | python3 -c 'import json,sys; d=json.load(sys.stdin)["status"]; print(d.get("trial", 0))')"
subs="$(echo "$data" | python3 -c 'import json,sys; d=json.load(sys.stdin)["status"]; print(d.get("active", 0))')"
uninstalls="$(echo "$data" | python3 -c 'import json,sys; print(json.load(sys.stdin)["uninstalls"])')"

if [ ! -f "$FILE" ]; then
  printf '%s\n' \
    "# StockyShift Launch Metrics" \
    "" \
    "| Date | Installs | Active installs | In trial | Subscribed | Uninstalls |" \
    "|------|----------|-----------------|----------|------------|------------|" \
    > "$FILE"
fi

printf '| %s | %s | %s | %s | %s | %s |\n' \
  "$TODAY" "$installs" "$active" "$trial" "$subs" "$uninstalls" >> "$FILE"

echo "Appended to $FILE"
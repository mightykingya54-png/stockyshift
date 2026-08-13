#!/bin/bash
# Snapshot StockyShift launch metrics from the live app into launch-metrics.md
#
# Usage (token from env, or saved once in scripts/.token):
#   ./scripts/metrics.sh
#   ./scripts/metrics.sh --shops     # also print the full shop list
#
# Requires: curl, python3 (for JSON pretty-print)

set -euo pipefail

TOKEN="${METRICS_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -f "$(dirname "$0")/.token" ]; then
  TOKEN="$(cat "$(dirname "$0")/.token" | tr -d '[:space:]')"
fi
if [ -z "$TOKEN" ]; then
  echo "No token found. Either:"
  echo "  export METRICS_TOKEN=your-token"
  echo "  or save it once: echo 'your-token' > scripts/.token"
  exit 1
fi

URL="${METRICS_URL:-https://stockyshift.onrender.com/admin/metrics}"
FILE="$(cd "$(dirname "$0")/.." && pwd)/launch-metrics.md"
TODAY="$(date +%F)"

EXTRA=""
if [ "${1:-}" = "--shops" ]; then EXTRA="?shops=1"; fi

echo "Fetching $URL$EXTRA ..."
data="$(curl -sf -H "x-metrics-token: $TOKEN" "$URL$EXTRA")"
if [ "${1:-}" = "--shops" ]; then
  echo "$data" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("installs:", d["total_installs"], "| active:", d["active_installs"], "| uninstalls:", d["uninstalls"], "| status:", d["status"])
print()
for s in d["shops"]:
    day = s["installed_at"][:10]
    st = s["billing_status"]
    shop = s["shop"]
    print(day, " ", st.ljust(10), shop)
'
else
  echo "$data" | python3 -m json.tool
fi

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
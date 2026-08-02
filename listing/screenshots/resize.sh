#!/bin/bash
# Auto-resize all raw screenshots in this folder to exactly 1600x900 (Shopify spec)
# Usage: drop your screenshots in here named 01-*, 02-*, ... 06-* then run: ./resize.sh
cd "$(dirname "$0")"
EXPECTED=(01-low-stock 02-products-reorder 03-vendors 04-create-po-modal 05-po-list 06-low-stock-email)
echo "=== Screenshot folder check ==="
for name in "${EXPECTED[@]}"; do
  files=$(ls ${name}* 2>/dev/null)
  if [ -z "$files" ]; then
    echo "❌ MISSING: $name.png  (take this shot, drop it here, rerun)"
  else
    for f in $files; do
      w=$(sips -g pixelWidth "$f" | awk '{print $2}')
      h=$(sips -g pixelHeight "$f" | awk '{print $2}')
      if [ "$w" = "1600" ] && [ "$h" = "900" ]; then
        echo "✅ $f  (${w}x${h})"
      else
        sips -z 900 1600 "$f" >/dev/null 2>&1
        nw=$(sips -g pixelWidth "$f" | awk '{print $2}')
        nh=$(sips -g pixelHeight "$f" | awk '{print $2}')
        echo "🔧 Resized $f  ${w}x${h} -> ${nw}x${nh}"
      fi
    done
  fi
done
echo "=== done ==="

#!/bin/bash
RATE=${1:-5000}
TPC=${2:-16}
PORTS=${3:-"80,443"}

echo "[watchdog] rate=$RATE tpc=$TPC ports=$PORTS"

while true; do
    rm -f /tmp/zorp_status
    echo "[$(date '+%H:%M:%S')] starting zorpinvader"

    sudo bin/zorpinvader --rate "$RATE" -p "$PORTS" --tpc "$TPC" &
    ZPID=$!

    sleep 2

    ZERO_COUNT=0
    STARTED=$(date +%s)

    while kill -0 $ZPID 2>/dev/null; do
        sleep 1

        ETA_LINE=$(cat /tmp/zorp_status 2>/dev/null)

        # Check if ETA is frozen (00:00:00 or 4+ digit hours)
        if echo "$ETA_LINE" | grep -qE "ETA: 00:00:00|ETA: [0-9]{4,}:"; then
            ZERO_COUNT=$((ZERO_COUNT + 1))
        else
            # ETA is normal, reset counter
            ZERO_COUNT=0
        fi

        if [ "$ZERO_COUNT" -ge 8 ]; then
            echo ""
            echo "[$(date '+%H:%M:%S')] frozen ETA ($ETA_LINE), restarting"
            kill $ZPID 2>/dev/null
            break
        fi
        if [ "$(( $(date +%s) - STARTED ))" -ge 240 ]; then
            echo ""
            echo "[$(date '+%H:%M:%S')] 4 min cycle, restarting"
            kill $ZPID 2>/dev/null
            break
        fi
    done

    wait $ZPID 2>/dev/null
    sleep 1
done

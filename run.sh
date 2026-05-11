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

    STARTED=$(date +%s)

    while kill -0 $ZPID 2>/dev/null; do
        sleep 1

        # Restart every 30 minutes (1800 seconds)
        ELAPSED=$(( $(date +%s) - STARTED ))
        if [ "$ELAPSED" -ge 1800 ]; then
            echo ""
            echo "[$(date '+%H:%M:%S')] 30 min cycle, restarting"
            kill $ZPID 2>/dev/null
            break
        fi
    done

    wait $ZPID 2>/dev/null
    sleep 1
done

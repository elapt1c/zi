#!/bin/bash
# External watchdog: restarts zorpinvader when ETA hits 00:00:00
RATE=${1:-5000}
TPC=${2:-16}
PORTS=${3:-"80,443"}

echo "[watchdog] rate=$RATE tpc=$TPC ports=$PORTS"
RESTARTS=0

while true; do
    RESTARTS=$((RESTARTS + 1))
    TMPLOG=$(mktemp /tmp/zorp_XXXXXX.log)

    echo "[$(date '+%H:%M:%S')] start #$RESTARTS"
    sudo bin/zorpinvader --rate "$RATE" -p "$PORTS" --tpc "$TPC" 2>"$TMPLOG" &
    ZPID=$!

    ZERO_COUNT=0
    LAST_PORT_COUNT=0
    STARTED=$(date +%s)

    while kill -0 $ZPID 2>/dev/null; do
        sleep 1
        # Check for ETA: 00:00:00 in output
        if tail -5 "$TMPLOG" | grep -q "ETA: 00:00:00"; then
            ZERO_COUNT=$((ZERO_COUNT + 1))
        else
            ZERO_COUNT=0
        fi

        if [ "$ZERO_COUNT" -ge 8 ]; then
            echo "[$(date '+%H:%M:%S')] ETA stuck at 00:00:00 for ${ZERO_COUNT}s, restarting"
            kill $ZPID 2>/dev/null
            wait $ZPID 2>/dev/null
            break
        fi

        # Also restart after 4 minutes to prevent memory buildup
        NOW=$(date +%s)
        ELAPSED=$((NOW - STARTED))
        if [ "$ELAPSED" -ge 240 ]; then
            echo "[$(date '+%H:%M:%S')] 4 min cycle, restarting"
            kill $ZPID 2>/dev/null
            wait $ZPID 2>/dev/null
            break
        fi
    done

    wait $ZPID 2>/dev/null
    rm -f "$TMPLOG"
    sleep 1
done

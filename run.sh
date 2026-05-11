#!/bin/bash
# Run zorpinvader with automatic restart on freeze (exit code 42)
RATE=${1:-5000}
TPC=${2:-16}
PORTS=${3:-"80,443"}

echo "[run] rate=$RATE tpc=$TPC ports=$PORTS"
RESTARTS=0

while true; do
    RESTARTS=$((RESTARTS + 1))
    echo "[$(date '+%H:%M:%S')] start #$RESTARTS - bin/zorpinvader --rate $RATE -p $PORTS --tpc $TPC"
    sudo bin/zorpinvader --rate "$RATE" -p "$PORTS" --tpc "$TPC"
    EC=$?
    if [ $EC -eq 42 ]; then
        echo "[$(date '+%H:%M:%S')] watchdog: scanner frozen, restarting"
        sleep 1
    elif [ $EC -eq 0 ]; then
        echo "[$(date '+%H:%M:%S')] scan complete"
        break
    else
        echo "[$(date '+%H:%M:%S')] exit code $EC, restarting"
        sleep 1
    fi
done

#!/bin/bash
# Watchdog: restarts zorpinvader if it freezes (no new open ports for 10s)
# Usage: ./watchdog.sh [--rate N] [--tpc N] [-p ports]

RATE=5000
TPC=16
PORTS="80,443"

while [ $# -gt 0 ]; do
    case "$1" in
        --rate) RATE="$2"; shift 2;;
        --tpc)  TPC="$2"; shift 2;;
        -p)     PORTS="$2"; shift 2;;
        *)      shift;;
    esac
done

echo "[watchdog] rate=$RATE tpc=$TPC ports=$PORTS"

while true; do
    TMPLOG=$(mktemp /tmp/zorp_watch.XXXXXX)
    
    echo "[watchdog] starting at $(date)"
    sudo timeout 300 bin/zorpinvader --rate "$RATE" -p "$PORTS" --tpc "$TPC" 2>"$TMPLOG" &
    ZPID=$!
    
    LAST_PORTS=0
    STUCK=0
    
    while kill -0 $ZPID 2>/dev/null; do
        sleep 2
        # Parse "Found: N" from the TUI output
        FOUND=$(grep -oP 'Found: \K[0-9]+' "$TMPLOG" 2>/dev/null | tail -1)
        FOUND=${FOUND:-0}
        
        if [ "$FOUND" = "$LAST_PORTS" ]; then
            STUCK=$((STUCK + 2))
        else
            STUCK=0
        fi
        LAST_PORTS=$FOUND
        
        if [ "$STUCK" -ge 10 ]; then
            echo "[watchdog] stuck at $FOUND ports for ${STUCK}s, restarting"
            kill $ZPID 2>/dev/null
            wait $ZPID 2>/dev/null
            break
        fi
        
        # Auto-cycle every 300s anyway
        START=${START:-$(date +%s)}
        ELAPSED=$(( $(date +%s) - START ))
        if [ "$ELAPSED" -ge 300 ]; then
            echo "[watchdog] 5 min cycle, restarting"
            kill $ZPID 2>/dev/null
            wait $ZPID 2>/dev/null
            break
        fi
    done
    
    wait $ZPID 2>/dev/null
    rm -f "$TMPLOG"
    sleep 1
    START=""
done

#!/bin/sh
set -e

echo "=== INITIATING CONTAINER INTERFACE (ROLE: ${NODE_ROLE}) ==="

if [ -n "$NETEM_RULE" ]; then
    echo "[KERNEL TC] Applying netem queuing discipline to eth0: $NETEM_RULE"
    tc qdisc add dev eth0 root netem $NETEM_RULE
    tc qdisc show dev eth0
else
    echo "[KERNEL TC] No netem rule specified, running unconstrained."
fi

exec /usr/local/bin/wan_mesh

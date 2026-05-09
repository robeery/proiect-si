#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== Building and starting peers ==="
docker compose up --build --abort-on-container-exit 2>&1 | tee /tmp/peer-test.log &
COMPOSE_PID=$!

echo "=== Waiting for containers to finish ==="
wait $COMPOSE_PID || true

echo "=== Checking results ==="

PASS=true

for peer in peer1 peer2 peer3; do
    echo "--- $peer logs ---"
    LOGS=$(docker compose logs "$peer" 2>&1)

    # Each peer should discover the other 2 peers
    EXPECTED=2

    if echo "$LOGS" | grep -q "discovered $EXPECTED peer(s)"; then
        echo "  ✓ $peer discovered $EXPECTED peers"
    else
        echo "  ✗ $peer did not discover $EXPECTED peers"
        echo "$LOGS" | grep "discovered"
        PASS=false
    fi
done

echo "=== Cleaning up ==="
docker compose down -v 2>/dev/null || true

if $PASS; then
    echo "=== ALL TESTS PASSED ==="
    exit 0
else
    echo "=== TESTS FAILED ==="
    exit 1
fi
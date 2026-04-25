#!/bin/bash
set -euo pipefail

PORT="${1:-7860}"
PORT2=$((PORT + 1))
CONTAINER_NAME="langflow-audit"
CONTAINER_NAME_NOAUTO="langflow-audit-noauto"

echo "=== Langflow Security Audit - Setup ==="
echo "Container 1 (AUTO_LOGIN=true):  http://localhost:$PORT"
echo "Container 2 (AUTO_LOGIN=false): http://localhost:$PORT2"
echo ""

if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not available."
    echo "Please install Docker or run Langflow manually:"
    echo "  pip install langflow"
    echo "  langflow run --host 0.0.0.0 --port $PORT"
    exit 1
fi

# ── Container 1: AUTO_LOGIN enabled (original chain) ──────────────────────────
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

echo "Pulling langflowai/langflow:latest..."
docker pull langflowai/langflow:latest

echo "Starting container 1 (AUTO_LOGIN=true)..."
docker run -d \
    --name "$CONTAINER_NAME" \
    -p "$PORT:7860" \
    -e LANGFLOW_AUTO_LOGIN=true \
    -e LANGFLOW_SUPERUSER=langflow \
    -e LANGFLOW_SUPERUSER_PASSWORD=langflow \
    -e LANGFLOW_SECRET_KEY=langflow \
    langflowai/langflow:latest

# ── Container 2: AUTO_LOGIN disabled (auth-independent chains) ─────────────────
docker rm -f "$CONTAINER_NAME_NOAUTO" 2>/dev/null || true

echo "Starting container 2 (AUTO_LOGIN=false)..."
docker run -d \
    --name "$CONTAINER_NAME_NOAUTO" \
    -p "$PORT2:7860" \
    -e LANGFLOW_AUTO_LOGIN=false \
    -e LANGFLOW_SUPERUSER=langflow \
    -e LANGFLOW_SUPERUSER_PASSWORD=langflow \
    -e LANGFLOW_SECRET_KEY=langflow \
    langflowai/langflow:latest

# ── Wait for container 1 ───────────────────────────────────────────────────────
echo ""
echo "Waiting for container 1 (port $PORT) to become healthy..."
MAX_WAIT=180
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/api/v1/version" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        echo ""
        echo "Container 1 ready at http://localhost:$PORT"
        break
    fi
    sleep 3
    ELAPSED=$((ELAPSED + 3))
    printf "."
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo ""
    echo "ERROR: Container 1 did not start within ${MAX_WAIT}s."
    echo "Check logs: docker logs $CONTAINER_NAME"
    exit 1
fi

# ── Wait for container 2 ───────────────────────────────────────────────────────
echo "Waiting for container 2 (port $PORT2) to become healthy..."
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT2/api/v1/version" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        echo ""
        echo "Container 2 ready at http://localhost:$PORT2"
        break
    fi
    sleep 3
    ELAPSED=$((ELAPSED + 3))
    printf "."
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo ""
    echo "ERROR: Container 2 did not start within ${MAX_WAIT}s."
    echo "Check logs: docker logs $CONTAINER_NAME_NOAUTO"
    exit 1
fi

# ── Usage instructions ─────────────────────────────────────────────────────────
echo ""
echo "=== Both containers ready ==="
echo ""
echo "Container 1 — AUTO_LOGIN=true  (http://localhost:$PORT)"
echo "  Tests the original unauthenticated chain:"
echo "  python3 exploit_chain_rce.py     --url http://localhost:$PORT"
echo "  python3 exploit_validate_code.py --url http://localhost:$PORT"
echo "  python3 exploit_fernet_key.py    (no server needed)"
echo ""
echo "Container 2 — AUTO_LOGIN=false (http://localhost:$PORT2)"
echo "  Tests auth-independent chains (critical: works without AUTO_LOGIN):"
echo "  python3 exploit_auth_user_rce.py --url http://localhost:$PORT2"
echo "  python3 exploit_ssrf_cloud.py    --url http://localhost:$PORT2"
echo "  python3 exploit_xss_to_rce.py   --url http://localhost:$PORT2"
echo ""
echo "Run all 6 exploits to fully demonstrate the audit findings:"
echo "  # AUTO_LOGIN-dependent exploits (container 1):"
echo "  python3 exploit_chain_rce.py     --url http://localhost:$PORT"
echo "  python3 exploit_validate_code.py --url http://localhost:$PORT"
echo "  # AUTH-INDEPENDENT exploits (container 2, AUTO_LOGIN=false):"
echo "  python3 exploit_auth_user_rce.py --url http://localhost:$PORT2"
echo "  python3 exploit_ssrf_cloud.py    --url http://localhost:$PORT2"
echo "  python3 exploit_xss_to_rce.py   --url http://localhost:$PORT2"
echo "  # Offline exploit (no server):"
echo "  python3 exploit_fernet_key.py"
echo ""
echo "To stop containers:"
echo "  docker rm -f $CONTAINER_NAME $CONTAINER_NAME_NOAUTO"

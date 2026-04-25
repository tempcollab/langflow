#!/bin/bash
set -euo pipefail

PORT="${1:-7860}"
CONTAINER_NAME="langflow-audit"

echo "=== Langflow Security Audit - Setup ==="
echo "Target port: $PORT"
echo ""

if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not available."
    echo "Please install Docker or run Langflow manually:"
    echo "  pip install langflow"
    echo "  langflow run --host 0.0.0.0 --port $PORT"
    exit 1
fi

# Stop existing container if any
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

echo "Pulling langflowai/langflow:latest..."
docker pull langflowai/langflow:latest

echo "Starting Langflow container..."
docker run -d \
    --name "$CONTAINER_NAME" \
    -p "$PORT:7860" \
    -e LANGFLOW_AUTO_LOGIN=true \
    -e LANGFLOW_SUPERUSER=langflow \
    -e LANGFLOW_SUPERUSER_PASSWORD=langflow \
    -e LANGFLOW_SECRET_KEY=langflow \
    langflowai/langflow:latest

echo "Waiting for Langflow to become healthy..."
MAX_WAIT=180
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/api/v1/version" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        echo ""
        echo "Langflow is ready at http://localhost:$PORT"
        echo "Container: $CONTAINER_NAME"
        echo ""
        echo "Run exploits with:"
        echo "  python3 exploit_chain_rce.py --url http://localhost:$PORT"
        echo "  python3 exploit_validate_code.py --url http://localhost:$PORT"
        echo "  python3 exploit_fernet_key.py  (no server needed)"
        exit 0
    fi
    sleep 3
    ELAPSED=$((ELAPSED + 3))
    printf "."
done

echo ""
echo "ERROR: Langflow did not start within ${MAX_WAIT}s."
echo "Check logs: docker logs $CONTAINER_NAME"
exit 1

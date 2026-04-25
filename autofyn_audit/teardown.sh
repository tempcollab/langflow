#!/bin/bash
set -euo pipefail

CONTAINER_NAME="langflow-audit"

echo "=== Langflow Security Audit - Teardown ==="

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Stopping container: $CONTAINER_NAME"
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    echo "Removing container: $CONTAINER_NAME"
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
    echo "Cleanup complete."
else
    echo "Container '$CONTAINER_NAME' not found. Nothing to clean up."
fi

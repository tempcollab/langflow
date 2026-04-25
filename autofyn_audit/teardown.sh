#!/bin/bash
set -euo pipefail

CONTAINER_NAME="langflow-audit"
CONTAINER_NAME_NOAUTO="langflow-audit-noauto"

echo "=== Langflow Security Audit - Teardown ==="

for name in "$CONTAINER_NAME" "$CONTAINER_NAME_NOAUTO"; do
    if docker ps -a --format '{{.Names}}' | grep -q "^${name}$"; then
        echo "Stopping container: $name"
        docker stop "$name" 2>/dev/null || true
        echo "Removing container: $name"
        docker rm "$name" 2>/dev/null || true
    else
        echo "Container '$name' not found. Skipping."
    fi
done

echo "Cleanup complete."

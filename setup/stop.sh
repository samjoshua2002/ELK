#!/bin/bash

# Navigate to the project root
cd "$(dirname "$0")/.."

echo "🛑 Stopping SIEM Stack..."

cd docker
docker-compose down

echo "✅ Stack stopped."

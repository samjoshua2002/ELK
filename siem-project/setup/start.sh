#!/bin/bash

# Navigate to the project root
cd "$(dirname "$0")/.."

echo "🚀 Starting SIEM Stack (Elasticsearch, Kibana, Agent)..."

cd docker
docker-compose up -d --build

echo "✅ Stack is starting up."
echo "------------------------------------------------"
echo "Kibana UI: http://localhost:5601"
echo "Elasticsearch: http://localhost:9200"
echo "------------------------------------------------"
echo "Use 'docker-compose logs -f' in the docker directory to see logs."

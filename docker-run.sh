#!/bin/bash
# Run the Flask MCP server Docker container

set -e

# Check if GITHUB_TOKEN is provided
if [ -z "$GITHUB_TOKEN" ]; then
    echo "❌ Error: GITHUB_TOKEN environment variable is required"
    echo "Usage: GITHUB_TOKEN=your_token_here ./docker-run.sh"
    exit 1
fi

echo "Starting Flask MCP server container..."

# Run the container
docker run -d \
    --name flask-mcp-server \
    -p 8080:8080 \
    -e GITHUB_TOKEN="$GITHUB_TOKEN" \
    -e APP_SECRET_KEY="${APP_SECRET_KEY:-dev-secret-key}" \
    -e AUTH0_CLIENT_ID="${AUTH0_CLIENT_ID}" \
    -e AUTH0_CLIENT_SECRET="${AUTH0_CLIENT_SECRET}" \
    -e AUTH0_DOMAIN="${AUTH0_DOMAIN}" \
    --restart unless-stopped \
    flask-mcp-server:latest

echo "✅ Container started successfully!"
echo "Access the web application at: http://localhost:8080"
echo "To view logs: docker logs flask-mcp-server"
echo "To stop: docker stop flask-mcp-server"
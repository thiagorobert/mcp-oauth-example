#!/bin/bash
# Build the Flask MCP server Docker image

set -e

echo "Building Flask MCP server Docker image..."

# Build the image
docker build -t flask-mcp-server:latest .

echo "✅ Docker image built successfully!"
echo "To run the container:"
echo "  docker run -p 8080:8080 -e GITHUB_TOKEN=your_token_here flask-mcp-server:latest"
echo ""
echo "Or use docker-compose:"
echo "  GITHUB_TOKEN=your_token_here docker-compose up"
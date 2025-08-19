# Docker Deployment Guide

This guide covers deploying the Flask MCP Server using Docker containers.

## Quick Start

1. **Build the image:**
   ```bash
   ./docker-build.sh
   ```

2. **Run the container:**
   ```bash
   GITHUB_TOKEN=your_token_here ./docker-run.sh
   ```

3. **Access the application:**
   - Web interface: http://localhost:8080
   - MCP server: Available via stdio (for MCP clients)

## Environment Variables

### Required
- `GITHUB_TOKEN`: GitHub OAuth access token for MCP functionality

### Optional (Flask Web App)
- `APP_SECRET_KEY`: Flask session secret key
- `AUTH0_CLIENT_ID`: Auth0 application client ID
- `AUTH0_CLIENT_SECRET`: Auth0 application client secret  
- `AUTH0_DOMAIN`: Auth0 domain (e.g., `your-domain.auth0.com`)

## Docker Commands

### Manual Docker Commands

```bash
# Build image
docker build -t flask-mcp-server .

# Run container (MCP only - missing Flask env vars)
docker run -p 8080:8080 -e GITHUB_TOKEN=your_token flask-mcp-server

# Run container (Full Flask + MCP)
docker run -p 8080:8080 \
  -e GITHUB_TOKEN=your_token \
  -e APP_SECRET_KEY=your_secret_key \
  -e AUTH0_CLIENT_ID=your_auth0_client_id \
  -e AUTH0_CLIENT_SECRET=your_auth0_client_secret \
  -e AUTH0_DOMAIN=your_auth0_domain \
  flask-mcp-server

# Run in background
docker run -d --name flask-mcp-server -p 8080:8080 \
  -e GITHUB_TOKEN=your_token flask-mcp-server

# View logs
docker logs flask-mcp-server

# Stop container
docker stop flask-mcp-server
```

### Using Docker Compose

```bash
# Create .env file with your environment variables
cat > .env << EOF
GITHUB_TOKEN=your_github_token
APP_SECRET_KEY=your_secret_key
AUTH0_CLIENT_ID=your_auth0_client_id
AUTH0_CLIENT_SECRET=your_auth0_client_secret
AUTH0_DOMAIN=your_auth0_domain
EOF

# Start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Container Features

### Security
- Runs as non-root user (`app`)
- Uses Python 3.12 slim base image
- Minimal attack surface

### Performance
- Production WSGI server (Waitress)
- Multi-threaded request handling
- Health checks for monitoring

### Monitoring
- Built-in health check endpoint
- Structured logging
- Container status monitoring

### Networking
- Exposes port 8080 by default
- Configurable port mapping
- Health check on startup

## Troubleshooting

### Container Won't Start
```bash
# Check logs
docker logs flask-mcp-server

# Check if port is available
netstat -tulpn | grep 8080

# Check environment variables
docker exec flask-mcp-server env
```

### Health Check Failures
```bash
# Check health status
docker inspect --format='{{.State.Health.Status}}' flask-mcp-server

# Manual health check
curl http://localhost:8080/
```

### MCP Server Issues
```bash
# Check if GitHub token is valid
docker exec flask-mcp-server curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user

# Check MCP server logs
docker logs flask-mcp-server | grep "MCP server"
```

## Production Deployment

For production deployments:

1. **Use specific image tags:**
   ```bash
   docker build -t flask-mcp-server:v1.0.0 .
   ```

2. **Set resource limits:**
   ```yaml
   services:
     flask-mcp-server:
       deploy:
         resources:
           limits:
             memory: 512M
             cpus: '0.5'
   ```

3. **Use secrets management:**
   ```yaml
   services:
     flask-mcp-server:
       environment:
         - GITHUB_TOKEN_FILE=/run/secrets/github_token
       secrets:
         - github_token
   ```

4. **Enable monitoring:**
   ```yaml
   services:
     flask-mcp-server:
       labels:
         - "prometheus.io/scrape=true"
         - "prometheus.io/port=8080"
   ```

## Integration with MCP Clients

The containerized MCP server can be used with MCP clients:

```json
{
  "mcpServers": {
    "github_oauth_example": {
      "command": "docker",
      "args": [
        "exec", 
        "flask-mcp-server",
        "uv", "run", "flask_mcp_server.py", 
        "--token", "${GITHUB_TOKEN}"
      ]
    }
  }
}
```

Or for direct stdio access:
```bash
docker exec -i flask-mcp-server uv run flask_mcp_server.py --token $GITHUB_TOKEN
```
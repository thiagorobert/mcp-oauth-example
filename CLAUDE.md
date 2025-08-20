# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is an MCP (Model Context Protocol) server that demonstrates OAuth authentication with GitHub. It provides tools for interacting with the GitHub API through the device flow OAuth process and includes both standalone authentication and integrated MCP server functionality.

## Architecture

The codebase consists of four main modules:

- **OAuth Client (`client_with_oauth.py`)**: Standalone GitHub OAuth authentication client for obtaining and storing GitHub tokens
- **Flask Web Server (`flask_mcp_server.py`)**: Flask web application with Auth0 OAuth authentication and OAuth callback demonstration
- **MCP Server (`mcp_server.py`)**: Standalone MCP server with GitHub API tools that can be integrated with the Flask app or used independently
- **Configuration Management (`user_inputs.py`)**: Centralized environment variable handling with dataclass-based configuration
- **Token-Based Architecture**: Server accepts pre-authenticated tokens rather than handling authentication internally

## Key Components

### OAuth Client (`client_with_oauth.py`)
- `authenticate()`: Main auth orchestrator that handles token loading/refreshing and OAuth flow
- `get_device_code()` and `poll_for_token()`: Implement GitHub's device flow OAuth
- `save_token()` and `load_token()`: Handle persistent token storage to `github_token.json`
- **Simplified Design**: Focuses solely on authentication; MCP server functionality moved to dedicated applications

### Flask Web Server (`flask_mcp_server.py`)
- **Flask Web App**: Auth0 OAuth integration for web-based authentication with production WSGI server (Waitress)
- **OAuth Callback Handler**: Dynamic application callback route for OAuth demonstrations at `/dynamic_application_callback`
- **Template-Based UI**: Comprehensive callback page with structured information display
- **Real Token Exchange**: Performs actual OAuth token exchange and user info retrieval when Auth0 credentials are configured
- **Integrated MCP**: Runs MCP server alongside Flask web server in unified process
- **Production Ready**: Uses Waitress WSGI server for reliable, thread-safe HTTP serving
- **Environment-Based Configuration**: Uses centralized configuration from `user_inputs.py`
- **Modular Design**: MCP functionality separated into dedicated module for better maintainability

### MCP Server (`mcp_server.py`)
- **Standalone Operation**: Can run independently or be integrated with Flask application
- **GitHub API Tools**: Provides MCP tools for interacting with GitHub's REST API
- **Token-Based Authentication**: Uses provided GitHub token for all GitHub API calls
- **FastMCP Framework**: Implements MCP protocol for tool exposure
- **Configurable Logging**: Supports verbose logging for debugging

### Configuration Management (`user_inputs.py`)
- **AppConfig dataclass**: Centralized configuration management with type safety
- **Environment Variable Loading**: Automatic loading from `.env` files with validation
- **Test Mode Support**: Bypasses validation in test environments (`TESTING=1` or `PYTEST_CURRENT_TEST`)
- **Error Handling**: Clear assertion errors for missing required environment variables
- **Backwards Compatibility**: Supports both `GITHUB_TOKEN` and `GITHUB_PERSONAL_ACCESS_TOKEN`

### MCP Tools (Available in `mcp_server.py`)
- `list_repositories()`: Fetches all repos accessible to authenticated user
- `get_repository_info(owner, repo)`: Gets detailed info for a specific repository
- `get_user_info()`: Retrieves authenticated user's profile information
- `make_github_request(url, token)`: Low-level function for GitHub API requests with proper type handling

## Environment Setup

### For GitHub OAuth and MCP Tools
Required environment variables (set in `.env` file):
- `GITHUB_CLIENT_ID`: Your GitHub OAuth app's client ID (for `client_with_oauth.py`)
- `GITHUB_CLIENT_SECRET`: Your GitHub OAuth app's client secret (for `client_with_oauth.py`)

Optional environment variables:
- `GITHUB_PERSONAL_ACCESS_TOKEN`: Personal Access Token for automated authentication (bypasses OAuth flow)
- `GITHUB_TOKEN`: GitHub token for MCP server functionality

### For Flask Web Application (Auth0)
Required environment variables for `flask_mcp_server.py`:
- `APP_SECRET_KEY`: Flask session secret key
- `AUTH0_CLIENT_ID`: Auth0 application client ID  
- `AUTH0_CLIENT_SECRET`: Auth0 application client secret
- `AUTH0_DOMAIN`: Auth0 domain (e.g., `your-domain.auth0.com`)
- `GITHUB_TOKEN`: GitHub OAuth token or Personal Access Token

Optional environment variables:
- `DYNAMIC_CLIENT_ID`: For OAuth callback demonstration
- `DYNAMIC_CLIENT_SECRET`: For OAuth callback demonstration

## Development Commands

### OAuth Client (Authentication Only)
```bash
# Authenticate and save token to github_token.json
python client_with_oauth.py

# Authenticate with verbose logging
python client_with_oauth.py -v
```

### Flask Web Server with Integrated MCP
```bash
# Set required environment variables
export GITHUB_TOKEN="your_github_token_here"
export APP_SECRET_KEY="your_secret_key"
export AUTH0_CLIENT_ID="your_auth0_client_id"
export AUTH0_CLIENT_SECRET="your_auth0_client_secret"
export AUTH0_DOMAIN="your-domain.auth0.com"

# Run Flask web app and MCP server together (default port 8080)
python flask_mcp_server.py

# Run with custom port
python flask_mcp_server.py --port 3000

# All configuration is now handled via environment variables
```

### Standalone MCP Server
```bash
# Set required environment variables
export GITHUB_TOKEN="your_github_token_here"

# Run only the MCP server (stdio transport)
python mcp_server.py

# MCP server can also be integrated with Flask application
```

### Flask Web Routes
The Flask application provides several routes:
- `/`: Home page with Auth0 authentication status
- `/login`: Auth0 OAuth login initiation
- `/callback`: Auth0 OAuth callback handler
- `/logout`: Auth0 logout and session cleanup
- `/dynamic_application_callback`: OAuth callback demonstration page with comprehensive information display

#### OAuth Callback Demonstration (`/dynamic_application_callback`)
This route demonstrates OAuth callback handling integrated from `oauth_dynamic_application.py`:
- **Purpose**: Educational demonstration of OAuth authorization code flow
- **Parameters**: Accepts `code`, `state`, `error`, `error_description`, and `scope` query parameters
- **Template-Based**: Uses `templates/callback.html` for structured information display
- **Information Display**: Shows callback details, token structure, and user information placeholders
- **Error Handling**: Comprehensive error state display with detailed messages
- **Security Features**: State parameter validation and truncation of sensitive values for display

## Token Management

- **Automatic Persistence**: Tokens are saved to `github_token.json` after successful authentication
- **Token Reuse**: Client attempts to reuse existing tokens before starting new OAuth flows
- **Personal Access Token Support**: Set `GITHUB_PERSONAL_ACCESS_TOKEN` for automated authentication
- **Token Expiration**: TODO - Token expiration checking is not yet implemented

## Logging and Debugging

Both modules support verbose logging:
- **Client**: Use `-v` flag with `client_with_oauth.py` for detailed OAuth flow logging
- **Server**: Verbose flag is automatically passed from client to server
- **Format**: `filename:line_number - LEVEL - message`

## Integration Workflow

### Current Architecture
1. **Configuration Management**: `user_inputs.py` handles all environment variable loading and validation
2. **Authentication**: `client_with_oauth.py` handles OAuth flow and saves token to `github_token.json`
3. **Application Server**: `flask_mcp_server.py` provides both web interface and MCP server functionality
4. **Unified Deployment**: Always runs both Flask and MCP services in a single process
5. **Environment-Based Configuration**: All configuration handled via environment variables with proper validation

## Dependencies

Managed via `pyproject.toml` with uv:
- `mcp[cli]`: MCP server and client framework
- `httpx`: HTTP client for GitHub API requests  
- `python-dotenv`: Environment variable loading
- `flask`: Web application framework
- `authlib`: OAuth authentication library
- `waitress`: Production WSGI server

Development dependencies:
- `pytest-asyncio`: Async test support
- `pytest-cov`: Coverage reporting (optional)

## Docker Deployment

The application includes Docker support for containerized deployment.

### Building the Docker Image

```bash
# Build the image
docker build -t flask-mcp-server .

# Or use the provided script
./docker-build.sh
```

### Running with Docker

```bash
# Run with Docker directly
docker run -p 8080:8080 -e GITHUB_TOKEN=your_token_here flask-mcp-server

# Or use the provided script
GITHUB_TOKEN=your_token_here ./docker-run.sh

# Or use docker-compose
GITHUB_TOKEN=your_token_here docker-compose up
```

### Docker Configuration

- **Base Image**: Python 3.12 slim for security and smaller size
- **Package Manager**: Uses uv for fast, reliable dependency management
- **Port**: Exposes port 8080 (configurable)
- **Security**: Runs as non-root user
- **Health Check**: Built-in health monitoring
- **Environment**: Supports all Flask and MCP environment variables

## File Status

Current files:
- ✅ `client_with_oauth.py`: Standalone GitHub OAuth authentication client
- ✅ `flask_mcp_server.py`: Flask web application with Auth0 OAuth and callback demonstration
- ✅ `mcp_server.py`: Standalone MCP server with GitHub API tools
- ✅ `user_inputs.py`: Centralized configuration management with dataclass validation
- ✅ `oauth_dynamic_application.py`: OAuth demonstration with callback server (integrated into Flask app)
- ✅ `templates/callback.html`: OAuth callback page template with comprehensive information display
- ✅ `CLAUDE.md`: This documentation file
- ✅ `.gitignore`: Updated to exclude removed files

Docker deployment:
- ✅ `Dockerfile`: Modern Docker image with uv and production WSGI server
- ✅ `docker-compose.yml`: Container orchestration configuration
- ✅ `.dockerignore`: Optimized Docker build context
- ✅ `docker-build.sh`: Build script for Docker image
- ✅ `docker-run.sh`: Run script for Docker container
- ✅ `DOCKER.md`: Comprehensive Docker deployment guide

Removed files:
- ❌ `mcp_oauth_example.py`: Replaced by `flask_mcp_server.py`
- ❌ `mcp_github.py`: Functionality merged into `flask_mcp_server.py`
- ❌ `test_oauth.sh`: Functionality integrated into `client_with_oauth.py`

## MCP Configuration

### Claude Desktop / MCP Client Configuration

The repository includes a pre-configured `mcp_config.json` for use with Claude Desktop or other MCP clients:

```json
{
  "mcpServers": {
    "github_oauth_example": {
      "command": "uv",
      "args": [
        "--directory",
        "/workspace/github/mcp-oauth-example",
        "run",
        "mcp_github.py",
        "--token",
        "${GITHUB_TOKEN}"
      ],
      "env": {
        "GITHUB_CLIENT_ID": "${GITHUB_CLIENT_ID}",
        "GITHUB_CLIENT_SECRET": "${GITHUB_CLIENT_SECRET}",
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

### Environment Setup for MCP

Set the required environment variables:
```bash
export GITHUB_TOKEN="your_github_token_here"           # Required: OAuth token or Personal Access Token
export GITHUB_CLIENT_ID="your_client_id"               # Optional: For OAuth flow reference
export GITHUB_CLIENT_SECRET="your_client_secret"       # Optional: For OAuth flow reference
```

**Note**: The MCP configuration in `mcp_config.json` references `mcp_github.py` but this file has been replaced by `flask_mcp_server.py`. Update the configuration to use the new unified application if needed.

### Testing with Claude CLI

Use the provided `test_mcp_using_claude.sh` script to test the MCP server with Claude CLI:

```bash
# Test the MCP server (requires GITHUB_TOKEN environment variable)
./test_mcp_using_claude.sh
```

The test script:
- Uses the `mcp_config.json` configuration
- Restricts Claude to only use the GitHub MCP tools via `--allowedTools`
- Demonstrates repository listing functionality
- Includes verbose logging for debugging

**Note**: The script includes a comment about forcing Claude to use the MCP tool rather than its built-in knowledge. If needed, use explicit prompts like "List all available repos using the MCP tool mcp__github_oauth_example. You MUST use the tool."

### Token Acquisition

Before using the MCP configuration, obtain a token via one of these methods:

1. **OAuth Flow**: Run `python client_with_oauth.py` and copy token from `github_token.json`
2. **Personal Access Token**: Create at https://github.com/settings/personal-access-tokens
3. **Environment Variable**: Set `GITHUB_PERSONAL_ACCESS_TOKEN` for automated authentication

## Testing

The project includes a comprehensive testing suite with 79 tests covering all functionality.

### Quick Test Commands

```bash
# Run all tests (recommended)
python run_tests.py

# Run with verbose output
python run_tests.py --verbose

# Continue running all tests even if some fail
python run_tests.py --continue-on-failure

# Quick smoke tests only
python run_tests.py --quick

# Run with coverage reporting
python run_tests.py --coverage
```

### Individual Test Suites

```bash
# Core functionality tests
python -m pytest test_oauth_updated.py -v

# Edge cases and comprehensive tests  
python -m pytest test_comprehensive.py -v

# OAuth callback route tests
python -m pytest test_callback_route.py -v

# Integration tests
python -m pytest test_mcp_integration.py -v

# Legacy test runner (redirects to updated tests)
python test_oauth_mcp.py
```

### Test Coverage

The test suite covers:
- ✅ OAuth authentication workflows (GitHub and Auth0)
- ✅ GitHub API tool functionality
- ✅ Flask web application features
- ✅ OAuth callback handling and template rendering
- ✅ MCP server protocol compliance
- ✅ Error handling and edge cases
- ✅ CLI interface and configuration
- ✅ Integration and performance scenarios
- ✅ Template rendering and user interface components

All tests use comprehensive mocking to avoid external dependencies and ensure fast, reliable execution.

### Recent Test Improvements
- ✅ **Configuration System**: Updated all tests to work with new `user_inputs.py` configuration
- ✅ **Performance Optimization**: Fixed slow tests by adding proper mocking and configuration
- ✅ **Type Safety**: Resolved all Pyright type checking issues (0 errors, 0 warnings)
- ✅ **Test Coverage**: Expanded to 79 tests covering all functionality including new configuration module
- ✅ **Fast Execution**: Complete test suite runs in ~1.5 seconds with proper mocking
- ✅ **Enhanced Test Runner**: Added `--continue-on-failure` option and improved output formatting
- ✅ **OAuth Callback Tests**: Comprehensive testing of template rendering and error handling
- ✅ **Integration Tests**: Updated MCP integration tests to work with environment-based configuration

For detailed testing information, see `TESTING.md`.
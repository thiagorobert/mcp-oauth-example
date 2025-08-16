# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is an MCP (Model Context Protocol) server that demonstrates OAuth authentication with GitHub. It provides tools for interacting with the GitHub API through the device flow OAuth process and includes both standalone authentication and integrated MCP server functionality.

## Architecture

The codebase consists of two main modules:

- **OAuth Client (`client_with_oauth.py`)**: Handles GitHub OAuth authentication and can optionally start the MCP server
- **MCP Server (`mcp_github.py`)**: FastMCP-based server that accepts tokens via command line and exposes GitHub API tools
- **Token-Based Architecture**: Server accepts pre-authenticated tokens rather than handling authentication internally
- **Threaded Operation**: Client runs MCP server in background thread for seamless integration

## Key Components

### OAuth Client (`client_with_oauth.py`)
- `authenticate()`: Main auth orchestrator that handles token loading/refreshing and OAuth flow
- `get_device_code()` and `poll_for_token()`: Implement GitHub's device flow OAuth
- `save_token()` and `load_token()`: Handle persistent token storage to `github_token.json`
- `MCPServerManager`: Manages MCP server process lifecycle and client communication
- `start_mcp_server_with_token()`: Starts server in background thread and demonstrates tool usage

### MCP Server (`mcp_github.py`)
- **Command Line Interface**: Accepts `--token` (required) and `-v/--verbose` flags
- **Token-Based Authentication**: Uses provided token for all GitHub API calls
- **FastMCP Framework**: Implements MCP protocol for tool exposure

### MCP Tools (Available in `mcp_github.py`)
- `list_repositories()`: Fetches all repos accessible to authenticated user
- `get_repository_info(owner, repo)`: Gets detailed info for a specific repository
- `get_user_info()`: Retrieves authenticated user's profile information

## Environment Setup

Required environment variables (set in `.env` file):
- `GITHUB_CLIENT_ID`: Your GitHub OAuth app's client ID
- `GITHUB_CLIENT_SECRET`: Your GitHub OAuth app's client secret

Optional environment variables:
- `GITHUB_PERSONAL_ACCESS_TOKEN`: Personal Access Token for automated authentication (bypasses OAuth flow)

## Development Commands

### OAuth Client with MCP Integration
```bash
# Authenticate only
python client_with_oauth.py

# Authenticate with verbose logging
python client_with_oauth.py -v

# Authenticate and start MCP server (demonstrates repository listing)
python client_with_oauth.py --start-mcp

# Authenticate and start MCP server with verbose logging
python client_with_oauth.py -v --start-mcp
```

### Standalone MCP Server
```bash
# Start MCP server with token (stdio transport)
python mcp_github.py --token YOUR_GITHUB_TOKEN

# Start MCP server with verbose logging
python mcp_github.py --token YOUR_GITHUB_TOKEN -v
```

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

1. **Authentication Phase**: `client_with_oauth.py` handles OAuth flow or uses Personal Access Token
2. **Server Startup**: Client launches `mcp_github.py` in background thread with obtained token
3. **Tool Demonstration**: Client creates MCP session and calls `list_repositories` tool
4. **Lifecycle Management**: Client handles graceful server shutdown on interrupt

## Dependencies

Managed via `pyproject.toml` with uv:
- `mcp[cli]`: MCP server and client framework
- `httpx`: HTTP client for GitHub API requests  
- `python-dotenv`: Environment variable loading

## File Status

Current files:
- ✅ `client_with_oauth.py`: OAuth client with MCP integration
- ✅ `mcp_github.py`: Token-based MCP server
- ✅ `CLAUDE.md`: This documentation file
- ✅ `.gitignore`: Updated to exclude removed files

Removed files:
- ❌ `mcp_oauth_example.py`: Replaced by `mcp_github.py`
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
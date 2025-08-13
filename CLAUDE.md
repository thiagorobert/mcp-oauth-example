# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is an MCP (Model Context Protocol) server that demonstrates OAuth authentication with GitHub. It provides tools for interacting with the GitHub API through the device flow OAuth process.

## Architecture

- **Single Module Design**: The entire server is implemented in `mcp_oauth_example.py` using the FastMCP framework
- **OAuth Flow**: Implements GitHub's device flow authentication pattern for CLI/headless environments
- **Token Persistence**: Stores OAuth tokens in `github_token.json` for reuse across sessions
- **MCP Integration**: Exposes GitHub API functionality as MCP tools that can be used by Claude

## Key Components

### Authentication System
- `authenticate()`: Main auth orchestrator that handles token loading/refreshing and OAuth flow
- `get_device_code()` and `poll_for_token()`: Implement GitHub's device flow OAuth
- `save_token()` and `load_token()`: Handle persistent token storage

### MCP Tools
- `list_repositories()`: Fetches all repos accessible to authenticated user
- `get_repository_info()`: Gets detailed info for a specific repo
- `get_user_info()`: Retrieves authenticated user's profile information

## Environment Setup

Required environment variables (set in `.env` file):
- `GITHUB_CLIENT_ID`: Your GitHub OAuth app's client ID
- `GITHUB_CLIENT_SECRET`: Your GitHub OAuth app's client secret

## Development Commands

### Running the MCP Server
```bash
# Direct execution for testing OAuth flow
python mcp_oauth_example.py

# Run via uv (preferred for MCP integration)
uv run mcp_oauth_example.py

# Test OAuth authentication standalone
./test_oauth.sh

# Test MCP integration with Claude
./test_mcp_using_claude.sh
```

### MCP Configuration
The server is configured in `mcp_config.json` for use with Claude Desktop or other MCP clients. It runs via uv and passes through GitHub OAuth environment variables.

## Token Management

- Tokens are automatically saved to `github_token.json` after successful authentication
- The server will attempt to reuse existing tokens before starting new OAuth flows
- TODO: Token expiration checking is not yet implemented (`mcp_oauth_example.py:55`)

## Dependencies

Managed via `pyproject.toml` with uv:
- `mcp[cli]`: MCP server framework
- `httpx`: HTTP client for API requests  
- `python-dotenv`: Environment variable loading
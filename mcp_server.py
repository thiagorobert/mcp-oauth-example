"""MCP server with GitHub API tools for OAuth demonstration.

This module contains the MCP (Model Context Protocol) server functionality
that was extracted from flask_mcp_server.py for better separation of concerns.
"""

import logging
from typing import Any, Dict, List, Optional, Union

import httpx
from mcp.server.fastmcp import FastMCP

# Set up module-specific logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Constants for GitHub API
GITHUB_API_BASE = "https://api.github.com"
USER_AGENT = "github-oauth-mcp-flask/1.0"

# Global variable to store GitHub access token for MCP server
_github_access_token = None

# Initialize FastMCP server
mcp = FastMCP("github_oauth_example")


def set_github_token(token: Optional[str]):
    """Set the GitHub access token for MCP tools."""
    global _github_access_token
    _github_access_token = token
    logger.debug(
        f"GitHub token set for MCP server: {'***' + token[-4:] if token else 'None'}")


def get_github_token() -> Optional[str]:
    """Get the current GitHub access token."""
    return _github_access_token


async def make_github_request(
    url: str, token: Optional[str] = None
) -> Optional[Union[Dict[str, Any], List[Dict[str, Any]]]]:
    """Make a request to the GitHub API with proper error handling."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github.v3+json"
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.debug(f"GitHub API request failed: {e}")
            return None


@mcp.tool()
async def list_repositories() -> str:
    """List all repositories accessible to the authenticated user."""
    logger.debug("Starting list_repositories tool...")

    if not _github_access_token:
        return (
            "No GitHub authentication token available. Please set GITHUB_TOKEN "
            "environment variable or use --token argument.")

    url = f"{GITHUB_API_BASE}/user/repos"
    data = await make_github_request(url, _github_access_token)

    if not data:
        return "Unable to fetch repositories."

    if not data or not isinstance(data, list):
        return "No repositories found."

    repos = []
    for repo in data:
        if not isinstance(repo, dict):
            continue
        repo_info = f"""
Repository: {repo.get('full_name', 'Unknown')}
Description: {repo.get('description', 'No description')}
Language: {repo.get('language', 'Unknown')}
Stars: {repo.get('stargazers_count', 0)}
Private: {repo.get('private', False)}
URL: {repo.get('html_url', 'Unknown')}
"""
        repos.append(repo_info)

    return "\n---\n".join(repos)


@mcp.tool()
async def get_repository_info(owner: str, repo: str) -> str:
    """Get detailed information about a specific repository.

    Args:
        owner: Repository owner (username or organization)
        repo: Repository name
    """
    if not _github_access_token:
        return "No GitHub authentication token available."

    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    data = await make_github_request(url, _github_access_token)

    if not data or not isinstance(data, dict):
        return f"Unable to fetch information for repository {owner}/{repo}."

    return f"""
Repository: {data.get('full_name', f'{owner}/{repo}')}
Description: {data.get('description', 'No description')}
Language: {data.get('language', 'Unknown')}
Stars: {data.get('stargazers_count', 0)}
Forks: {data.get('forks_count', 0)}
Issues: {data.get('open_issues_count', 0)}
Created: {data.get('created_at', 'Unknown')}
Updated: {data.get('updated_at', 'Unknown')}
Private: {data.get('private', False)}
URL: {data.get('html_url', 'Unknown')}
Clone URL: {data.get('clone_url', 'Unknown')}
"""


@mcp.tool()
async def get_user_info() -> str:
    """Get information about the authenticated user."""
    if not _github_access_token:
        return "No GitHub authentication token available."

    url = f"{GITHUB_API_BASE}/user"
    data = await make_github_request(url, _github_access_token)

    if not data or not isinstance(data, dict):
        return "Unable to fetch user information."

    return f"""
Username: {data.get('login', 'Unknown')}
Name: {data.get('name', 'Not set')}
Email: {data.get('email', 'Not public')}
Bio: {data.get('bio', 'No bio')}
Location: {data.get('location', 'Not set')}
Public Repos: {data.get('public_repos', 0)}
Followers: {data.get('followers', 0)}
Following: {data.get('following', 0)}
Profile URL: {data.get('html_url', 'Unknown')}
"""


def run_mcp_server():
    """Run the MCP server in stdio mode."""
    logger.debug("Starting MCP server...")
    mcp.run(transport='stdio')


def get_mcp_instance():
    """Get the MCP server instance for integration with other applications."""
    return mcp

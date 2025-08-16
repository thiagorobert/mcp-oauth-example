import argparse
import asyncio
import dotenv
import httpx
import json
import logging
import os
from mcp.server.fastmcp import FastMCP
from typing import Any

# Set up module-specific logger with DEBUG level
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Logger handler will be configured based on verbose flag
_verbose_mode = False

def setup_logging(verbose: bool = False):
    """Configure logging based on verbose flag."""
    global _verbose_mode
    _verbose_mode = verbose
    
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    if verbose:
        # Create handler for stdout output when verbose mode is enabled
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(filename)s:%(lineno)d - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

# Constants
GITHUB_API_BASE = "https://api.github.com"
USER_AGENT = "github-oauth-mcp/1.0"

# Global variable to store access token
_access_token = None

# Initialize FastMCP server
mcp = FastMCP("github_oauth_example")

async def make_github_request(url: str, token: str = None) -> dict[str, Any] | None:
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
    
    url = f"{GITHUB_API_BASE}/user/repos"
    data = await make_github_request(url, _access_token)
    
    if not data:
        return "Unable to fetch repositories."
    
    if not data:
        return "No repositories found."
    
    repos = []
    for repo in data:
        repo_info = f"""
Repository: {repo['full_name']}
Description: {repo.get('description', 'No description')}
Language: {repo.get('language', 'Unknown')}
Stars: {repo['stargazers_count']}
Private: {repo['private']}
URL: {repo['html_url']}
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
    if not _access_token:
        return "No authentication token available."
    
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    data = await make_github_request(url, _access_token)
    
    if not data:
        return f"Unable to fetch information for repository {owner}/{repo}."
    
    return f"""
Repository: {data['full_name']}
Description: {data.get('description', 'No description')}
Language: {data.get('language', 'Unknown')}
Stars: {data['stargazers_count']}
Forks: {data['forks_count']}
Issues: {data['open_issues_count']}
Created: {data['created_at']}
Updated: {data['updated_at']}
Private: {data['private']}
URL: {data['html_url']}
Clone URL: {data['clone_url']}
"""

@mcp.tool()
async def get_user_info() -> str:
    """Get information about the authenticated user."""
    if not _access_token:
        return "No authentication token available."
    
    url = f"{GITHUB_API_BASE}/user"
    data = await make_github_request(url, _access_token)
    
    if not data:
        return "Unable to fetch user information."
    
    return f"""
Username: {data['login']}
Name: {data.get('name', 'Not set')}
Email: {data.get('email', 'Not public')}
Bio: {data.get('bio', 'No bio')}
Location: {data.get('location', 'Not set')}
Public Repos: {data['public_repos']}
Followers: {data['followers']}
Following: {data['following']}
Profile URL: {data['html_url']}
"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GitHub MCP server with OAuth token")
    parser.add_argument("--token", required=True, help="GitHub OAuth access token")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Enable verbose logging to stdout")
    args = parser.parse_args()
    
    # Configure logging based on verbose flag
    setup_logging(args.verbose)
    
    # Set the global access token
    _access_token = args.token
    
    mcp.run(transport='stdio')

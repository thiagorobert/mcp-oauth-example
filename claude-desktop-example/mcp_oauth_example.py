import asyncio
import dotenv
import httpx
import json
from mcp.server.fastmcp import FastMCP
import os
import time
from typing import Any


dotenv.load_dotenv()  # load environment variables from .env

# Initialize FastMCP server
mcp = FastMCP("github_oauth_example")

# Constants
GITHUB_API_BASE = "https://api.github.com"
GITHUB_DEVICE_CODE_URL = "https://github.com/login/device/code"
GITHUB_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_AGENT = "github-oauth-mcp/1.0"
TOKEN_FILE = "github_token.json"  # Token storage file

# OAuth configuration - set these as environment variables
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")

# Global variable to store access token
_access_token = None


def save_token(token: str):
    """Save access token to file."""
    import time
    token_data = {
        "access_token": token,
        "created_at": time.time()
    }
    try:
        with open(TOKEN_FILE, 'w') as f:
            json.dump(token_data, f)
        print(f"Token saved to {TOKEN_FILE}")
    except Exception as e:
        print(f"Failed to save token: {e}")

def load_token() -> str | None:
    """Load access token from file if it exists and is valid."""
    try:
        with open(TOKEN_FILE, 'r') as f:
            token_data = json.load(f)
        
        # Check if token exists
        if "access_token" not in token_data:
            return None
            
        # TODO: check if token is expired

        print(f"Token loaded from {TOKEN_FILE}")
        return token_data["access_token"]
        
    except FileNotFoundError:
        print(f"No token file found at {TOKEN_FILE}")
        return None
    except Exception as e:
        print(f"Failed to load token: {e}")
        return None

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
            print(f"GitHub API request failed: {e}")
            return None

async def get_device_code() -> dict[str, Any] | None:
    """Start the OAuth device flow by requesting device and user codes."""
    if not GITHUB_CLIENT_ID:
        raise ValueError("GITHUB_CLIENT_ID environment variable not set")
    
    data = {
        "client_id": GITHUB_CLIENT_ID,
        "scope": "repo read:user"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                GITHUB_DEVICE_CODE_URL,
                data=data,
                headers={"Accept": "application/json"}
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Failed to get device code: {e}")
            return None

async def poll_for_token(device_code: str, interval: int = 5) -> str | None:
    """Poll GitHub for the access token."""
    if not GITHUB_CLIENT_ID:
        raise ValueError("GITHUB_CLIENT_ID environment variable not set")
    
    data = {
        "client_id": GITHUB_CLIENT_ID,
        "device_code": device_code,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
    }
    
    async with httpx.AsyncClient() as client:
        while True:
            try:
                response = await client.post(
                    GITHUB_ACCESS_TOKEN_URL,
                    data=data,
                    headers={"Accept": "application/json"}
                )
                
                result = response.json()
                
                if "access_token" in result:
                    return result["access_token"]
                elif result.get("error") == "authorization_pending":
                    await asyncio.sleep(interval)
                    continue
                elif result.get("error") == "slow_down":
                    interval += 5
                    await asyncio.sleep(interval)
                    continue
                elif result.get("error") == "access_denied":
                    print("User denied access")
                    return None
                else:
                    print(f"Unknown error: {result}")
                    return None
                    
            except Exception as e:
                print(f"Error polling for token: {e}")
                await asyncio.sleep(interval)

async def authenticate() -> str | None:
    """Complete OAuth device flow and return access token."""
    global _access_token
    
    print("Starting authentication process...")
    
    if _access_token:
        print(" Using existing access token")
        return _access_token
    _access_token = load_token()
    if _access_token:
        print(" Using existing access token read from file")
        return _access_token
    
    print("No existing token, starting OAuth device flow...")
    
    # Start device flow
    device_info = await get_device_code()
    if not device_info:
        print(" Failed to get device code")
        return None
    
    print(f"\nGitHub OAuth Authentication Required:")
    print(f" 1. Go to: {device_info['verification_uri']}")
    print(f" 2. Enter code: {device_info['user_code']}")
    print(f" 3. Waiting for authentication...")
    print(f" (Code expires in {device_info.get('expires_in', 900)} seconds)")
    
    # Poll for token
    _access_token = await poll_for_token(
        device_info["device_code"], 
        device_info.get("interval", 5)
    )
    
    if _access_token:
        print("Authentication successful!")
        save_token(_access_token)  # Save token to file
    else:
        print("Authentication failed")
    
    return _access_token

@mcp.tool()
async def list_repositories() -> str:
    """List all repositories accessible to the authenticated user."""
    print("Starting list_repositories tool...")
    print(f"GITHUB_CLIENT_ID set: {bool(GITHUB_CLIENT_ID)}")
    print(f"GITHUB_CLIENT_SECRET set: {bool(GITHUB_CLIENT_SECRET)}")
    
    token = await authenticate()
    
    if not token:
        return "Authentication failed. Please check your GitHub OAuth app configuration."
    
    url = f"{GITHUB_API_BASE}/user/repos"
    data = await make_github_request(url, token)
    
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
    token = await authenticate()
    if not token:
        return "Authentication failed. Please check your GitHub OAuth app configuration."
    
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    data = await make_github_request(url, token)
    
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
    token = await authenticate()
    if not token:
        return "Authentication failed. Please check your GitHub OAuth app configuration."
    
    url = f"{GITHUB_API_BASE}/user"
    data = await make_github_request(url, token)
    
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
    assert GITHUB_CLIENT_ID, "GITHUB_CLIENT_ID not available"
    assert GITHUB_CLIENT_SECRET, "GITHUB_CLIENT_SECRET not available"
    print("here")
    mcp.run(transport='stdio')

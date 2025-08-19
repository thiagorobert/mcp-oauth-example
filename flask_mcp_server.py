"""Merged Flask web application with MCP server functionality.

This application combines:
- Flask web server with Auth0 OAuth authentication (HTTP interface)
- MCP server with GitHub API tools (stdio transport for MCP clients)
"""

import argparse
import httpx
import json
import logging
import threading
from os import environ as env
from urllib.parse import quote_plus, urlencode
from typing import Any

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for
from mcp.server.fastmcp import FastMCP
from waitress import serve

# Load environment variables
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

# Set up module-specific logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def setup_logging(verbose: bool = False):
    """Configure logging based on verbose flag."""
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

# Constants for GitHub API
GITHUB_API_BASE = "https://api.github.com"
USER_AGENT = "github-oauth-mcp-flask/1.0"

# Global variable to store GitHub access token for MCP server
_github_access_token = None

# Initialize Flask app
app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

# Initialize OAuth
oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

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
    
    if not _github_access_token:
        return "No GitHub authentication token available. Please set GITHUB_TOKEN environment variable or use --token argument."
    
    url = f"{GITHUB_API_BASE}/user/repos"
    data = await make_github_request(url, _github_access_token)
    
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
    if not _github_access_token:
        return "No GitHub authentication token available."
    
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    data = await make_github_request(url, _github_access_token)
    
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
    if not _github_access_token:
        return "No GitHub authentication token available."
    
    url = f"{GITHUB_API_BASE}/user"
    data = await make_github_request(url, _github_access_token)
    
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

# Flask routes
@app.route("/")
def home():
    return render_template(
        "home.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

def run_mcp_server():
    """Run the MCP server in stdio mode."""
    logger.debug("Starting MCP server...")
    mcp.run(transport='stdio')

def run_flask_server(port: int = 8080):
    """Run the Flask web server using Waitress (production WSGI server)."""
    logger.debug(f"Starting Flask server with Waitress on port {port}...")
    
    # Use Waitress as the production WSGI server
    # Waitress is thread-safe and works well in background threads
    serve(
        app,
        host='0.0.0.0',
        port=port,
        threads=4,  # Number of threads to handle requests
        connection_limit=100,  # Maximum number of connections
        cleanup_interval=30,  # Cleanup interval in seconds
        channel_timeout=120,  # Channel timeout in seconds
        log_socket_errors=True,  # Log socket errors
        max_request_header_size=262144,  # 256KB max header size
        max_request_body_size=1073741824,  # 1GB max body size
        expose_tracebacks=False,  # Don't expose tracebacks in production
        ident='waitress-flask-mcp-server'  # Server identification
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Flask web app with MCP server")
    parser.add_argument("--token", help="GitHub OAuth access token (for MCP functionality)")
    parser.add_argument("--port", type=int, default=8080, help="Flask server port (default: 8080)")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Enable verbose logging")
    args = parser.parse_args()
    
    # Configure logging
    setup_logging(args.verbose)
    
    # Set GitHub token from argument or environment
    if args.token:
        _github_access_token = args.token
    else:
        _github_access_token = env.get("GITHUB_TOKEN") or env.get("GITHUB_PERSONAL_ACCESS_TOKEN")
    
    # Always run in both mode - Flask web server and MCP server together
    flask_vars = ["APP_SECRET_KEY", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET", "AUTH0_DOMAIN"]
    missing_flask_vars = [var for var in flask_vars if not env.get(var)]
    
    if missing_flask_vars:
        print(f"Warning: Missing Flask environment variables: {', '.join(missing_flask_vars)}")
        print("Flask web server will not start. Only MCP server will run.")
        if not _github_access_token:
            print("Error: GitHub token also required for MCP mode. Use --token or set GITHUB_TOKEN environment variable.")
            exit(1)
        run_mcp_server()
    else:
        if not _github_access_token:
            print("Warning: No GitHub token available. MCP tools will not function properly.")
        
        # Run both Flask and MCP server
        # MCP server runs in stdio mode, so Flask must run in a separate thread
        flask_thread = threading.Thread(target=run_flask_server, args=(args.port,), daemon=True)
        flask_thread.start()
        
        print(f"Flask server starting on port {args.port}")
        print("MCP server starting on stdio...")
        print("Use Ctrl+C to stop both servers")
        
        try:
            run_mcp_server()
        except KeyboardInterrupt:
            print("\nShutting down servers...")
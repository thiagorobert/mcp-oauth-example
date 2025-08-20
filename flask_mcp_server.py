"""Flask web application with integrated MCP server functionality.

This application combines:
- Flask web server with Auth0 OAuth authentication (HTTP interface)
- MCP server with GitHub API tools (stdio transport for MCP clients)

The MCP server logic is implemented in mcp_server.py for better separation of concerns.
"""

import argparse
import json
import logging
import threading
import urllib.parse
from datetime import datetime
from os import environ as env
from typing import Any
from urllib.parse import quote_plus, urlencode

import requests
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for
from waitress import serve

# Import MCP server functionality
from mcp_server import run_mcp_server, set_github_token

# Load environment variables
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

# Set up module-specific logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# Global variable to store GitHub access token for MCP server
_github_access_token = None


class OAuth2Client:
    """OAuth2 client for Auth0 authentication - integrated from
    oauth_dynamic_application_no_server.py"""

    def __init__(self, client_id: str, client_secret: str, auth0_domain: str,
                 redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth0_domain = auth0_domain
        self.authorization_url = f"https://{auth0_domain}/authorize"
        self.token_url = f"https://{auth0_domain}/oauth/token"
        self.userinfo_url = f"https://{auth0_domain}/userinfo"
        self.redirect_uri = redirect_uri

    def generate_auth_url(self, state: str) -> str:
        """Generate the authorization URL for OAuth flow."""
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'openid profile email',
            'state': state,
        }

        query_string = urllib.parse.urlencode(params)
        auth_url = f"{self.authorization_url}?{query_string}"

        logger.debug(f"Generated auth URL: {auth_url}")
        return auth_url

    def exchange_code_for_token(self, code: str) -> dict[str, Any] | None:
        """Exchange authorization code for access token."""
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.redirect_uri,
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        logger.debug("Exchanging authorization code for token...")

        try:
            response = requests.post(self.token_url, data=token_data, headers=headers, timeout=30)
            response.raise_for_status()

            token_response = response.json()
            logger.debug(f"Token response received: {list(token_response.keys())}")

            return token_response

        except requests.exceptions.RequestException as e:
            logger.error(f"Token exchange failed: {e}")
            return None

    def get_user_info(self, access_token: str) -> dict[str, Any] | None:
        """Get user information using access token."""
        headers = {
            'Authorization': f'Bearer {access_token}'
        }

        try:
            response = requests.get(self.userinfo_url, headers=headers, timeout=30)
            response.raise_for_status()

            user_info = response.json()
            logger.debug(f"User info received: {list(user_info.keys())}")

            return user_info

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get user info: {e}")
            return None


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

# MCP server functionality is now in mcp_server.py

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


@app.route("/dynamic_application_callback")
def dynamic_application_callback():
    """Handle OAuth callback with actual token exchange and user info retrieval."""

    # Extract callback parameters from query string
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    error_description = request.args.get('error_description')
    scope = request.args.get('scope')

    # Prepare callback information
    callback_info = {
        'code': code,
        'state': state,
        'error': error,
        'error_description': error_description,
        'scope': scope,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    }

    success = bool(code and not error)
    error_message = error_description if error else None
    token_info = None
    user_info = None

    # If there's a code and Auth0 credentials are available, attempt token exchange
    if (code and success and env.get("DYNAMIC_CLIENT_ID") and
            env.get("DYNAMIC_CLIENT_SECRET") and env.get("AUTH0_DOMAIN")):
        try:
            # Create OAuth client with callback URL
            redirect_uri = url_for("dynamic_application_callback", _external=True)
            oauth_client = OAuth2Client(
                client_id=env.get("DYNAMIC_CLIENT_ID"),
                client_secret=env.get("DYNAMIC_CLIENT_SECRET"),
                auth0_domain=env.get("AUTH0_DOMAIN"),
                redirect_uri=redirect_uri
            )

            # Exchange code for token
            logger.debug(f"Attempting token exchange with redirect_uri: {redirect_uri}")
            token_response = oauth_client.exchange_code_for_token(code)

            if token_response:
                token_info = {
                    'access_token': token_response.get('access_token'),
                    'token_type': token_response.get('token_type'),
                    'expires_in': token_response.get('expires_in'),
                    'id_token': token_response.get('id_token'),
                    'refresh_token': token_response.get('refresh_token'),
                    'scope': token_response.get('scope')
                }

                # Get user info if we have an access token
                if token_response.get('access_token'):
                    user_response = oauth_client.get_user_info(token_response['access_token'])
                    if user_response:
                        user_info = {
                            'name': user_response.get('name'),
                            'email': user_response.get('email'),
                            'sub': user_response.get('sub'),
                            'picture': user_response.get('picture'),
                            'nickname': user_response.get('nickname'),
                            'email_verified': user_response.get('email_verified'),
                            'updated_at': user_response.get('updated_at')
                        }
                    else:
                        logger.warning("Failed to retrieve user information")
                else:
                    logger.warning("No access token received from token exchange")
            else:
                logger.error("Token exchange failed")
                error_message = "Failed to exchange authorization code for token"
                success = False

        except Exception as e:
            logger.error(f"Error during token exchange: {e}")
            error_message = f"Token exchange error: {str(e)}"
            success = False

    elif code and success:
        # Auth0 credentials not available, show placeholder info
        logger.info("Auth0 credentials not configured, showing placeholder information")
        token_info = {
            'access_token': 'Auth0 credentials required for token exchange',
            'token_type': 'bearer',
            'expires_in': 3600,
            'id_token': 'Would contain ID token'
        }
        user_info = {
            'name': 'Auth0 credentials required for user info',
            'email': 'Configure AUTH0_* environment variables',
            'sub': 'to enable real token exchange',
            'picture': None
        }

    return render_template(
        'callback.html',
        success=success,
        error_message=error_message,
        error_description=error_description,
        callback_info=callback_info,
        token_info=token_info,
        user_info=user_info,
        auto_close=False,
        auto_close_delay=3000
    )

# MCP server run function is now imported from mcp_server.py


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
    args = parser.parse_args()

    # Set GitHub token from argument or environment
    if args.token:
        _github_access_token = args.token
    else:
        _github_access_token = env.get("GITHUB_TOKEN") or env.get("GITHUB_PERSONAL_ACCESS_TOKEN")

    # Set the token in the MCP server
    set_github_token(_github_access_token)

    # Always run in both mode - Flask web server and MCP server together
    flask_vars = ["APP_SECRET_KEY", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET", "AUTH0_DOMAIN"]
    missing_flask_vars = [var for var in flask_vars if not env.get(var)]

    if missing_flask_vars:
        print(f"Warning: Missing Flask environment variables: {', '.join(missing_flask_vars)}")
        print("Flask web server will not start. Only MCP server will run.")
        if not _github_access_token:
            print("Error: GitHub token also required for MCP mode. Use --token or set "
                  "GITHUB_TOKEN environment variable.")
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

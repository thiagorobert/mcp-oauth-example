"""Flask web application with integrated MCP server functionality.

This application combines:
- Flask web server with Auth0 OAuth authentication (HTTP interface)
- MCP server with GitHub API tools (stdio transport for MCP clients)

The MCP server logic is implemented in mcp_server.py for better separation of concerns.
"""

import argparse
import json
import threading
import urllib.parse
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote_plus, urlencode

import requests
from authlib.integrations.flask_client import OAuth
from flask import (Flask, redirect, render_template, render_template_string,
                   request, session, url_for)
from waitress import serve

import logging_config
# Import token decoding functionality
from decode import decode_token, format_timestamp
from mcp_server import run_mcp_server, set_github_token
from user_inputs import get_config

# Set up module-specific logger
logger = logging_config.configure_logger("flask_mcp_server")

# Load configuration
config = get_config()


class OAuth2Client:
    """OAuth2 client for Auth0 authentication."""

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
            response = requests.post(
                self.token_url,
                data=token_data,
                headers=headers,
                timeout=30)
            response.raise_for_status()

            token_response = response.json()
            logger.debug(
                f"Token response received: {
                    list(
                        token_response.keys())}")

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
            response = requests.get(
                self.userinfo_url, headers=headers, timeout=30)
            response.raise_for_status()

            user_info = response.json()
            logger.debug(f"User info received: {list(user_info.keys())}")

            return user_info

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get user info: {e}")
            return None


# Initialize Flask app
app = Flask(__name__)
app.secret_key = config.app_secret_key

# Initialize OAuth
oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=config.auth0_client_id,
    client_secret=config.auth0_client_secret,
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{config.auth0_domain}/.well-known/openid-configuration',
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
    if oauth.auth0 is None:
        raise RuntimeError("Auth0 client not properly initialized")
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")


@app.route("/login")
def login():
    if oauth.auth0 is None:
        raise RuntimeError("Auth0 client not properly initialized")
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + config.auth0_domain
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": config.auth0_client_id,
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

    # If there's a code and Auth0 credentials are available, attempt token
    # exchange
    if (code and success and config.dynamic_client_id and
            config.dynamic_client_secret and config.auth0_domain):
        try:
            # Create OAuth client with callback URL
            redirect_uri = url_for(
                "dynamic_application_callback",
                _external=True)
            oauth_client = OAuth2Client(
                client_id=config.dynamic_client_id,
                client_secret=config.dynamic_client_secret,
                auth0_domain=config.auth0_domain,
                redirect_uri=redirect_uri
            )

            # Exchange code for token
            logger.debug(
                f"Attempting token exchange with redirect_uri: {redirect_uri}")
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
                    user_response = oauth_client.get_user_info(
                        token_response['access_token'])
                    if user_response:
                        user_info = {
                            'name': user_response.get('name'),
                            'email': user_response.get('email'),
                            'sub': user_response.get('sub'),
                            'picture': user_response.get('picture'),
                            'nickname': user_response.get('nickname'),
                            'email_verified': user_response.get('email_verified'),
                            'updated_at': user_response.get('updated_at')}
                    else:
                        logger.warning("Failed to retrieve user information")
                else:
                    logger.warning(
                        "No access token received from token exchange")
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
        logger.info(
            "Auth0 credentials not configured, showing placeholder information")
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


@app.route("/decode")
def decode():
    """Decode JWT/JWE tokens and display formatted information."""
    token = request.args.get('token')
    token_type = request.args.get('type', 'unknown')

    if not token:
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Token Decoder - Error</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    max-width: 800px; 
                    margin: 2rem auto; 
                    padding: 2rem; 
                }
                .error { 
                    color: #dc3545; 
                    border: 2px solid #dc3545; 
                    background-color: #f8d7da; 
                    padding: 1rem; 
                    border-radius: 4px; 
                }
            </style>
        </head>
        <body>
            <div class="error">
                <h2>❌ Missing Token</h2>
                <p>No token provided for decoding. 
                   Please provide a token parameter.</p>
            </div>
        </body>
        </html>
        """)

    try:
        # Get secret keys from config for JWE decoding
        secret_keys = {}
        if config.app_secret_key:
            secret_keys['APP_SECRET_KEY'] = config.app_secret_key
        if config.auth0_client_secret:
            secret_keys['AUTH0_CLIENT_SECRET'] = config.auth0_client_secret

        # Decode the token
        (header, payload, signature), decoded_type = decode_token(token, secret_keys)

        # Format payload with descriptions
        claim_descriptions = {
            'iss': 'Issuer',
            'sub': 'Subject',
            'aud': 'Audience',
            'exp': 'Expiration Time',
            'nbf': 'Not Before',
            'iat': 'Issued At',
            'jti': 'JWT ID',
            'name': 'Full Name',
            'nickname': 'Nickname',
            'email': 'Email',
            'picture': 'Profile Picture',
            'updated_at': 'Last Updated',
            'sid': 'Session ID',
            'nonce': 'Nonce'
        }

        formatted_payload = {}
        for key, value in payload.items():
            description = claim_descriptions.get(key, key.title())

            # Format timestamps
            if key in [
                    'exp', 'nbf', 'iat'] and isinstance(
                    value, (int, float)):
                formatted_value = f"{value} ({format_timestamp(value)})"
            else:
                formatted_value = value

            formatted_payload[f"{description} ({key})"] = formatted_value

        # Check token validity
        current_time = datetime.now(timezone.utc).timestamp()
        validity_info = {}

        if 'iat' in payload:
            validity_info['issued_at'] = format_timestamp(payload['iat'])

        if 'exp' in payload:
            exp_time = payload['exp']
            validity_info['expires_at'] = format_timestamp(exp_time)

            if current_time > exp_time:
                validity_info['status'] = 'EXPIRED'
                validity_info['status_class'] = 'expired'
            else:
                time_left = exp_time - current_time
                hours_left = int(time_left // 3600)
                minutes_left = int((time_left % 3600) // 60)
                validity_info['status'] = f'VALID (expires in {hours_left}h {minutes_left}m)'
                validity_info['status_class'] = 'valid'

        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Token Decoder - {{ decoded_type }}</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    max-width: 1000px;
                    margin: 2rem auto;
                    padding: 2rem;
                    background-color: #f8f9fa;
                    color: #333;
                }
                .container {
                    background: white;
                    border-radius: 8px;
                    padding: 2rem;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                .section {
                    margin: 1.5rem 0;
                    padding: 1rem;
                    background-color: #f8f9fa;
                    border-radius: 4px;
                    border-left: 4px solid #007bff;
                }
                .json-content {
                    background-color: #2d3748;
                    color: #e2e8f0;
                    padding: 1rem;
                    border-radius: 4px;
                    font-family: 'Monaco', 'Consolas', monospace;
                    font-size: 0.9rem;
                    overflow-x: auto;
                    white-space: pre-wrap;
                }
                .validity {
                    padding: 0.75rem;
                    border-radius: 4px;
                    margin-top: 1rem;
                }
                .valid {
                    background-color: #d4edda;
                    color: #155724;
                    border: 1px solid #c3e6cb;
                }
                .expired {
                    background-color: #f8d7da;
                    color: #721c24;
                    border: 1px solid #f5c6cb;
                }
                .info-grid {
                    display: grid;
                    grid-template-columns: 1fr 2fr;
                    gap: 0.5rem;
                    margin-top: 1rem;
                }
                .info-label {
                    font-weight: bold;
                    color: #495057;
                }
                .info-value {
                    font-family: 'Monaco', 'Consolas', monospace;
                    background-color: #e9ecef;
                    padding: 0.25rem 0.5rem;
                    border-radius: 3px;
                    font-size: 0.9rem;
                }
                .btn {
                    display: inline-block;
                    padding: 0.5rem 1rem;
                    margin-top: 1rem;
                    background-color: #6c757d;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                }
                .btn:hover {
                    background-color: #5a6268;
                    color: white;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 {{ decoded_type }} Token Decoder</h1>
                <p><strong>Token Type:</strong> {{ token_type.title() }} Token</p>

                <div class="section">
                    <h3>📋 Header</h3>
                    <div class="json-content">{{ header | tojson(indent=2) }}</div>
                </div>

                <div class="section">
                    <h3>📦 Payload</h3>
                    <div class="json-content">{{ formatted_payload | tojson(indent=2) }}</div>
                </div>

                {% if validity_info %}
                <div class="section">
                    <h3>⏰ Token Validity</h3>
                    <div class="info-grid">
                        {% if validity_info.issued_at %}
                        <div class="info-label">Issued:</div>
                        <div class="info-value">{{ validity_info.issued_at }}</div>
                        {% endif %}

                        {% if validity_info.expires_at %}
                        <div class="info-label">Expires:</div>
                        <div class="info-value">{{ validity_info.expires_at }}</div>
                        {% endif %}
                    </div>

                    {% if validity_info.status %}
                    <div class="validity {{ validity_info.status_class }}">
                        <strong>Status:</strong> {{ validity_info.status }}
                    </div>
                    {% endif %}
                </div>
                {% endif %}

                {% if signature %}
                <div class="section">
                    <h3>🔐 Signature</h3>
                    <div class="info-grid">
                        <div class="info-label">Base64URL:</div>
                        <div class="info-value">{{ signature[:50] }}...</div>
                        <div class="info-label">Length:</div>
                        <div class="info-value">{{ signature|length }} characters</div>
                    </div>
                </div>
                {% else %}
                <div class="section">
                    <h3>🔐 Encryption</h3>
                    <p>This token was encrypted (JWE) and has been successfully decrypted.</p>
                </div>
                {% endif %}

                <a href="javascript:window.close()" class="btn">Close Window</a>
            </div>
        </body>
        </html>
        """,
                                      decoded_type=decoded_type,
                                      token_type=token_type,
                                      header=header,
                                      formatted_payload=formatted_payload,
                                      signature=signature,
                                      validity_info=validity_info
                                      )

    except ValueError as e:
        logger.error(f"Token decoding error: {e}")
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Token Decoder - Error</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    max-width: 800px; 
                    margin: 2rem auto; 
                    padding: 2rem; 
                }
                .error { 
                    color: #dc3545; 
                    border: 2px solid #dc3545; 
                    background-color: #f8d7da; 
                    padding: 1rem; 
                    border-radius: 4px; 
                }
                .btn { display: inline-block; padding: 0.5rem 1rem; margin-top: 1rem; background-color: #6c757d; color: white; text-decoration: none; border-radius: 4px; }
            </style>
        </head>
        <body>
            <div class="error">
                <h2>❌ Token Decoding Failed</h2>
                <p>Unable to decode the provided token: {{ error }}</p>
                <p>The token may be malformed, encrypted with an unknown key, or not a valid JWT/JWE token.</p>
            </div>
            <a href="javascript:window.close()" class="btn">Close Window</a>
        </body>
        </html>
        """, error=str(e))


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
    parser = argparse.ArgumentParser(
        description="Flask web app with MCP server")
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Flask server port (default: 8080)")
    args = parser.parse_args()

    # Set the GitHub token in the MCP server
    set_github_token(config.github_token)

    # Run both Flask and MCP server together
    # MCP server runs in stdio mode, so Flask must run in a separate thread
    flask_thread = threading.Thread(
        target=run_flask_server, args=(
            args.port,), daemon=True)
    flask_thread.start()

    print(f"Flask server starting on port {args.port}")
    print("MCP server starting on stdio...")
    print("Use Ctrl+C to stop both servers")

    try:
        run_mcp_server()
    except KeyboardInterrupt:
        print("\nShutting down servers...")

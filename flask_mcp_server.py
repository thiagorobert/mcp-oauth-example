"""Flask web application with integrated MCP server functionality.

This application combines:
- Flask web server with Auth0 OAuth authentication (HTTP interface)
- MCP server with GitHub API tools (stdio transport for MCP clients)

The MCP server logic is implemented in mcp_server.py for better separation of concerns.
"""

import argparse
import json
import os
import threading
import urllib.parse
from datetime import datetime, timezone
from typing import Any

import requests
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, render_template, request, session, url_for
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

# Global port variable (set at startup)
flask_port = 8080


class OAuth2Client:
    """OAuth2 client for Auth0 authentication."""

    def __init__(self, client_id: str, client_secret: str, auth0_domain: str,
                 redirect_uri: str, port: int = 8080):
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth0_domain = auth0_domain
        self.authorization_url = f"https://{auth0_domain}/authorize"
        self.token_url = f"https://{auth0_domain}/oauth/token"
        self.userinfo_url = f"https://{auth0_domain}/userinfo"
        self.redirect_uri = redirect_uri
        self.port = port

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


# Flask routes
@app.route("/")
def home():
    user_data = session.get("user")
    return render_template(
        "home.html",
        session=user_data,
        raw_json=json.dumps(user_data, indent=4) if user_data else None,
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
    logout_url = (
        "https://" +
        config.auth0_domain +
        "/v2/logout?" +
        urllib.parse.urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": config.auth0_client_id,
            },
            quote_via=urllib.parse.quote_plus,
        )
    )
    return redirect(logout_url)


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
    if (code and success and config.dynamic_client_id
            and config.dynamic_client_secret and config.auth0_domain):
        try:
            # Create OAuth client with callback URL
            redirect_uri = url_for(
                "dynamic_application_callback",
                _external=True)
            oauth_client = OAuth2Client(
                client_id=config.dynamic_client_id,
                client_secret=config.dynamic_client_secret,
                auth0_domain=config.auth0_domain,
                redirect_uri=redirect_uri,
                port=flask_port
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

    # Prepare raw JSON data for display
    raw_data = {
        'success': success,
        'callback_info': callback_info.__dict__ if hasattr(callback_info, '__dict__') else callback_info,
        'token_info': token_info,
        'user_info': user_info,
        'error_message': error_message,
        'error_description': error_description
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
        auto_close_delay=3000,
        raw_json=json.dumps(raw_data, indent=4)
    )


@app.route("/decode")
def decode():
    """Decode JWT/JWE tokens and display formatted information."""
    token = request.args.get('token')
    token_type = request.args.get('type', 'unknown')

    if not token:
        return render_template('decode_error.html',
                               error_title="❌ Missing Token",
                               error_message="No token provided for decoding.",
                               error_details="Please provide a token parameter.")

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
            if key in ['exp', 'nbf', 'iat'] and isinstance(value, (int, float)):
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

        return render_template('decode.html',
                               decoded_type=decoded_type,
                               token_type=token_type,
                               header=header,
                               formatted_payload=formatted_payload,
                               signature=signature,
                               validity_info=validity_info)

    except ValueError as e:
        logger.error(f"Token decoding error: {e}")
        return render_template('decode_error.html',
                               error_message=f"Unable to decode the provided token: {str(e)}",
                               error_details="The token may be malformed, encrypted with an unknown key, or not a valid JWT/JWE token.")


# MCP server run function is now imported from mcp_server.py


def run_flask_server(port: int = 8080, https: bool = False):
    """Run the Flask web server using Waitress for HTTP or Flask dev server for HTTPS."""
    if https:
        # Check for SSL certificates
        cert_file = os.path.join(os.path.dirname(__file__), 'tls_data', 'server.crt')
        key_file = os.path.join(os.path.dirname(__file__), 'tls_data', 'server.key')

        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            logger.error(f"SSL certificates not found: {cert_file}, {key_file}")
            raise FileNotFoundError("SSL certificates not found. Please ensure tls_data/server.crt and tls_data/server.key exist.")

        host = '127.0.0.1'  # Use localhost for HTTPS
        logger.info(f"Starting Flask development server (HTTPS) on {host}:{port}...")
        logger.info(f"Server will be available at https://{host}:{port}")

        # Use Flask's built-in development server with SSL context for HTTPS
        # This is suitable for development and testing
        app.run(
            host=host,
            port=port,
            ssl_context=(cert_file, key_file),
            debug=False,
            threaded=True
        )
    else:
        host = '0.0.0.0'  # Use all interfaces for HTTP
        logger.info(f"Starting Flask server with Waitress (HTTP) on {host}:{port}...")
        logger.info(f"Server will be available at http://{host}:{port}")

        # Use Waitress as the production WSGI server for HTTP
        # Waitress is thread-safe and works well in background threads
        serve(
            app,
            host=host,
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
    parser.add_argument(
        "--https",
        action='store_true',
        help="Enable HTTPS using certificates in tls_data/ directory")
    args = parser.parse_args()

    # Set the global port variable
    flask_port = args.port

    # Set the GitHub token in the MCP server
    set_github_token(config.github_token)

    # Run both Flask and MCP server together
    # MCP server runs in stdio mode, so Flask must run in a separate thread
    flask_thread = threading.Thread(
        target=run_flask_server, args=(
            args.port, args.https), daemon=True)
    flask_thread.start()

    protocol = "HTTPS" if args.https else "HTTP"
    host = "127.0.0.1" if args.https else "0.0.0.0"
    logger.info(f"Flask server starting on {protocol}://{host}:{args.port}")
    logger.info("MCP server starting on stdio...")
    logger.info("Use Ctrl+C to stop both servers")

    try:
        run_mcp_server()
    except KeyboardInterrupt:
        logger.info("\nShutting down servers...")

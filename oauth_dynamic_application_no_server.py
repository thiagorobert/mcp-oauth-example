import argparse
import asyncio
import logging
import secrets
import urllib.parse
import webbrowser
from typing import Dict, Optional
import requests


# Set up module-specific logger with DEBUG level
logger = logging.getLogger(__name__)


class OAuth2Client:
    """Simple OAuth2 client for Auth0 authentication."""

    def __init__(self, client_id: str, client_secret: str, auth0_domain: str, port: int = 8080):
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth0_domain = auth0_domain
        self.authorization_url = f"https://{auth0_domain}/authorize"
        self.token_url = f"https://{auth0_domain}/oauth/token"
        self.userinfo_url = f"https://{auth0_domain}/userinfo"
        self.redirect_uri = f"https://127.0.0.1:{port}/dynamic_application_callback"
        # self.redirect_uri = f"http://127.0.0.1:{port}/dynamic_application_callback"

    def generate_auth_url(self, state: str) -> str:
        """Generate the authorization URL for OAuth flow."""
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'openid profile email',
            'state': state,
            'audience': 'http://127.0.0.1:8080',
        }

        query_string = urllib.parse.urlencode(params)
        auth_url = f"{self.authorization_url}?{query_string}"

        logger.debug(f"Generated auth URL: {auth_url}")
        return auth_url

    def exchange_code_for_token(self, code: str) -> Optional[Dict]:
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
            response = requests.post(self.token_url, data=token_data, headers=headers)
            response.raise_for_status()

            token_response = response.json()
            logger.debug(f"Token response received: {list(token_response.keys())}")

            return token_response
        except requests.exceptions.RequestException as e:
            logger.error(f"Token exchange failed: {e}")
            return None

    def get_user_info(self, access_token: str) -> Optional[Dict]:
        """Get user information using access token."""
        headers = {
            'Authorization': f'Bearer {access_token}'
        }

        try:
            response = requests.get(self.userinfo_url, headers=headers)
            response.raise_for_status()

            user_info = response.json()
            logger.debug(f"User info received: {list(user_info.keys())}")

            return user_info
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get user info: {e}")
            return None


async def authenticate(client_id: str, client_secret: str, auth0_domain: str, port: int = 8080) -> Optional[Dict]:
    """Complete OAuth authentication flow."""

    # Create OAuth client
    oauth_client = OAuth2Client(client_id, client_secret, auth0_domain, port=port)

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)

    # Generate authorization URL
    auth_url = oauth_client.generate_auth_url(state)

    print("🔗 Opening browser for authentication...")
    print(f"If the browser doesn't open automatically, visit: {auth_url}")

    # Open browser
    webbrowser.open(auth_url)

    return None


def main():
    """Main function."""

    parser = argparse.ArgumentParser(description="Auth0 OAuth2 client example")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose logging to stdout")
    parser.add_argument("--client-id", required=True,
                        help="OAuth2 client ID")
    parser.add_argument("--client-secret", required=True,
                        help="OAuth2 client secret")
    parser.add_argument("--auth0-domain", required=True,
                        help="Auth0 domain (e.g., example.us.auth0.com)")
    parser.add_argument("--port", type=int, default=8080,
                        help="Local callback server port (default: 8080)")
    args = parser.parse_args()

    print("🚀 Starting Auth0 OAuth2 authentication...")
    print(f"📍 Auth0 Domain: {args.auth0_domain}")
    print(f"🆔 Client ID: {args.client_id}")
    print()

    # Run authentication
    logger.debug("Starting OAuth authentication process...")
    asyncio.run(authenticate(args.client_id, args.client_secret, args.auth0_domain))


if __name__ == "__main__":
    main()

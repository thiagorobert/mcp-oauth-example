import argparse
import asyncio
import dotenv
import httpx
import json
import logging
import os
import time
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

dotenv.load_dotenv()  # load environment variables from .env

# Constants
GITHUB_API_BASE = "https://api.github.com"
GITHUB_DEVICE_CODE_URL = "https://github.com/login/device/code"
GITHUB_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
TOKEN_FILE = "github_token.json"  # Token storage file

# OAuth configuration - set these as environment variables
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_PERSONAL_ACCESS_TOKEN = os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN")  # Personal Access Token for automated auth

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
        logger.debug(f"Token saved to {TOKEN_FILE}")
    except Exception as e:
        logger.debug(f"Failed to save token: {e}")

def load_token() -> str | None:
    """Load access token from file if it exists and is valid."""
    try:
        with open(TOKEN_FILE, 'r') as f:
            token_data = json.load(f)
        
        # Check if token exists
        if "access_token" not in token_data:
            return None
            
        # TODO: check if token is expired

        logger.debug(f"Token loaded from {TOKEN_FILE}")
        return token_data["access_token"]
        
    except FileNotFoundError:
        logger.debug(f"No token file found at {TOKEN_FILE}")
        return None
    except Exception as e:
        logger.debug(f"Failed to load token: {e}")
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
            logger.debug(f"Failed to get device code: {e}")
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
                    logger.debug("User denied access")
                    return None
                else:
                    logger.debug(f"Unknown error: {result}")
                    return None
                    
            except Exception as e:
                logger.debug(f"Error polling for token: {e}")
                await asyncio.sleep(interval)

async def authenticate() -> str | None:
    """Complete authentication using Personal Access Token or OAuth device flow."""
    global _access_token
    
    logger.debug("Starting authentication process...")
    
    # Check if we already have a token in memory
    if _access_token:
        logger.debug(" Using existing access token")
        return _access_token
    
    # Check for Personal Access Token from environment variable (automated auth)
    if GITHUB_PERSONAL_ACCESS_TOKEN:
        logger.debug("Using Personal Access Token from environment: %s", GITHUB_PERSONAL_ACCESS_TOKEN)
        _access_token = GITHUB_PERSONAL_ACCESS_TOKEN
        return _access_token
    
    # Try to load token from file
    _access_token = load_token()
    if _access_token:
        logger.debug(" Using existing access token read from file")
        return _access_token
    
    logger.debug("No existing token found, starting OAuth device flow...")
    
    # Start device flow
    device_info = await get_device_code()
    if not device_info:
        logger.debug(" Failed to get device code")
        return None
    
    print(f"\nGitHub OAuth Authentication Required:")
    print(f" 1. Go to: {device_info['verification_uri']}")
    print(f" 2. Enter code: {device_info['user_code']}")
    print(f" 3. Waiting for authentication...")
    print(f" (Code expires in {device_info.get('expires_in', 900)} seconds)")
    print(f"\nAlternatively, set GITHUB_PERSONAL_ACCESS_TOKEN environment variable with a Personal Access Token for automated authentication.")
    
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



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GitHub OAuth client example")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Enable verbose logging to stdout")
    args = parser.parse_args()
    
    # Configure logging based on verbose flag
    setup_logging(args.verbose)
    
    # These are required for OAuth2
    assert GITHUB_CLIENT_ID, "required GITHUB_CLIENT_ID not available"
    assert GITHUB_CLIENT_SECRET, "required GITHUB_CLIENT_SECRET not available"

    async def main():
        token = await authenticate()
        if token:
            print(f"Authentication successful! Token saved to {TOKEN_FILE}")
        else:
            print("Authentication failed")
            
    asyncio.run(main())

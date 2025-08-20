"""Configuration management for Flask MCP server application.

This module handles environment variable loading and validation using a dataclass structure.
All required environment variables are validated on initialization with assertions.
"""

import os
from dataclasses import dataclass
import logging
from typing import Optional

from dotenv import find_dotenv, load_dotenv

import logging_config

logger = logging_config.configure_logger(__name__)


@dataclass
class AppConfig:
    """Configuration dataclass for Flask MCP server application.

    This dataclass centralizes all environment variable handling and provides
    validation through assertions to ensure required values are present.
    """

    # Flask web server configuration
    app_secret_key: str
    auth0_client_id: str
    auth0_client_secret: str
    auth0_domain: str

    # GitHub OAuth and MCP configuration
    github_token: str

    # Dynamic OAuth callback configuration (optional)
    dynamic_client_id: Optional[str] = None
    dynamic_client_secret: Optional[str] = None

    def __post_init__(self):
        """Validate required environment variables after initialization."""
        # Skip validation if we're in a test environment
        if os.environ.get('PYTEST_CURRENT_TEST') or os.environ.get('TESTING'):
            return

        # Assert all required Flask variables are set
        assert self.app_secret_key, "APP_SECRET_KEY environment variable is required"
        assert self.auth0_client_id, "AUTH0_CLIENT_ID environment variable is required"
        assert self.auth0_client_secret, "AUTH0_CLIENT_SECRET environment variable is required"
        assert self.auth0_domain, "AUTH0_DOMAIN environment variable is required"

        # Assert GitHub token is set
        assert self.github_token, "GITHUB_TOKEN environment variable is required"


def load_config() -> AppConfig:
    """Load configuration from environment variables.

    Returns:
        AppConfig: Validated configuration object

    Raises:
        AssertionError: If required environment variables are missing
    """
        
    # Load environment variables from .env file if it exists
    env_file = find_dotenv()
    if env_file:
        logger.debug(f"Using .env file {env_file}")
        load_dotenv(env_file)
    else:
        logger.warning(".env file not found")

    # Create configuration from environment variables
    config = AppConfig(
        # Flask web server configuration
        app_secret_key=os.environ.get("APP_SECRET_KEY", ""),
        auth0_client_id=os.environ.get("AUTH0_CLIENT_ID", ""),
        auth0_client_secret=os.environ.get("AUTH0_CLIENT_SECRET", ""),
        auth0_domain=os.environ.get("AUTH0_DOMAIN", ""),

        # GitHub OAuth and MCP configuration
        github_token=os.environ.get("GITHUB_TOKEN", ""),

        # Dynamic OAuth callback configuration (optional)
        dynamic_client_id=os.environ.get("DYNAMIC_CLIENT_ID", ""),
        dynamic_client_secret=os.environ.get("DYNAMIC_CLIENT_SECRET", ""),
    )

    return config


# Global configuration instance
_config: Optional[AppConfig] = None


def create_test_config() -> AppConfig:
    """Create a configuration instance suitable for testing.

    Returns:
        AppConfig: Configuration with test values
    """
    return AppConfig(
        app_secret_key="test_secret_key",
        auth0_client_id="test_auth0_client_id",
        auth0_client_secret="test_auth0_client_secret",
        auth0_domain="test.auth0.com",
        github_token="test_github_token",
        dynamic_client_id="test_dynamic_client_id",
        dynamic_client_secret="test_dynamic_client_secret"
    )


def reset_config() -> None:
    """Reset the global configuration instance. Useful for testing."""
    global _config
    _config = None


def get_config() -> AppConfig:
    """Get the global configuration instance.

    Lazy loads the configuration on first access.

    Returns:
        AppConfig: The global configuration instance
    """
    global _config
    if _config is None:
        # Use test config if in test environment
        if (os.environ.get('PYTEST_CURRENT_TEST') or
                os.environ.get('TESTING')):
            _config = create_test_config()
        else:
            _config = load_config()
    return _config

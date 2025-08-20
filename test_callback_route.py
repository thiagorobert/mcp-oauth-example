"""
Unit tests for the /dynamic_application_callback route in flask_mcp_server.py

This module tests the OAuth callback functionality that was integrated from oauth_dynamic_application.py
"""

from datetime import datetime
from unittest.mock import MagicMock, Mock, patch

import pytest

from flask_mcp_server import OAuth2Client, app


class TestDynamicApplicationCallback:
    """Test cases for the /dynamic_application_callback route."""

    @pytest.fixture
    def client(self):
        """Create a test client for the Flask app."""
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    @pytest.fixture(autouse=True)
    def mock_auth0_env(self):
        """Mock Auth0 environment variables to prevent real API calls."""
        with patch('flask_mcp_server.env') as mock_env:
            # Return None for Dynamic OAuth credentials to prevent real token exchange
            mock_env.get.return_value = None
            yield mock_env

    def test_callback_success_with_code(self, client):
        """Test successful OAuth callback with authorization code."""
        response = client.get(
            '/dynamic_application_callback?code=auth123&state=state456&scope=openid%20profile%20email')

        assert response.status_code == 200
        content = response.data.decode()

        # Check for success indicators
        assert '✅ Authentication Successful!' in content
        assert 'Authorization Code:' in content
        assert 'auth123' in content
        assert 'State:' in content
        assert 'state456' in content
        assert 'Scope:' in content
        assert 'openid profile email' in content
        assert 'Timestamp:' in content

        # Check that error content is not present
        assert '❌ Authentication Failed' not in content
        assert 'Error:' not in content

    def test_callback_success_minimal_params(self, client):
        """Test successful callback with minimal required parameters."""
        response = client.get('/dynamic_application_callback?code=minimal123')

        assert response.status_code == 200
        content = response.data.decode()

        assert '✅ Authentication Successful!' in content
        assert 'minimal123' in content
        assert 'Authorization Code:' in content

    def test_callback_error_scenario(self, client):
        """Test OAuth callback with error parameters."""
        response = client.get(
            '/dynamic_application_callback?error=access_denied&error_description=User%20denied%20access&state=state789')

        assert response.status_code == 200
        content = response.data.decode()

        # Check for error indicators
        assert '❌ Authentication Failed' in content
        assert 'Error:' in content
        assert 'access_denied' in content
        assert 'Description:' in content
        assert 'User denied access' in content
        assert 'state789' in content

        # Check that success content is not present
        assert '✅ Authentication Successful!' not in content
        assert 'Authorization Code:' not in content

    def test_callback_no_parameters(self, client):
        """Test callback with no parameters (should be treated as error)."""
        response = client.get('/dynamic_application_callback')

        assert response.status_code == 200
        content = response.data.decode()

        # Should be treated as failed authentication
        assert '❌ Authentication Failed' in content
        assert 'An unknown error occurred during authentication' in content

    def test_callback_mixed_parameters(self, client):
        """Test callback with both code and error (error should take precedence)."""
        response = client.get(
            '/dynamic_application_callback?code=test123&error=invalid_request&error_description=Invalid%20request')

        assert response.status_code == 200
        content = response.data.decode()

        # Error should take precedence over code - logic is `success = bool(code and not error)`
        assert '❌ Authentication Failed' in content  # Error takes precedence
        assert '✅ Authentication Successful!' not in content
        assert 'invalid_request' in content
        assert 'Invalid request' in content

    def test_callback_only_error_no_description(self, client):
        """Test callback with error but no description."""
        response = client.get('/dynamic_application_callback?error=server_error')

        assert response.status_code == 200
        content = response.data.decode()

        assert '❌ Authentication Failed' in content
        assert 'server_error' in content

    @patch('flask_mcp_server.datetime')
    def test_callback_timestamp_format(self, mock_datetime, client):
        """Test that timestamp is properly formatted."""
        # Mock datetime to return a specific time
        mock_now = MagicMock()
        mock_now.strftime.return_value = '2023-12-25 10:30:45 UTC'
        mock_datetime.now.return_value = mock_now

        response = client.get('/dynamic_application_callback?code=test123')

        assert response.status_code == 200
        content = response.data.decode()

        assert '2023-12-25 10:30:45 UTC' in content
        mock_datetime.now.assert_called_once()
        mock_now.strftime.assert_called_once_with('%Y-%m-%d %H:%M:%S UTC')

    def test_callback_url_encoding(self, client):
        """Test callback with URL-encoded parameters."""
        response = client.get(
            '/dynamic_application_callback?code=test%20code&state=test%20state&scope=openid%20profile%20email&error_description=Test%20error%20message')

        assert response.status_code == 200
        content = response.data.decode()

        # Flask automatically decodes URL-encoded parameters
        assert 'test code' in content
        assert 'test state' in content
        assert 'openid profile email' in content

    def test_callback_special_characters(self, client):
        """Test callback with special characters in parameters."""
        response = client.get(
            '/dynamic_application_callback?code=abc-123_XYZ&state=def+456&scope=openid,profile,email')

        assert response.status_code == 200
        content = response.data.decode()

        assert 'abc-123_XYZ' in content
        assert 'def 456' in content  # + becomes space in URL decoding
        assert 'openid,profile,email' in content

    def test_callback_long_parameters(self, client):
        """Test callback with very long parameters."""
        long_code = 'a' * 100
        long_state = 'b' * 80

        response = client.get(f'/dynamic_application_callback?code={long_code}&state={long_state}')

        assert response.status_code == 200
        content = response.data.decode()

        # Long values should be truncated in display (first 20 + ... + last 10)
        assert long_code[:20] in content
        assert long_code[-10:] in content
        assert long_state[:20] in content
        assert long_state[-10:] in content

    def test_callback_template_structure(self, client):
        """Test that the callback template has the expected structure."""
        response = client.get('/dynamic_application_callback?code=test123&state=abc456')

        assert response.status_code == 200
        content = response.data.decode()

        # Check for HTML structure elements
        assert '<!DOCTYPE html>' in content
        assert '<title>OAuth Callback - Flask + MCP Server</title>' in content
        assert 'class="container"' in content
        assert 'class="success"' in content
        assert 'class="info-section"' in content
        assert 'class="info-grid"' in content
        # Note: auto_close is False by default, so these links don't appear
        assert 'class="close-notice"' in content

    def test_callback_token_info_structure(self, client):
        """Test that token info is properly structured when code is present."""
        response = client.get('/dynamic_application_callback?code=test123')

        assert response.status_code == 200
        content = response.data.decode()

        # Check for token information section
        assert '🔑 Token Information' in content
        assert 'Access Token:' in content
        assert 'Token Type:' in content
        assert 'Expires In:' in content
        assert 'Auth0 credentials required for' in content  # Updated placeholder text
        assert 'bearer' in content
        assert '3600 seconds' in content

    def test_callback_user_info_structure(self, client):
        """Test that user info is properly structured when code is present."""
        response = client.get('/dynamic_application_callback?code=test123')

        assert response.status_code == 200
        content = response.data.decode()

        # Check for user information section
        assert '👤 User Information' in content
        assert 'Name:' in content
        assert 'Email:' in content
        assert 'Subject ID:' in content
        assert 'Auth0 credentials required for user info' in content  # Updated placeholder text

    def test_callback_auto_close_disabled(self, client):
        """Test that auto-close is disabled in the template."""
        response = client.get('/dynamic_application_callback?code=test123')

        assert response.status_code == 200
        content = response.data.decode()

        # Auto-close should be disabled based on the template context
        # The JavaScript auto-close should not execute since auto_close=False
        # Check that the auto-close script section is empty (no setTimeout call)
        assert 'setTimeout' not in content  # No auto-close timer should be present

    def test_callback_csrf_state_handling(self, client):
        """Test that state parameter is properly handled for CSRF protection."""
        state_values = [
            'simple_state',
            'state-with-dashes',
            'state_with_underscores',
            'state.with.dots',
            'state123456789',
            ''  # Empty state
        ]

        for state in state_values:
            if state:
                response = client.get(f'/dynamic_application_callback?code=test&state={state}')
            else:
                response = client.get('/dynamic_application_callback?code=test&state=')

            assert response.status_code == 200
            content = response.data.decode()

            if state:
                # State values longer than 20 chars get truncated in template: first20...last10
                if len(state) > 20:
                    assert state[:20] in content  # First 20 chars
                    assert state[-10:] in content  # Last 10 chars
                else:
                    assert state in content
                assert 'State:' in content  # Label present when state has value
            else:
                # Empty state doesn't show the State label in template
                assert 'State:' not in content

    def test_callback_scope_parsing(self, client):
        """Test different scope formats and values."""
        scope_tests = [
            ('openid', 'openid'),
            ('openid%20profile', 'openid profile'),
            ('openid%20profile%20email', 'openid profile email'),
            ('read:user%20repo', 'read:user repo'),
            ('', ''),  # Empty scope
        ]

        for url_scope, expected_scope in scope_tests:
            if url_scope:
                response = client.get(f'/dynamic_application_callback?code=test&scope={url_scope}')
            else:
                response = client.get('/dynamic_application_callback?code=test&scope=')

            assert response.status_code == 200
            content = response.data.decode()

            if expected_scope:
                assert expected_scope in content

    def test_callback_error_types(self, client):
        """Test different OAuth error types."""
        error_tests = [
            ('access_denied', 'User denied access'),
            ('invalid_request', 'Invalid request parameters'),
            ('invalid_client', 'Invalid client credentials'),
            ('invalid_grant', 'Invalid authorization grant'),
            ('unsupported_response_type', 'Unsupported response type'),
            ('invalid_scope', 'Invalid scope requested'),
            ('server_error', 'Server error occurred'),
            ('temporarily_unavailable', 'Service temporarily unavailable'),
        ]

        for error_code, error_desc in error_tests:
            response = client.get(
                f'/dynamic_application_callback?error={error_code}&error_description={error_desc.replace(" ", "%20")}')

            assert response.status_code == 200
            content = response.data.decode()

            assert '❌ Authentication Failed' in content
            assert error_code in content
            assert error_desc in content

    def test_callback_return_links(self, client):
        """Test that callback page has proper close notice when auto_close is False."""
        response = client.get('/dynamic_application_callback?code=test123')

        assert response.status_code == 200
        content = response.data.decode()

        # With auto_close=False, navigation links don't appear but close notice does
        assert 'class="close-notice"' in content
        assert 'This window should close automatically' in content
        # The actual navigation links only appear when auto_close=True


class TestCallbackRouteIntegration:
    """Integration tests for the callback route with other app components."""

    @pytest.fixture
    def client(self):
        """Create a test client for the Flask app."""
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_callback_route_exists(self, client):
        """Test that the callback route is properly registered."""
        # Test that the route exists and responds
        response = client.get('/dynamic_application_callback')
        assert response.status_code == 200

        # Test that it's different from 404
        response_404 = client.get('/nonexistent_route')
        assert response_404.status_code == 404

    def test_callback_with_home_navigation(self, client):
        """Test navigation from callback back to home."""
        # First test the callback
        callback_response = client.get('/dynamic_application_callback?code=test123')
        assert callback_response.status_code == 200

        # Test that home route exists and is accessible
        home_response = client.get('/')
        assert home_response.status_code == 200

    def test_callback_template_inheritance(self, client):
        """Test that the callback template works with Flask's template system."""
        response = client.get('/dynamic_application_callback?code=test123')

        assert response.status_code == 200
        content = response.data.decode()

        # Check that Jinja2 templating worked correctly
        assert '{{' not in content  # No unrendered template variables
        assert '}}' not in content  # No unrendered template variables
        assert '{%' not in content  # No unrendered template blocks
        assert '%}' not in content  # No unrendered template blocks


class TestOAuth2ClientIntegration:
    """Test cases for OAuth2Client integration in the callback route."""

    @pytest.fixture
    def client(self):
        """Create a test client for the Flask app."""
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    @patch('flask_mcp_server.OAuth2Client')
    @patch('flask_mcp_server.env')
    def test_callback_with_real_token_exchange_success(self, mock_env, mock_oauth_client_class, client):
        """Test callback with successful token exchange and user info retrieval."""
        # Setup environment variables for dynamic OAuth (callback route uses DYNAMIC_* vars)
        mock_env.get.side_effect = lambda key: {
            'DYNAMIC_CLIENT_ID': 'test_client_id',
            'DYNAMIC_CLIENT_SECRET': 'test_client_secret',
            'AUTH0_DOMAIN': 'test.auth0.com'
        }.get(key)

        # Mock OAuth client instance
        mock_oauth_client = Mock()
        mock_oauth_client_class.return_value = mock_oauth_client

        # Mock successful token exchange
        mock_token_response = {
            'access_token': 'test_access_token',
            'token_type': 'Bearer',
            'expires_in': 3600,
            'id_token': 'test_id_token',
            'refresh_token': 'test_refresh_token',
            'scope': 'openid profile email'
        }
        mock_oauth_client.exchange_code_for_token.return_value = mock_token_response

        # Mock user info response
        mock_user_response = {
            'name': 'John Doe',
            'email': 'john@example.com',
            'sub': 'auth0|123456',
            'picture': 'https://example.com/avatar.jpg',
            'nickname': 'johndoe',
            'email_verified': True,
            'updated_at': '2023-12-01T10:00:00.000Z'
        }
        mock_oauth_client.get_user_info.return_value = mock_user_response

        # Make request
        response = client.get('/dynamic_application_callback?code=test_auth_code&state=test_state')

        assert response.status_code == 200
        content = response.data.decode()

        # Check success indicators
        assert '✅ Authentication Successful!' in content
        assert 'John Doe' in content
        assert 'john@example.com' in content
        assert 'test_access_token' in content
        assert 'Bearer' in content

        # Verify OAuth client was called correctly
        mock_oauth_client.exchange_code_for_token.assert_called_once_with('test_auth_code')
        mock_oauth_client.get_user_info.assert_called_once_with('test_access_token')

    @patch('flask_mcp_server.OAuth2Client')
    @patch('flask_mcp_server.env')
    def test_callback_with_token_exchange_failure(self, mock_env, mock_oauth_client_class, client):
        """Test callback when token exchange fails."""
        # Setup environment variables for dynamic OAuth (callback route uses DYNAMIC_* vars)
        mock_env.get.side_effect = lambda key: {
            'DYNAMIC_CLIENT_ID': 'test_client_id',
            'DYNAMIC_CLIENT_SECRET': 'test_client_secret',
            'AUTH0_DOMAIN': 'test.auth0.com'
        }.get(key)

        # Mock OAuth client instance
        mock_oauth_client = Mock()
        mock_oauth_client_class.return_value = mock_oauth_client

        # Mock failed token exchange
        mock_oauth_client.exchange_code_for_token.return_value = None

        # Make request
        response = client.get('/dynamic_application_callback?code=test_auth_code&state=test_state')

        assert response.status_code == 200
        content = response.data.decode()

        # Check error indicators
        assert '❌ Authentication Failed' in content
        assert 'Failed to exchange authorization code for token' in content

        # Verify OAuth client was called
        mock_oauth_client.exchange_code_for_token.assert_called_once_with('test_auth_code')
        mock_oauth_client.get_user_info.assert_not_called()

    @patch('flask_mcp_server.OAuth2Client')
    @patch('flask_mcp_server.env')
    def test_callback_with_user_info_failure(self, mock_env, mock_oauth_client_class, client):
        """Test callback when user info retrieval fails."""
        # Setup environment variables for dynamic OAuth (callback route uses DYNAMIC_* vars)
        mock_env.get.side_effect = lambda key: {
            'DYNAMIC_CLIENT_ID': 'test_client_id',
            'DYNAMIC_CLIENT_SECRET': 'test_client_secret',
            'AUTH0_DOMAIN': 'test.auth0.com'
        }.get(key)

        # Mock OAuth client instance
        mock_oauth_client = Mock()
        mock_oauth_client_class.return_value = mock_oauth_client

        # Mock successful token exchange
        mock_token_response = {
            'access_token': 'test_access_token',
            'token_type': 'Bearer',
            'expires_in': 3600
        }
        mock_oauth_client.exchange_code_for_token.return_value = mock_token_response

        # Mock failed user info retrieval
        mock_oauth_client.get_user_info.return_value = None

        # Make request
        response = client.get('/dynamic_application_callback?code=test_auth_code&state=test_state')

        assert response.status_code == 200
        content = response.data.decode()

        # Should still show success for token exchange, but no user info
        assert '✅ Authentication Successful!' in content
        assert 'test_access_token' in content

        # Verify both methods were called
        mock_oauth_client.exchange_code_for_token.assert_called_once_with('test_auth_code')
        mock_oauth_client.get_user_info.assert_called_once_with('test_access_token')

    @patch('flask_mcp_server.env')
    def test_callback_without_auth0_credentials(self, mock_env, client):
        """Test callback when Auth0 credentials are not configured."""
        # Mock missing Auth0 credentials
        mock_env.get.return_value = None

        # Make request
        response = client.get('/dynamic_application_callback?code=test_auth_code&state=test_state')

        assert response.status_code == 200
        content = response.data.decode()

        # Should show success but with placeholder info
        assert '✅ Authentication Successful!' in content
        assert 'Auth0 credentials required for' in content  # Truncated in template
        assert 'Configure AUTH0_* environment variables' in content

    @patch('flask_mcp_server.OAuth2Client')
    @patch('flask_mcp_server.env')
    def test_callback_with_oauth_client_exception(self, mock_env, mock_oauth_client_class, client):
        """Test callback when OAuth client raises an exception."""
        # Setup environment variables for dynamic OAuth (callback route uses DYNAMIC_* vars)
        mock_env.get.side_effect = lambda key: {
            'DYNAMIC_CLIENT_ID': 'test_client_id',
            'DYNAMIC_CLIENT_SECRET': 'test_client_secret',
            'AUTH0_DOMAIN': 'test.auth0.com'
        }.get(key)

        # Mock OAuth client to raise exception
        mock_oauth_client_class.side_effect = Exception("OAuth client initialization failed")

        # Make request
        response = client.get('/dynamic_application_callback?code=test_auth_code&state=test_state')

        assert response.status_code == 200
        content = response.data.decode()

        # Should show error
        assert '❌ Authentication Failed' in content
        assert 'Token exchange error: OAuth client initialization failed' in content

    @patch('flask_mcp_server.OAuth2Client')
    @patch('flask_mcp_server.env')
    def test_callback_token_exchange_timeout(self, mock_env, mock_oauth_client_class, client):
        """Test callback when token exchange times out."""
        # Setup environment variables for dynamic OAuth (callback route uses DYNAMIC_* vars)
        mock_env.get.side_effect = lambda key: {
            'DYNAMIC_CLIENT_ID': 'test_client_id',
            'DYNAMIC_CLIENT_SECRET': 'test_client_secret',
            'AUTH0_DOMAIN': 'test.auth0.com'
        }.get(key)

        # Mock OAuth client instance
        mock_oauth_client = Mock()
        mock_oauth_client_class.return_value = mock_oauth_client

        # Mock timeout during token exchange
        import requests
        mock_oauth_client.exchange_code_for_token.side_effect = requests.exceptions.Timeout(
            "Request timed out")

        # Make request
        response = client.get('/dynamic_application_callback?code=test_auth_code&state=test_state')

        assert response.status_code == 200
        content = response.data.decode()

        # Should show error
        assert '❌ Authentication Failed' in content
        assert 'Token exchange error: Request timed out' in content


class TestOAuth2Client:
    """Test cases for the OAuth2Client class directly."""

    def test_oauth2_client_initialization(self):
        """Test OAuth2Client initialization."""
        client = OAuth2Client(
            client_id='test_id',
            client_secret='test_secret',
            auth0_domain='test.auth0.com',
            redirect_uri='http://localhost:8080/callback'
        )

        assert client.client_id == 'test_id'
        assert client.client_secret == 'test_secret'
        assert client.auth0_domain == 'test.auth0.com'
        assert client.redirect_uri == 'http://localhost:8080/callback'
        assert client.authorization_url == 'https://test.auth0.com/authorize'
        assert client.token_url == 'https://test.auth0.com/oauth/token'
        assert client.userinfo_url == 'https://test.auth0.com/userinfo'

    @patch('flask_mcp_server.requests.post')
    def test_exchange_code_for_token_success(self, mock_post):
        """Test successful token exchange."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'access_token': 'test_token',
            'token_type': 'Bearer',
            'expires_in': 3600
        }
        mock_post.return_value = mock_response

        client = OAuth2Client(
            client_id='test_id',
            client_secret='test_secret',
            auth0_domain='test.auth0.com',
            redirect_uri='http://localhost:8080/callback'
        )

        result = client.exchange_code_for_token('test_code')

        assert result is not None
        assert result['access_token'] == 'test_token'
        assert result['token_type'] == 'Bearer'
        assert result['expires_in'] == 3600

        # Verify the request was made correctly
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == 'https://test.auth0.com/oauth/token'
        data = call_args[1]['data']
        assert data['grant_type'] == 'authorization_code'
        assert data['code'] == 'test_code'
        assert data['client_id'] == 'test_id'

    @patch('flask_mcp_server.requests.post')
    def test_exchange_code_for_token_failure(self, mock_post):
        """Test token exchange failure."""
        # Mock failed response
        import requests
        mock_post.side_effect = requests.exceptions.RequestException("HTTP 400 Error")

        client = OAuth2Client(
            client_id='test_id',
            client_secret='test_secret',
            auth0_domain='test.auth0.com',
            redirect_uri='http://localhost:8080/callback'
        )

        result = client.exchange_code_for_token('invalid_code')

        assert result is None
        mock_post.assert_called_once()

    @patch('flask_mcp_server.requests.get')
    def test_get_user_info_success(self, mock_get):
        """Test successful user info retrieval."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'name': 'John Doe',
            'email': 'john@example.com',
            'sub': 'auth0|123456'
        }
        mock_get.return_value = mock_response

        client = OAuth2Client(
            client_id='test_id',
            client_secret='test_secret',
            auth0_domain='test.auth0.com',
            redirect_uri='http://localhost:8080/callback'
        )

        result = client.get_user_info('test_access_token')

        assert result is not None
        assert result['name'] == 'John Doe'
        assert result['email'] == 'john@example.com'
        assert result['sub'] == 'auth0|123456'

        # Verify the request was made correctly
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert call_args[0][0] == 'https://test.auth0.com/userinfo'
        assert call_args[1]['headers']['Authorization'] == 'Bearer test_access_token'

    @patch('flask_mcp_server.requests.get')
    def test_get_user_info_failure(self, mock_get):
        """Test user info retrieval failure."""
        # Mock failed response
        import requests
        mock_get.side_effect = requests.exceptions.RequestException("HTTP 401 Error")

        client = OAuth2Client(
            client_id='test_id',
            client_secret='test_secret',
            auth0_domain='test.auth0.com',
            redirect_uri='http://localhost:8080/callback'
        )

        result = client.get_user_info('invalid_token')

        assert result is None
        mock_get.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

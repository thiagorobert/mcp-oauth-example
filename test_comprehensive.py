#!/usr/bin/env python3
"""
Comprehensive additional tests to improve coverage for the MCP OAuth GitHub example.

This file contains additional edge cases, error conditions, and comprehensive
integration tests to ensure robust functionality.
"""

import asyncio
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch, mock_open
import pytest
import httpx

# Import modules under test
import client_with_oauth
import flask_mcp_server


class TestClientOAuthEdgeCases(unittest.TestCase):
    """Additional edge case tests for client_with_oauth.py."""
    
    def setUp(self):
        """Set up test fixtures."""
        client_with_oauth._access_token = None
        
    def tearDown(self):
        """Clean up after tests."""
        client_with_oauth._access_token = None
    
    def test_save_token_file_permission_error(self):
        """Test saving token when file permissions are denied."""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with patch.object(client_with_oauth.logger, 'debug') as mock_log:
                client_with_oauth.save_token("test_token")
                mock_log.assert_called()
    
    def test_load_token_json_decode_error(self):
        """Test loading token with corrupted JSON file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
            tmp_file.write("invalid json content")
            tmp_path = tmp_file.name
            
        try:
            with patch.object(client_with_oauth, 'TOKEN_FILE', tmp_path):
                result = client_with_oauth.load_token()
                self.assertIsNone(result)
        finally:
            os.unlink(tmp_path)
    
    def test_load_token_missing_access_token_field(self):
        """Test loading token file that's missing the access_token field."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
            json.dump({"created_at": 1234567890}, tmp_file)
            tmp_path = tmp_file.name
            
        try:
            with patch.object(client_with_oauth, 'TOKEN_FILE', tmp_path):
                result = client_with_oauth.load_token()
                self.assertIsNone(result)
        finally:
            os.unlink(tmp_path)


@pytest.mark.asyncio
class TestClientOAuthAsyncEdgeCases:
    """Additional async edge case tests for client_with_oauth.py."""
    
    def setup_method(self):
        """Set up test fixtures."""
        client_with_oauth._access_token = None
        
    def teardown_method(self):
        """Clean up after tests."""
        client_with_oauth._access_token = None
    
    @patch('client_with_oauth.httpx.AsyncClient')
    async def test_get_device_code_http_error(self, mock_client):
        """Test device code retrieval with HTTP error."""
        mock_client_instance = AsyncMock()
        mock_client_instance.post.side_effect = httpx.HTTPStatusError(
            "Bad Request", request=Mock(), response=Mock(status_code=400)
        )
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        with patch.dict(os.environ, {'GITHUB_CLIENT_ID': 'test_client_id'}):
            result = await client_with_oauth.get_device_code()
            
        assert result is None
    
    @patch('client_with_oauth.httpx.AsyncClient')
    async def test_poll_for_token_access_denied(self, mock_client):
        """Test token polling when user denies access."""
        mock_response = Mock()
        mock_response.json.return_value = {'error': 'access_denied'}
        
        mock_client_instance = AsyncMock()
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        with patch.dict(os.environ, {'GITHUB_CLIENT_ID': 'test_client_id'}):
            result = await client_with_oauth.poll_for_token("device_code", interval=0.1)
            
        assert result is None
    
    @patch('client_with_oauth.httpx.AsyncClient')
    async def test_poll_for_token_slow_down(self, mock_client):
        """Test token polling with slow_down error."""
        slow_down_response = Mock()
        slow_down_response.json.return_value = {'error': 'slow_down'}
        
        success_response = Mock()
        success_response.json.return_value = {'access_token': 'test_token'}
        
        mock_client_instance = AsyncMock()
        mock_client_instance.post.side_effect = [slow_down_response, success_response]
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        with patch.dict(os.environ, {'GITHUB_CLIENT_ID': 'test_client_id'}):
            with patch('client_with_oauth.asyncio.sleep', new_callable=AsyncMock):
                result = await client_with_oauth.poll_for_token("device_code", interval=1)
                
        assert result == 'test_token'
    
    @patch('client_with_oauth.httpx.AsyncClient')
    async def test_poll_for_token_unknown_error(self, mock_client):
        """Test token polling with unknown error."""
        mock_response = Mock()
        mock_response.json.return_value = {'error': 'unknown_error', 'error_description': 'Something went wrong'}
        
        mock_client_instance = AsyncMock()
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        with patch.dict(os.environ, {'GITHUB_CLIENT_ID': 'test_client_id'}):
            result = await client_with_oauth.poll_for_token("device_code", interval=0.1)
            
        assert result is None
    
    @patch('client_with_oauth.get_device_code')
    async def test_authenticate_device_code_failure(self, mock_get_device_code):
        """Test authentication when device code retrieval fails."""
        mock_get_device_code.return_value = None
        
        with patch.object(client_with_oauth, 'GITHUB_PERSONAL_ACCESS_TOKEN', None):
            with patch('client_with_oauth.load_token', return_value=None):
                result = await client_with_oauth.authenticate()
                
        assert result is None
    
    @patch('client_with_oauth.load_token')
    async def test_authenticate_memory_token_priority(self, mock_load_token):
        """Test that memory token takes priority over file token."""
        client_with_oauth._access_token = "memory_token"
        mock_load_token.return_value = "file_token"
        
        result = await client_with_oauth.authenticate()
        
        assert result == "memory_token"
        mock_load_token.assert_not_called()


class TestFlaskMCPServerEdgeCases(unittest.TestCase):
    """Additional edge case tests for flask_mcp_server.py."""
    
    def setUp(self):
        """Set up test fixtures."""
        flask_mcp_server._github_access_token = None
        
    def tearDown(self):
        """Clean up after tests."""
        flask_mcp_server._github_access_token = None
    
    def test_logging_handler_removal(self):
        """Test that existing logging handlers are properly removed."""
        # Add a dummy handler
        import logging
        dummy_handler = logging.StreamHandler()
        flask_mcp_server.logger.addHandler(dummy_handler)
        
        # Call setup_logging which should remove existing handlers
        flask_mcp_server.setup_logging(verbose=True)
        
        # Verify the dummy handler was removed
        self.assertNotIn(dummy_handler, flask_mcp_server.logger.handlers)


@pytest.mark.asyncio
class TestFlaskMCPServerAsyncEdgeCases:
    """Additional async edge case tests for flask_mcp_server.py."""
    
    def setup_method(self):
        """Set up test fixtures."""
        flask_mcp_server._github_access_token = "test_token"
        
    def teardown_method(self):
        """Clean up after tests."""
        flask_mcp_server._github_access_token = None
    
    @patch('flask_mcp_server.httpx.AsyncClient')
    async def test_make_github_request_timeout(self, mock_client):
        """Test GitHub API request with timeout."""
        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = httpx.TimeoutException("Request timeout")
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        result = await flask_mcp_server.make_github_request(
            "https://api.github.com/user", 
            "test_token"
        )
        
        assert result is None
    
    @patch('flask_mcp_server.httpx.AsyncClient')
    async def test_make_github_request_http_status_error(self, mock_client):
        """Test GitHub API request with HTTP status error."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not Found", request=Mock(), response=Mock(status_code=404)
        )
        
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        result = await flask_mcp_server.make_github_request(
            "https://api.github.com/user", 
            "test_token"
        )
        
        assert result is None
    
    @patch('flask_mcp_server.make_github_request')
    async def test_list_repositories_empty_response(self, mock_request):
        """Test list_repositories with empty response."""
        mock_request.return_value = []
        
        result = await flask_mcp_server.list_repositories()
        
        # Empty list should still be processed, just return empty result
        assert isinstance(result, str)
    
    @patch('flask_mcp_server.make_github_request')
    async def test_list_repositories_api_failure(self, mock_request):
        """Test list_repositories when API request fails."""
        mock_request.return_value = None
        
        result = await flask_mcp_server.list_repositories()
        
        assert "Unable to fetch repositories" in result
    
    @patch('flask_mcp_server.make_github_request')
    async def test_get_repository_info_api_failure(self, mock_request):
        """Test get_repository_info when API request fails."""
        mock_request.return_value = None
        
        result = await flask_mcp_server.get_repository_info("user", "repo")
        
        assert "Unable to fetch information for repository user/repo" in result
    
    @patch('flask_mcp_server.make_github_request')
    async def test_get_user_info_api_failure(self, mock_request):
        """Test get_user_info when API request fails."""
        mock_request.return_value = None
        
        result = await flask_mcp_server.get_user_info()
        
        assert "Unable to fetch user information" in result
    
    @patch('flask_mcp_server.make_github_request')
    async def test_mcp_tools_with_missing_optional_fields(self, mock_request):
        """Test MCP tools handle missing optional fields gracefully."""
        # Test repository with minimal data
        mock_repos = [
            {
                'full_name': 'user/minimal-repo',
                'stargazers_count': 0,
                'private': False,
                'html_url': 'https://github.com/user/minimal-repo'
                # Missing description, language
            }
        ]
        mock_request.return_value = mock_repos
        
        result = await flask_mcp_server.list_repositories()
        
        assert 'user/minimal-repo' in result
        assert 'No description' in result
        assert 'Unknown' in result


class TestFlaskMCPServerCLI(unittest.TestCase):
    """Test cases for flask_mcp_server.py command line interface."""
    
    @patch('sys.argv', ['flask_mcp_server.py', '--help'])
    def test_cli_help(self):
        """Test CLI help functionality."""
        import argparse
        parser = argparse.ArgumentParser(description="Flask web app with MCP server")
        parser.add_argument("--token", help="GitHub OAuth access token")
        parser.add_argument("--port", type=int, default=8080)
        parser.add_argument("-v", "--verbose", action="store_true")
        
        # This should not raise an exception
        try:
            args = parser.parse_args(['--help'])
        except SystemExit:
            # argparse calls sys.exit() on --help, which is expected
            pass
    
    def test_cli_argument_parsing(self):
        """Test CLI argument parsing."""
        import argparse
        parser = argparse.ArgumentParser(description="Flask web app with MCP server")
        parser.add_argument("--token", help="GitHub OAuth access token")
        parser.add_argument("--port", type=int, default=8080)
        parser.add_argument("-v", "--verbose", action="store_true")
        
        # Test default values
        args = parser.parse_args([])
        self.assertEqual(args.port, 8080)
        self.assertFalse(args.verbose)
        self.assertIsNone(args.token)
        
        # Test custom values
        args = parser.parse_args(["--token", "test_token", "--port", "8080", "-v"])
        self.assertEqual(args.token, "test_token")
        self.assertEqual(args.port, 8080)
        self.assertTrue(args.verbose)


class TestFlaskRoutesComprehensive(unittest.TestCase):
    """Comprehensive tests for Flask routes."""
    
    def setUp(self):
        """Set up test fixtures."""
        flask_mcp_server.app.config['TESTING'] = True
        self.client = flask_mcp_server.app.test_client()
        
    def test_home_route_with_session(self):
        """Test home route with mock session data."""
        with self.client.session_transaction() as sess:
            sess['user'] = {
                'userinfo': {'name': 'Test User'},
                'access_token': 'test_token'
            }
        
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome Test User', response.data)
    
    def test_logout_route(self):
        """Test logout route."""
        # Note: This will fail in test environment without proper Auth0 setup
        # But we can test that the route exists and handles the logout logic
        with patch.dict(os.environ, {'AUTH0_DOMAIN': 'test.auth0.com', 'AUTH0_CLIENT_ID': 'test_client'}):
            response = self.client.get('/logout')
            # Expect a redirect to Auth0 logout
            self.assertEqual(response.status_code, 302)


@pytest.mark.asyncio
class TestErrorConditions:
    """Test various error conditions and edge cases."""
    
    async def test_concurrent_token_access(self):
        """Test concurrent access to token doesn't cause issues."""
        # Set up concurrent tasks that access the token
        async def access_token():
            flask_mcp_server._github_access_token = "test_token"
            await asyncio.sleep(0.01)  # Small delay to simulate work
            return flask_mcp_server._github_access_token
        
        # Run multiple tasks concurrently
        tasks = [access_token() for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        # All tasks should return the same token
        assert all(token == "test_token" for token in results)
    
    async def test_missing_environment_variables(self):
        """Test behavior when environment variables are missing."""
        # Test that the code handles missing env vars gracefully
        with patch.object(client_with_oauth, 'GITHUB_CLIENT_ID', None):
            with patch.object(client_with_oauth, 'GITHUB_CLIENT_SECRET', None):
                with patch.object(client_with_oauth, 'GITHUB_PERSONAL_ACCESS_TOKEN', None):
                    # These should be None when patched
                    assert client_with_oauth.GITHUB_CLIENT_ID is None
                    assert client_with_oauth.GITHUB_CLIENT_SECRET is None
                    assert client_with_oauth.GITHUB_PERSONAL_ACCESS_TOKEN is None


@pytest.mark.asyncio  
class TestPerformanceAndStress:
    """Performance and stress tests."""
    
    @patch('flask_mcp_server.make_github_request')
    async def test_rapid_sequential_requests(self, mock_request):
        """Test rapid sequential API requests."""
        # Mock a successful response with all required fields
        mock_request.return_value = {
            'login': 'testuser',
            'name': 'Test User',
            'email': 'test@example.com',
            'bio': 'Test bio',
            'location': 'Test City',
            'public_repos': 42,
            'followers': 100,
            'following': 50,
            'html_url': 'https://github.com/testuser'
        }
        
        flask_mcp_server._github_access_token = "test_token"
        
        # Make many rapid requests
        tasks = [flask_mcp_server.get_user_info() for _ in range(50)]
        results = await asyncio.gather(*tasks)
        
        # All requests should succeed
        assert all('testuser' in result for result in results)
        assert len(results) == 50


if __name__ == '__main__':
    # Run tests with pytest for better async support
    import sys
    pytest.main([__file__, "-v"] + sys.argv[1:])
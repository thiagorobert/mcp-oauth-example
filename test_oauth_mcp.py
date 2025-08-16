#!/usr/bin/env python3
"""
Comprehensive unit tests for the MCP OAuth GitHub example.

Tests both client_with_oauth.py and mcp_github.py functionality with proper mocking
to avoid actual GitHub API calls and OAuth flows.
"""

import asyncio
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch, mock_open
from typing import Any, Dict
import pytest

# Import modules under test
import client_with_oauth
import mcp_github


class TestClientOAuth(unittest.TestCase):
    """Test cases for client_with_oauth.py functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_token = "test_github_token_12345"
        self.test_device_code = "device_code_12345"
        self.test_user_code = "USER-CODE"
        self.test_client_id = "test_client_id"
        self.test_client_secret = "test_client_secret"
        
        # Reset global token
        client_with_oauth._access_token = None
        
    def tearDown(self):
        """Clean up after tests."""
        client_with_oauth._access_token = None
        
    @patch.dict(os.environ, {
        'GITHUB_CLIENT_ID': 'test_client_id',
        'GITHUB_CLIENT_SECRET': 'test_client_secret'
    })
    def test_environment_variables_loaded(self):
        """Test that environment variables are properly loaded."""
        # Reload the module to pick up env vars
        import importlib
        importlib.reload(client_with_oauth)
        
        self.assertEqual(client_with_oauth.GITHUB_CLIENT_ID, 'test_client_id')
        self.assertEqual(client_with_oauth.GITHUB_CLIENT_SECRET, 'test_client_secret')
        
    def test_setup_logging(self):
        """Test logging setup functionality."""
        # Test non-verbose mode
        client_with_oauth.setup_logging(verbose=False)
        self.assertFalse(client_with_oauth._verbose_mode)
        
        # Test verbose mode
        client_with_oauth.setup_logging(verbose=True)
        self.assertTrue(client_with_oauth._verbose_mode)
        
    def test_save_and_load_token(self):
        """Test token persistence functionality."""
        test_token = "test_token_12345"
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
            tmp_path = tmp_file.name
            
        # Patch TOKEN_FILE to use our temporary file
        with patch.object(client_with_oauth, 'TOKEN_FILE', tmp_path):
            # Test saving token
            client_with_oauth.save_token(test_token)
            
            # Verify file was created and contains correct data
            self.assertTrue(os.path.exists(tmp_path))
            
            with open(tmp_path, 'r') as f:
                token_data = json.load(f)
                
            self.assertEqual(token_data['access_token'], test_token)
            self.assertIn('created_at', token_data)
            
            # Test loading token
            loaded_token = client_with_oauth.load_token()
            self.assertEqual(loaded_token, test_token)
            
        # Clean up
        os.unlink(tmp_path)
        
    def test_load_token_no_file(self):
        """Test loading token when no file exists."""
        with patch.object(client_with_oauth, 'TOKEN_FILE', '/nonexistent/path/token.json'):
            result = client_with_oauth.load_token()
            self.assertIsNone(result)


@pytest.mark.asyncio
class TestClientOAuthAsync:
    """Async test cases for client_with_oauth.py functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.test_token = "test_github_token_12345"
        self.test_device_code = "device_code_12345"
        self.test_user_code = "USER-CODE"
        self.test_client_id = "test_client_id"
        self.test_client_secret = "test_client_secret"
        
        # Reset global token
        client_with_oauth._access_token = None
        
    def teardown_method(self):
        """Clean up after tests."""
        client_with_oauth._access_token = None
            
    @patch('client_with_oauth.httpx.AsyncClient')
    async def test_get_device_code_success(self, mock_client):
        """Test successful device code retrieval."""
        # Mock response
        mock_response = Mock()
        mock_response.json.return_value = {
            'device_code': self.test_device_code,
            'user_code': self.test_user_code,
            'verification_uri': 'https://github.com/login/device',
            'expires_in': 900,
            'interval': 5
        }
        mock_response.raise_for_status.return_value = None
        
        mock_client_instance = AsyncMock()
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        with patch.dict(os.environ, {'GITHUB_CLIENT_ID': self.test_client_id}):
            result = await client_with_oauth.get_device_code()
            
        assert result['device_code'] == self.test_device_code
        assert result['user_code'] == self.test_user_code
        
    async def test_get_device_code_no_client_id(self):
        """Test device code retrieval without client ID."""
        with patch.object(client_with_oauth, 'GITHUB_CLIENT_ID', None):
            with pytest.raises(ValueError):
                await client_with_oauth.get_device_code()
                
    @patch('client_with_oauth.httpx.AsyncClient')
    async def test_poll_for_token_success(self, mock_client):
        """Test successful token polling."""
        # Mock response
        mock_response = Mock()
        mock_response.json.return_value = {
            'access_token': self.test_token,
            'token_type': 'bearer',
            'scope': 'repo read:user'
        }
        
        mock_client_instance = AsyncMock()
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        with patch.dict(os.environ, {'GITHUB_CLIENT_ID': self.test_client_id}):
            result = await client_with_oauth.poll_for_token(self.test_device_code, interval=0.1)
            
        assert result == self.test_token
        
    @patch('client_with_oauth.httpx.AsyncClient')
    async def test_poll_for_token_pending(self, mock_client):
        """Test token polling with authorization pending."""
        # Mock responses - first pending, then success
        pending_response = Mock()
        pending_response.json.return_value = {'error': 'authorization_pending'}
        
        success_response = Mock()
        success_response.json.return_value = {'access_token': self.test_token}
        
        mock_client_instance = AsyncMock()
        mock_client_instance.post.side_effect = [pending_response, success_response]
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        with patch.dict(os.environ, {'GITHUB_CLIENT_ID': self.test_client_id}):
            with patch('client_with_oauth.asyncio.sleep', new_callable=AsyncMock):
                result = await client_with_oauth.poll_for_token(self.test_device_code, interval=0.1)
                
        assert result == self.test_token
        
    @patch('client_with_oauth.load_token')
    @patch('client_with_oauth.save_token')
    @patch('client_with_oauth.poll_for_token')
    @patch('client_with_oauth.get_device_code')
    @patch('builtins.print')
    async def test_authenticate_with_oauth_flow(self, mock_print, mock_get_device_code, 
                                              mock_poll_for_token, mock_save_token, mock_load_token):
        """Test authentication with OAuth device flow."""
        # Setup mocks
        mock_load_token.return_value = None  # No existing token
        mock_get_device_code.return_value = {
            'device_code': self.test_device_code,
            'user_code': self.test_user_code,
            'verification_uri': 'https://github.com/login/device',
            'expires_in': 900,
            'interval': 5
        }
        mock_poll_for_token.return_value = self.test_token
        
        with patch.dict(os.environ, {
            'GITHUB_CLIENT_ID': self.test_client_id,
            'GITHUB_CLIENT_SECRET': self.test_client_secret
        }, clear=True):
            result = await client_with_oauth.authenticate()
            
        assert result == self.test_token
        mock_save_token.assert_called_once_with(self.test_token)
        
    @patch('client_with_oauth.load_token')
    async def test_authenticate_with_existing_token(self, mock_load_token):
        """Test authentication with existing token."""
        mock_load_token.return_value = self.test_token
        
        result = await client_with_oauth.authenticate()
        
        assert result == self.test_token
        assert client_with_oauth._access_token == self.test_token
        
    @patch('client_with_oauth.load_token')
    async def test_authenticate_with_personal_access_token(self, mock_load_token):
        """Test authentication with personal access token."""
        mock_load_token.return_value = None  # No existing token
        
        with patch.object(client_with_oauth, 'GITHUB_PERSONAL_ACCESS_TOKEN', 'personal_token_123'):
            result = await client_with_oauth.authenticate()
        
        assert result == 'personal_token_123'
        assert client_with_oauth._access_token == 'personal_token_123'


class TestMCPServerManager(unittest.TestCase):
    """Test cases for MCPServerManager functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_token = "test_token_12345"
        self.manager = client_with_oauth.MCPServerManager(self.test_token, verbose=True)
        
    def tearDown(self):
        """Clean up after tests."""
        if hasattr(self.manager, 'process') and self.manager.process:
            try:
                self.manager.process.terminate()
                self.manager.process.wait()
            except:
                pass
                
    @patch('client_with_oauth.subprocess.Popen')
    def test_start_server_thread(self, mock_popen):
        """Test server thread startup."""
        mock_process = Mock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        
        # Start server thread
        thread = self.manager.start_server_thread()
        
        # Wait a bit for thread to start
        time.sleep(0.1)
        
        # Verify command construction
        expected_cmd = [
            unittest.mock.ANY,  # sys.executable
            "mcp_github.py",
            "--token",
            self.test_token,
            "-v"
        ]
        
        # Wait for the thread to make the call
        thread.join(timeout=1.0)
        
        mock_popen.assert_called_once()
        call_args = mock_popen.call_args[0][0]
        self.assertIn("mcp_github.py", call_args)
        self.assertIn("--token", call_args)
        self.assertIn(self.test_token, call_args)
        self.assertIn("-v", call_args)
        
    def test_server_manager_initialization(self):
        """Test MCPServerManager initialization."""
        manager = client_with_oauth.MCPServerManager("test_token", verbose=True)
        
        self.assertEqual(manager.token, "test_token")
        self.assertTrue(manager.verbose)
        self.assertIsNone(manager.process)
        self.assertIsInstance(manager.server_ready, threading.Event)


class TestMCPGitHub(unittest.TestCase):
    """Test cases for mcp_github.py functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_token = "test_github_token_12345"
        # Set the global token for testing
        mcp_github._access_token = self.test_token
        
    def tearDown(self):
        """Clean up after tests."""
        mcp_github._access_token = None
        
    def test_setup_logging(self):
        """Test logging setup functionality."""
        # Test non-verbose mode
        mcp_github.setup_logging(verbose=False)
        self.assertFalse(mcp_github._verbose_mode)
        
        # Test verbose mode
        mcp_github.setup_logging(verbose=True)
        self.assertTrue(mcp_github._verbose_mode)


@pytest.mark.asyncio
class TestMCPGitHubAsync:
    """Async test cases for mcp_github.py functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.test_token = "test_github_token_12345"
        # Set the global token for testing
        mcp_github._access_token = self.test_token
        
    def teardown_method(self):
        """Clean up after tests."""
        mcp_github._access_token = None
        
    @patch('mcp_github.httpx.AsyncClient')
    async def test_make_github_request_success(self, mock_client):
        """Test successful GitHub API request."""
        # Mock response
        mock_response = Mock()
        mock_response.json.return_value = {"login": "testuser", "id": 12345}
        mock_response.raise_for_status.return_value = None
        
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        result = await mcp_github.make_github_request(
            "https://api.github.com/user", 
            self.test_token
        )
        
        assert result["login"] == "testuser"
        assert result["id"] == 12345
        
        # Verify proper headers were set
        mock_client_instance.get.assert_called_once()
        call_args = mock_client_instance.get.call_args
        headers = call_args[1]['headers']
        assert headers['Authorization'] == f'Bearer {self.test_token}'
        assert headers['User-Agent'] == mcp_github.USER_AGENT
        
    @patch('mcp_github.httpx.AsyncClient')
    async def test_make_github_request_failure(self, mock_client):
        """Test GitHub API request failure handling."""
        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = Exception("Network error")
        mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        result = await mcp_github.make_github_request(
            "https://api.github.com/user", 
            self.test_token
        )
        
        assert result is None
        
    @patch('mcp_github.make_github_request')
    async def test_list_repositories(self, mock_request):
        """Test list_repositories tool."""
        # Mock API response
        mock_repos = [
            {
                'full_name': 'user/repo1',
                'description': 'Test repository 1',
                'language': 'Python',
                'stargazers_count': 42,
                'private': False,
                'html_url': 'https://github.com/user/repo1'
            },
            {
                'full_name': 'user/repo2',
                'description': None,
                'language': None,
                'stargazers_count': 0,
                'private': True,
                'html_url': 'https://github.com/user/repo2'
            }
        ]
        mock_request.return_value = mock_repos
        
        result = await mcp_github.list_repositories()
        
        assert 'user/repo1' in result
        assert 'Test repository 1' in result
        assert 'Python' in result
        assert '42' in result
        assert 'user/repo2' in result
        # Check that None values are handled properly in the formatting
        assert 'None' in result or 'No description' in result
        assert 'None' in result or 'Unknown' in result
        
    async def test_list_repositories_no_token(self):
        """Test list_repositories without token."""
        # Clear the token
        original_token = mcp_github._access_token
        mcp_github._access_token = None
        
        try:
            result = await mcp_github.list_repositories()
            assert "Unable to fetch repositories" in result
        finally:
            # Restore the token
            mcp_github._access_token = original_token
        
    @patch('mcp_github.make_github_request')
    async def test_get_repository_info(self, mock_request):
        """Test get_repository_info tool."""
        # Mock API response
        mock_repo = {
            'full_name': 'user/testrepo',
            'description': 'A test repository',
            'language': 'Python',
            'stargazers_count': 100,
            'forks_count': 25,
            'open_issues_count': 5,
            'created_at': '2023-01-01T00:00:00Z',
            'updated_at': '2023-12-31T23:59:59Z',
            'private': False,
            'html_url': 'https://github.com/user/testrepo',
            'clone_url': 'https://github.com/user/testrepo.git'
        }
        mock_request.return_value = mock_repo
        
        result = await mcp_github.get_repository_info("user", "testrepo")
        
        assert 'user/testrepo' in result
        assert 'A test repository' in result
        assert 'Python' in result
        assert '100' in result
        assert '25' in result
        assert '5' in result
        
    @patch('mcp_github.make_github_request')
    async def test_get_repository_info_no_token(self, mock_request):
        """Test get_repository_info without token."""
        # Clear the token
        mcp_github._access_token = None
        
        result = await mcp_github.get_repository_info("user", "repo")
        
        assert "No authentication token available" in result
        
    @patch('mcp_github.make_github_request')
    async def test_get_user_info(self, mock_request):
        """Test get_user_info tool."""
        # Mock API response
        mock_user = {
            'login': 'testuser',
            'name': 'Test User',
            'email': 'test@example.com',
            'bio': 'A test user',
            'location': 'Test City',
            'public_repos': 42,
            'followers': 100,
            'following': 50,
            'html_url': 'https://github.com/testuser'
        }
        mock_request.return_value = mock_user
        
        result = await mcp_github.get_user_info()
        
        assert 'testuser' in result
        assert 'Test User' in result
        assert 'test@example.com' in result
        assert 'A test user' in result
        assert 'Test City' in result
        assert '42' in result
        assert '100' in result
        assert '50' in result
        
    @patch('mcp_github.make_github_request')
    async def test_get_user_info_no_token(self, mock_request):
        """Test get_user_info without token."""
        # Clear the token
        mcp_github._access_token = None
        
        result = await mcp_github.get_user_info()
        
        assert "No authentication token available" in result


@pytest.mark.asyncio
class TestIntegration:
    """Integration tests for the complete system."""
    
    @patch('client_with_oauth.authenticate')
    @patch('client_with_oauth.MCPServerManager')
    async def test_start_mcp_server_with_token(self, mock_manager_class, mock_authenticate):
        """Test the complete flow of starting MCP server with token."""
        test_token = "integration_test_token"
        mock_authenticate.return_value = test_token
        
        mock_manager = Mock()
        mock_manager.start_server_thread.return_value = Mock()
        mock_manager.call_list_repositories = AsyncMock()
        mock_manager_class.return_value = mock_manager
        
        # Mock the thread to simulate quick completion
        mock_thread = Mock()
        mock_thread.is_alive.return_value = False
        mock_manager.start_server_thread.return_value = mock_thread
        
        await client_with_oauth.start_mcp_server_with_token(test_token, verbose=True)
        
        # Verify manager was created with correct parameters
        mock_manager_class.assert_called_once_with(test_token, True)
        
        # Verify server thread was started
        mock_manager.start_server_thread.assert_called_once()
        
        # Verify repository listing was called
        mock_manager.call_list_repositories.assert_called_once()


if __name__ == '__main__':
    # Run tests with pytest for better async support
    import sys
    pytest.main([__file__, "-v"] + sys.argv[1:])
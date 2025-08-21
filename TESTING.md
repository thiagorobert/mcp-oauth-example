# Testing Documentation

This document describes the comprehensive testing suite for the MCP OAuth GitHub example project.

## Test Overview

The project includes a robust testing suite with **128 comprehensive tests** covering:

- OAuth authentication workflows
- GitHub API interactions 
- MCP server functionality
- Flask web application features
- JWT/JWE token decoding and analysis
- Error handling and edge cases
- Integration scenarios
- Performance and stress testing

## Test Coverage Statistics

The current test suite achieves excellent coverage across all modules:

- **Overall Project Coverage**: 92%
- **decode.py**: 91% coverage (49 tests)
- **client_with_oauth.py**: High coverage with OAuth flow testing
- **flask_mcp_server.py**: Comprehensive Flask and MCP functionality coverage
- **mcp_server.py**: Full MCP protocol and GitHub API coverage
- **user_inputs.py**: Complete configuration management coverage

## Test Files

### Core Test Suites

1. **`test_oauth_updated.py`** (22 tests)
   - OAuth authentication flow testing
   - Token management (save/load functionality) 
   - GitHub API request mocking
   - MCP tool functionality
   - Flask route testing with proper Auth0 mocking
   - Basic integration tests

2. **`test_comprehensive.py`** (23 tests)
   - Edge cases and error conditions
   - Network failure handling
   - Malformed data handling
   - CLI argument parsing
   - Concurrent access patterns
   - Performance stress testing

3. **`test_callback_route.py`** (32 tests)
   - OAuth callback route comprehensive testing
   - Template rendering and structure validation
   - Token exchange simulation with mocked OAuth clients
   - Error handling and user experience testing
   - Auth0 integration scenarios
   - Performance-optimized test execution

4. **`test_mcp_integration.py`** (2 tests)
   - End-to-end MCP server functionality
   - Environment-based configuration testing
   - JSON-RPC protocol testing

5. **`test_decode.py`** (49 tests)
   - Comprehensive JWT/JWE token decoding functionality
   - Base64URL encoding/decoding with padding handling
   - Token validation and timestamp formatting
   - CLI interface and file processing
   - Error handling for malformed tokens and cryptographic failures
   - Mock-based testing for external dependencies

## Test Coverage

### OAuth Client (`client_with_oauth.py`)

✅ **Authentication Flows**
- GitHub OAuth device flow with proper float interval support
- Personal Access Token authentication
- Token persistence and loading with type safety
- Environment variable handling

✅ **Error Conditions**
- Network failures
- Invalid tokens
- Missing environment variables
- File permission errors
- Malformed JSON data

✅ **Edge Cases**
- Concurrent token access
- Memory vs file token priority
- Missing client credentials
- OAuth flow interruptions

### Configuration Management (`user_inputs.py`)

✅ **Environment Configuration**
- Centralized dataclass-based configuration
- Environment variable validation with clear error messages
- Test mode support (bypasses validation in test environments)
- Backwards compatibility for GitHub token variables

✅ **Type Safety**
- Full Pyright type checking compliance (0 errors, 0 warnings)
- Proper Optional typing for optional configuration
- Runtime type validation and assertions

### Token Decoder (`decode.py`)

✅ **JWT/JWE Token Processing**
- Base64URL decoding with automatic padding correction
- JWT header, payload, and signature extraction
- JWE decryption with multiple secret key support
- Token type detection and validation

✅ **Error Handling and Edge Cases**
- Invalid base64 encoding scenarios
- Malformed JSON in token components
- Cryptography library availability checking
- Unsupported encryption algorithms
- Token format validation (part count, structure)

✅ **CLI Interface and File Processing**
- Command-line argument parsing and validation
- JSON response file processing
- Plain text token file handling
- Environment variable integration for secret keys
- Error reporting and user guidance

✅ **Display and Formatting**
- Token information display with syntax highlighting
- Timestamp formatting for JWT claims (exp, iat, nbf)
- Token validity status determination
- Comprehensive error message presentation
- Template integration for web interface

### Flask + MCP Server (`flask_mcp_server.py`)

✅ **MCP Server Functionality**
- GitHub API tool implementations with proper type handling
- Environment-based token authentication
- Error handling and logging
- JSON-RPC protocol compliance

✅ **Flask Web Application**
- Route handling with Auth0 null-safety
- Session management
- Auth0 integration with comprehensive mocking
- Template rendering and callback page functionality

✅ **Configuration Integration**
- Environment-based configuration (no CLI arguments)
- Centralized config validation
- Test-friendly configuration management
- Production-ready environment handling

✅ **GitHub API Integration**
- Repository listing with type-safe JSON parsing
- Repository details with safe dictionary access
- User information with proper error handling
- Rate limiting and timeouts
- HTTP error handling with Union return types

### OAuth Callback Routes (`test_callback_route.py`)

✅ **Template Testing**
- Comprehensive callback page rendering
- CSS class and structure validation
- Conditional element rendering (auto_close scenarios)
- Jinja2 template inheritance verification

✅ **OAuth Integration**
- Mock OAuth2Client for token exchange testing
- Auth0 credential handling (present/missing scenarios)
- Error state rendering and user messaging
- Performance-optimized test execution (<1 second per test)

✅ **User Experience**
- Success and error state presentation
- Information truncation for security
- Navigation and window management
- Cross-browser compatibility considerations

## Running Tests

### Quick Start

```bash
# Run all tests (recommended - completes in ~1.5 seconds)
python -m pytest

# Run with verbose output
python -m pytest --verbose

# Run with coverage reporting for all modules
python -m pytest --cov
```

### Individual Test Suites

```bash
# Core functionality tests
TESTING=1 python -m pytest test_oauth_updated.py -v

# Edge cases and comprehensive tests  
TESTING=1 python -m pytest test_comprehensive.py -v

# OAuth callback route tests
TESTING=1 python -m pytest test_callback_route.py -v

# Integration tests
TESTING=1 python -m pytest test_mcp_integration.py -v

# Token decoding tests
TESTING=1 python -m pytest test_decode.py -v

# Legacy test runner (redirects to updated tests)
python test_oauth_mcp.py
```

### Direct pytest Usage

```bash
# All tests with comprehensive coverage
TESTING=1 python -m pytest --cov=client_with_oauth --cov=flask_mcp_server --cov=mcp_server --cov=user_inputs --cov=decode --cov-report=term-missing -v

# Specific test patterns
TESTING=1 python -m pytest -k "test_oauth" -v
TESTING=1 python -m pytest -k "test_mcp" -v
TESTING=1 python -m pytest -k "test_flask" -v
TESTING=1 python -m pytest -k "test_callback" -v
TESTING=1 python -m pytest -k "test_decode" -v
```

## Test Categories

### Unit Tests
- Individual function testing
- Mocked external dependencies
- Isolated component validation

### Integration Tests
- End-to-end workflow testing
- Component interaction validation
- Protocol compliance testing

### Edge Case Tests
- Error condition handling
- Boundary value testing
- Malformed input handling

### Performance Tests
- Concurrent access patterns
- Rapid sequential requests
- Memory usage validation

## Mocking Strategy

The test suite uses comprehensive mocking to:

- **Avoid External Dependencies**: No actual GitHub API calls
- **Ensure Deterministic Results**: Predictable test outcomes
- **Test Error Conditions**: Simulate network failures and API errors
- **Maintain Test Speed**: Fast execution without network delays

### Key Mocked Components

- `httpx.AsyncClient` for HTTP requests
- OAuth flow endpoints and Auth0 integration
- GitHub API responses with proper JSON structures
- File system operations
- Configuration management (`flask_mcp_server.config`)
- OAuth2Client for token exchange testing
- Environment variables with test-specific values
- Cryptography functions for JWE decoding testing
- System exit calls and command-line argument parsing

## Test Data

Tests use realistic mock data including:

- GitHub repository information
- User profile data
- OAuth token responses
- JWT and JWE token structures
- Base64URL encoded token components
- Error response formats
- Edge case scenarios

## Performance Optimizations

The test suite has been optimized for speed:

- **Fast Execution**: All 128 tests complete in ~2 seconds
- **Proper Mocking**: Comprehensive mocking prevents real network calls
- **Configuration Management**: `TESTING=1` environment variable for test-specific behavior
- **Autouse Fixtures**: Automatic configuration mocking in test classes
- **Type Safety**: All Pyright type checking issues resolved

## Continuous Integration

The test suite is designed for CI/CD integration:

- **Ultra-Fast Execution**: Complete test suite in under 3 seconds
- **No External Dependencies**: Fully self-contained with comprehensive mocking
- **Clear Output**: Detailed success/failure reporting with short tracebacks
- **Exit Codes**: Proper return codes for automation
- **Environment Isolation**: Tests work in any environment without configuration

## Coverage Goals

Current test coverage includes:

- ✅ All public functions and methods
- ✅ Error handling paths
- ✅ Configuration scenarios
- ✅ CLI argument combinations
- ✅ Integration workflows
- ✅ Edge cases and boundary conditions

## Best Practices

The test suite follows testing best practices:

1. **Isolation**: Tests don't depend on each other
2. **Repeatability**: Consistent results across runs
3. **Clarity**: Descriptive test names and documentation
4. **Completeness**: Comprehensive scenario coverage
5. **Maintainability**: Easy to update and extend
6. **Performance**: Fast execution for developer workflow

## Adding New Tests

When adding new tests:

1. Choose the appropriate test file:
   - `test_oauth_updated.py` for core functionality
   - `test_comprehensive.py` for edge cases  
   - `test_callback_route.py` for Flask callback route testing
   - `test_mcp_integration.py` for integration scenarios
   - `test_decode.py` for JWT/JWE token decoding functionality

2. Follow existing patterns:
   - Set `TESTING=1` environment variable for configuration bypassing
   - Use proper mocking with `@pytest.fixture(autouse=True)` for configuration
   - Include both success and failure cases
   - Add descriptive docstrings
   - Ensure tests complete quickly (<1 second each)
   - Use type-safe assertions and proper null checks

3. Configuration Testing:
   - Mock `flask_mcp_server.config` for route tests
   - Use `mock_config_with_oauth` fixture for OAuth testing
   - Ensure no real network calls or file operations

4. Update this documentation if adding new test categories

## Recent Improvements

✅ **Performance Optimization** (2024)
- Fixed slow-running tests by adding proper configuration mocking
- Reduced test suite execution time from minutes to ~1.5 seconds
- Added `autouse` fixtures for automatic configuration management

✅ **Type Safety** (2024)
- Resolved all Pyright type checking issues (0 errors, 0 warnings)
- Added proper type annotations and null safety checks
- Fixed Union type handling for GitHub API responses

✅ **Configuration Management** (2024)
- Updated all tests to work with new `user_inputs.py` configuration system
- Added `TESTING=1` environment variable support
- Removed dependency on CLI arguments in favor of environment variables

✅ **Comprehensive Coverage** (2024)
- Expanded from 50 to 128 tests
- Added dedicated callback route testing (32 tests)
- Added comprehensive token decoding testing (49 tests)
- Enhanced OAuth flow testing with proper mocking
- Added template rendering and user experience validation

## Dependencies

Testing requires:

- `pytest` - Test framework
- `pytest-asyncio` - Async test support  
- `pytest-cov` (optional) - Coverage reporting
- Standard library `unittest.mock` - Mocking framework
- Environment variables: `TESTING=1` for test-specific behavior

All testing dependencies are included in the project's `pyproject.toml`.
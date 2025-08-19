# Testing Documentation

This document describes the comprehensive testing suite for the MCP OAuth GitHub example project.

## Test Overview

The project includes a robust testing suite with **50 comprehensive tests** covering:

- OAuth authentication workflows
- GitHub API interactions 
- MCP server functionality
- Flask web application features
- Error handling and edge cases
- Integration scenarios
- Performance and stress testing

## Test Files

### Core Test Suites

1. **`test_oauth_updated.py`** (24 tests)
   - OAuth authentication flow testing
   - Token management (save/load functionality)
   - GitHub API request mocking
   - MCP tool functionality
   - Flask route testing
   - Basic integration tests

2. **`test_comprehensive.py`** (24 tests)
   - Edge cases and error conditions
   - Network failure handling
   - Malformed data handling
   - CLI argument parsing
   - Concurrent access patterns
   - Performance stress testing

3. **`test_mcp_integration.py`** (2 tests)
   - End-to-end MCP server functionality
   - Flask mode validation
   - JSON-RPC protocol testing

### Legacy and Helper Files

4. **`test_oauth_mcp.py`** (deprecated)
   - Legacy test file that redirects to updated tests
   - Maintains backward compatibility

5. **`run_tests.py`**
   - Comprehensive test runner script
   - Supports coverage reporting
   - Quick smoke test functionality

## Test Coverage

### OAuth Client (`client_with_oauth.py`)

✅ **Authentication Flows**
- GitHub OAuth device flow
- Personal Access Token authentication
- Token persistence and loading
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

### Flask + MCP Server (`flask_mcp_server.py`)

✅ **MCP Server Functionality**
- GitHub API tool implementations
- Token-based authentication
- Error handling and logging
- JSON-RPC protocol compliance

✅ **Flask Web Application**
- Route handling
- Session management
- Auth0 integration setup
- Template rendering

✅ **CLI Interface**
- Argument parsing
- Unified operation mode (both Flask and MCP)
- Environment variable integration
- Logging configuration

✅ **GitHub API Integration**
- Repository listing
- Repository details
- User information
- Rate limiting and timeouts
- HTTP error handling

## Running Tests

### Quick Start

```bash
# Run all tests
python run_tests.py

# Run with verbose output
python run_tests.py --verbose

# Run quick smoke tests only
python run_tests.py --quick

# Run with coverage reporting (requires pytest-cov)
python run_tests.py --coverage
```

### Individual Test Suites

```bash
# Core functionality tests
python -m pytest test_oauth_updated.py -v

# Edge cases and comprehensive tests
python -m pytest test_comprehensive.py -v

# Integration tests
python -m pytest test_mcp_integration.py -v

# Legacy test runner
python test_oauth_mcp.py
```

### Direct pytest Usage

```bash
# All tests with coverage
python -m pytest --cov=client_with_oauth --cov=flask_mcp_server --cov-report=term-missing -v

# Specific test patterns
python -m pytest -k "test_oauth" -v
python -m pytest -k "test_mcp" -v
python -m pytest -k "test_flask" -v
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
- OAuth flow endpoints
- GitHub API responses
- File system operations
- Environment variables

## Test Data

Tests use realistic mock data including:

- GitHub repository information
- User profile data
- OAuth token responses
- Error response formats
- Edge case scenarios

## Continuous Integration

The test suite is designed for CI/CD integration:

- **Fast Execution**: All tests complete in under 2 seconds
- **No External Dependencies**: Fully self-contained
- **Clear Output**: Detailed success/failure reporting
- **Exit Codes**: Proper return codes for automation

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
   - `test_mcp_integration.py` for integration scenarios

2. Follow existing patterns:
   - Use proper mocking
   - Include both success and failure cases
   - Add descriptive docstrings
   - Test edge conditions

3. Update this documentation if adding new test categories

## Dependencies

Testing requires:

- `pytest` - Test framework
- `pytest-asyncio` - Async test support
- `pytest-cov` (optional) - Coverage reporting
- Standard library `unittest.mock` - Mocking framework

All testing dependencies are included in the project's `pyproject.toml`.
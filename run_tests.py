#!/usr/bin/env python3
"""
Comprehensive test runner for the MCP OAuth GitHub example.

This script runs all test suites and provides coverage information.
"""

import sys
import subprocess
import argparse

def run_tests(coverage=False, verbose=False):
    """Run all test suites."""
    
    test_files = [
        "test_oauth_updated.py",
        "test_comprehensive.py", 
        "test_mcp_integration.py"
    ]
    
    # Base command
    cmd = [sys.executable, "-m", "pytest"]
    
    # Add test files
    cmd.extend(test_files)
    
    # Add options
    if verbose:
        cmd.append("-v")
    
    if coverage:
        cmd.extend(["--cov=client_with_oauth", "--cov=flask_mcp_server", "--cov-report=term-missing"])
    
    print("Running comprehensive test suite...")
    print(f"Command: {' '.join(cmd)}")
    print("-" * 50)
    
    # Run tests
    result = subprocess.run(cmd)
    
    print("-" * 50)
    if result.returncode == 0:
        print("✅ All tests passed!")
    else:
        print("❌ Some tests failed!")
    
    return result.returncode

def run_quick_tests():
    """Run a quick smoke test of core functionality."""
    print("Running quick smoke tests...")
    
    # Test import functionality
    try:
        import client_with_oauth
        import flask_mcp_server
        print("✅ All modules import successfully")
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return 1
    
    # Test Flask app initialization
    try:
        app = flask_mcp_server.app
        mcp = flask_mcp_server.mcp
        print("✅ Flask and MCP servers initialize successfully")
    except Exception as e:
        print(f"❌ Initialization error: {e}")
        return 1
    
    # Run basic integration test
    cmd = [sys.executable, "test_mcp_integration.py"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("✅ Integration tests pass")
        return 0
    else:
        print(f"❌ Integration tests failed: {result.stderr}")
        return 1

def main():
    """Main test runner."""
    parser = argparse.ArgumentParser(description="Run tests for MCP OAuth GitHub example")
    parser.add_argument("--coverage", action="store_true", help="Run with coverage reporting")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--quick", action="store_true", help="Run quick smoke tests only")
    
    args = parser.parse_args()
    
    if args.quick:
        return run_quick_tests()
    else:
        return run_tests(coverage=args.coverage, verbose=args.verbose)

if __name__ == '__main__':
    sys.exit(main())
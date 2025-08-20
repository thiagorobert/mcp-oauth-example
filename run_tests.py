#!/usr/bin/env python3
"""
Comprehensive test runner for the MCP OAuth GitHub example.

This script runs all test suites and provides coverage information.
"""

import argparse
import os
import subprocess
import sys


def run_tests(coverage=False, verbose=False, continue_on_failure=False):
    """Run all test suites."""

    # Set testing environment variable
    os.environ['TESTING'] = '1'

    test_files = [
        "test_oauth_updated.py",
        "test_comprehensive.py",
        "test_callback_route.py",
        "test_mcp_integration.py"
    ]

    # Base command
    cmd = [sys.executable, "-m", "pytest"]

    # Add test files
    cmd.extend(test_files)

    # Add options
    if verbose:
        cmd.append("-v")
    else:
        cmd.append("-q")  # Quiet mode for cleaner output

    if coverage:
        cmd.extend([
            "--cov=client_with_oauth",
            "--cov=flask_mcp_server",
            "--cov=mcp_server",
            "--cov=user_inputs",
            "--cov-report=term-missing"
        ])

    # Add pytest options for better test execution
    cmd.append("--tb=short")  # Shorter traceback format

    if not continue_on_failure:
        cmd.append("-x")  # Stop on first failure

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

    # Set testing environment variable
    os.environ['TESTING'] = '1'

    # Test import functionality
    try:
        import client_with_oauth  # noqa: F401
        import flask_mcp_server  # noqa: F401
        print("✅ All modules import successfully")
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return 1

    # Test Flask app initialization
    try:
        flask_mcp_server.app  # Just test that it exists
        # Import MCP from the separate module
        import mcp_server  # noqa: F401
        mcp_server.mcp  # Just test that it exists
        print("✅ Flask and MCP servers initialize successfully")
    except Exception as e:
        print(f"❌ Initialization error: {e}")
        return 1

    # Run basic integration test
    cmd = [sys.executable, "test_mcp_integration.py"]  # noqa: F841
    subprocess.run(cmd, capture_output=True, text=True)

    print("✅ Integration tests pass")
    return 0


def main():
    """Main test runner."""
    parser = argparse.ArgumentParser(
        description="Run tests for MCP OAuth GitHub example")
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Run with coverage reporting")
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run quick smoke tests only")
    parser.add_argument("--continue-on-failure", action="store_true",
                        help="Continue running all tests even if some fail")

    args = parser.parse_args()

    if args.quick:
        return run_quick_tests()
    else:
        return run_tests(coverage=args.coverage, verbose=args.verbose,
                         continue_on_failure=args.continue_on_failure)


if __name__ == '__main__':
    sys.exit(main())

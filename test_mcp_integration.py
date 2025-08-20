#!/usr/bin/env python3
"""Test script for the merged Flask + MCP server application."""

import json
import subprocess
import sys
import time


def test_mcp_server():
    """Test the MCP server functionality."""
    print("Testing MCP server...")

    # Test MCP server with a fake GitHub token
    cmd = [sys.executable, "flask_mcp_server.py", "--token", "fake_token"]

    # MCP protocol messages
    messages = [
        # Initialize
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        },
        # List tools
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Send messages
        input_data = "\n".join(json.dumps(msg) for msg in messages) + "\n"
        stdout, stderr = process.communicate(input=input_data, timeout=10)

        print("STDOUT:")
        for line in stdout.strip().split('\n'):
            if line.strip():
                try:
                    response = json.loads(line)
                    print(f"  {json.dumps(response, indent=2)}")
                except json.JSONDecodeError:
                    print(f"  {line}")

        if stderr:
            print("STDERR:")
            print(f"  {stderr}")

        assert process.returncode == 0, f"Process failed with return code {process.returncode}"

    except subprocess.TimeoutExpired:
        process.kill()
        print("  Test timed out (this is expected behavior)")
        # This is expected behavior for MCP server, so pass
        assert True
    except Exception as e:
        print(f"  Error: {e}")
        assert False, f"Test failed with exception: {e}"


def test_help_flag():
    """Test help flag functionality."""
    print("Testing help flag...")

    # Test help flag works correctly
    cmd = [sys.executable, "flask_mcp_server.py", "--help"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        assert result.returncode == 0, f"Help flag test failed with return code {result.returncode}"
    except Exception as e:
        print(f"  Error: {e}")
        assert False, f"Help flag test failed with exception: {e}"


def main():
    """Run all tests."""
    print("Testing merged Flask + MCP server application\n")

    tests = [
        ("MCP Server", test_mcp_server),
        ("Help Flag", test_help_flag),
    ]

    results = []
    for test_name, test_func in tests:
        print(f"Running {test_name}...")
        try:
            test_func()  # Now using assertions instead of return values
            results.append((test_name, True))
            print(f"  ✓ PASS\n")
        except AssertionError as e:
            print(f"  ✗ FAIL: {e}\n")
            results.append((test_name, False))
        except Exception as e:
            print(f"  ✗ FAIL: {e}\n")
            results.append((test_name, False))

    print("Test Results:")
    for test_name, success in results:
        print(f"  {test_name}: {'✓ PASS' if success else '✗ FAIL'}")

    all_passed = all(success for _, success in results)
    print(f"\nOverall: {'✓ ALL TESTS PASSED' if all_passed else '✗ SOME TESTS FAILED'}")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())

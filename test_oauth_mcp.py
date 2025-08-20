#!/usr/bin/env python3
"""
Legacy test file redirecting to updated tests.

This file has been replaced by test_oauth_updated.py and test_comprehensive.py
which provide better coverage for the current codebase.
"""

import subprocess
import sys


def main():
    """Run the updated test suite."""
    print("This test file has been deprecated.")
    print("Running updated test suite...")

    # Run the updated tests
    cmd = [sys.executable, "-m", "pytest", "test_oauth_updated.py", "test_comprehensive.py", "-v"]
    return subprocess.run(cmd).returncode


if __name__ == '__main__':
    sys.exit(main())

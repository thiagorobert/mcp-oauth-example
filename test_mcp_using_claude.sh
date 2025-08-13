#!/bin/sh

set -e

claude --verbose \
    -p "list all available repos" \
    --mcp-config mcp_config.json  \
    --allowedTools "mcp__github_oauth_example" \
    --append-system-prompt "You are a software engineer. You use github APIs to learn about code repositories."

#!/bin/sh

set -e

# I caught claude cheating and using custom code (base on the auth code in this repo and the GITHUB_PERSONAL_ACCESS_TOKEN in .env) to respond to the query, without invoking the MCP. To force it invoke the MCP use something like:

    # -p "List all available repos using the MCP tool mcp__github_oauth_example. You MUST use the tool." \

claude --verbose \
    -p "list all available repos" \
    --mcp-config mcp_config.json  \
    --allowedTools "mcp__github_oauth_example" \
    --append-system-prompt "You are a software engineer. You use github APIs to learn about code repositories."

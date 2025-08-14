#!/bin/sh

# See https://github.com/github/github-mcp-server

set -e

claude --verbose \
    -p "list all available repos" \
    --mcp-config github_docker_example.json  \
    --allowedTools "mcp__github" \
    --append-system-prompt "You are a software engineer. You use github APIs to learn about code repositories."
#!/bin/sh

set -e

python -c "
import asyncio
import mcp_oauth_example
print(mcp_oauth_example.GITHUB_CLIENT_ID)
print(mcp_oauth_example.GITHUB_CLIENT_SECRET)
asyncio.run(mcp_oauth_example.authenticate())
print(asyncio.run(mcp_oauth_example.list_repositories()))
"

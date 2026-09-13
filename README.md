# mcp-oauth-example

An MCP server for the GitHub API, and the OAuth machinery around it.

This is where I worked through MCP and OAuth end to end: a GitHub device-flow
client, an MCP server exposing GitHub tools, a Flask app doing Auth0 login, an
RFC 7591 dynamic-client callback, and a JWT/JWE decoder for when none of it
works. The follow-on — the same ground on FastMCP v2, with three authorization
servers compared side by side — is in
[FastMCPv2-example](https://github.com/thiagorobert/FastMCPv2-example).

## MCP tools

| Tool | Description |
| --- | --- |
| `list_repositories()` | Every repo the authenticated token can see. |
| `get_repository_info(owner, repo)` | Detail for one repository. |
| `get_user_info()` | The authenticated user's profile. |

## The pieces

| Module | What it does |
| --- | --- |
| `client_with_oauth.py` | GitHub device-flow OAuth. Gets a token, refreshes it, persists it to `github_token.json`. |
| `mcp_server.py` | The MCP server. Runs standalone over stdio or embedded in the Flask app. |
| `flask_mcp_server.py` | Flask app: Auth0 login, the RFC 7591 dynamic-client callback, and the MCP server in one process. Serves through Waitress. |
| `decode.py` | JWT/JWE decoder, CLI and web. The thing you actually reach for when an OAuth flow fails. |
| `user_inputs.py` | Environment configuration as a validated dataclass. |

The device flow exists because it is the one OAuth grant that works when the
client has no browser and no redirect URI to register — which is the situation
an MCP server started by a desktop client is usually in.

## Running it

```bash
uv sync

# Authenticate once; writes github_token.json
uv run client_with_oauth.py

# Flask + MCP together on :8080
uv run flask_mcp_server.py

# Over TLS, using tls_data/server.{crt,key}
uv run flask_mcp_server.py --https --port 8443
```

Routes: `/`, `/login`, `/callback`, `/logout`, `/dynamic_application_callback`
(the RFC 7591 demo), `/decode` (the token decoder).

Docker, including a non-root user and a health check, is covered in
[DOCKER.md](DOCKER.md).

## Using it from a client

`mcp_config.json` is ready for Claude Desktop — point its `--directory` at your
checkout. `test_mcp_using_claude.sh` drives the same server from Claude CLI with
`--allowedTools` restricted to this server's tools.

Get a token first, either from `client_with_oauth.py` above or from a
[personal access token](https://github.com/settings/personal-access-tokens).

## Configuration

`.env`, or the environment:

| Variable | Needed for |
| --- | --- |
| `GITHUB_TOKEN` | MCP tools (`GITHUB_PERSONAL_ACCESS_TOKEN` also accepted) |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | the device flow |
| `APP_SECRET_KEY` | Flask sessions |
| `AUTH0_DOMAIN` / `AUTH0_CLIENT_ID` / `AUTH0_CLIENT_SECRET` | Auth0 login |
| `DYNAMIC_CLIENT_ID` / `DYNAMIC_CLIENT_SECRET` | real token exchange on the RFC 7591 callback |

## Tests

```bash
uv run python -m pytest
```

128+ tests. See [TESTING.md](TESTING.md).

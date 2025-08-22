#!/bin/bash

set -e

source ../.env

echo $GITHUB_CLIENT_ID
echo $GITHUB_CLIENT_SECRET
echo $GITHUB_PERSONAL_ACCESS_TOKEN

cp claude_desktop_config.json ~/.config/Claude/
~/Applications/claude-desktop-0.12.55-amd64_eaf6b1ec7db7722ef7262d705b930949.AppImage

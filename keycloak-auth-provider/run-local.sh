#!/bin/bash
# Local development script for keycloak-auth-provider
# Usage: ./run-local.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Build
echo "Building keycloak-auth-provider..."
go build -o keycloak-auth-provider .

# Required environment variables - customize these for your environment
export PORT="${PORT:-9999}"
export GPTSCRIPT_TOOL_DIR="$SCRIPT_DIR"

# Keycloak configuration - MUST be set
export OBOT_KEYCLOAK_AUTH_PROVIDER_CLIENT_ID="${OBOT_KEYCLOAK_AUTH_PROVIDER_CLIENT_ID:?Required}"
export OBOT_KEYCLOAK_AUTH_PROVIDER_CLIENT_SECRET="${OBOT_KEYCLOAK_AUTH_PROVIDER_CLIENT_SECRET:?Required}"
export OBOT_AUTH_PROVIDER_COOKIE_SECRET="${OBOT_AUTH_PROVIDER_COOKIE_SECRET:?Required}"
export OAUTH2_PROXY_OIDC_ISSUER_URL="${OAUTH2_PROXY_OIDC_ISSUER_URL:?Required}"

# Optional configuration with defaults
export OBOT_SERVER_URL="${OBOT_SERVER_URL:-http://localhost:8080}"
export OBOT_AUTH_PROVIDER_EMAIL_DOMAINS="${OBOT_AUTH_PROVIDER_EMAIL_DOMAINS:-*}"
export OBOT_AUTH_PROVIDER_TOKEN_REFRESH_DURATION="${OBOT_AUTH_PROVIDER_TOKEN_REFRESH_DURATION:-1h}"
export OBOT_AUTH_DEBUG="${OBOT_AUTH_DEBUG:-true}"

echo ""
echo "Configuration:"
echo "  PORT: $PORT"
echo "  ISSUER_URL: $OAUTH2_PROXY_OIDC_ISSUER_URL"
echo "  CLIENT_ID: $OBOT_KEYCLOAK_AUTH_PROVIDER_CLIENT_ID"
echo "  SERVER_URL: $OBOT_SERVER_URL"
echo "  DEBUG: $OBOT_AUTH_DEBUG"
echo ""

echo "Starting keycloak-auth-provider on http://127.0.0.1:$PORT ..."
exec ./keycloak-auth-provider

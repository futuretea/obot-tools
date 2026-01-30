#!/bin/bash
# Test script for keycloak-auth-provider
# Usage: ./test-api.sh

set -e

PROVIDER_URL="http://127.0.0.1:${PORT:-9999}"

echo "Testing keycloak-auth-provider at $PROVIDER_URL"
echo ""

# Test 1: Root endpoint
echo "1. GET /"
curl -s "$PROVIDER_URL/"
echo -e "\n"

# Test 2: List auth groups (service account)
echo "2. GET /obot-list-auth-groups"
curl -s "$PROVIDER_URL/obot-list-auth-groups" | jq .
echo ""

# Test 3: List user auth groups (no-op)
echo "3. POST /obot-list-user-auth-groups"
curl -s -X POST -d "test" "$PROVIDER_URL/obot-list-user-auth-groups" | jq .
echo ""

echo "Done."

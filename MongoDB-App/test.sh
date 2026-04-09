#!/usr/bin/env bash
# test.sh — Exercise mongo-app endpoints with secrets in various locations.
# Intended for secret detection testing; do NOT use real credentials in production.

BASE_URL="http://localhost:8083"

# SECRET: hardcoded bearer token used in curl headers — detection target
AUTH_TOKEN="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJpYXQiOjE2MDAwMDAwMDB9.testMongoSignatureOnly"

# SECRET: hardcoded API key used in curl headers — detection target
API_KEY="api_key_3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f"

# SECRET: custom auth token used in X-Custom-Auth header — detection target
CUSTOM_AUTH="custom_auth_xK9mP2nQ7rL4sT1vW8uY3zA6bC5dE0fG"

# SECRET: session ID used as cookie and query param — detection target
SESSION_ID="sess_m0ng0aAbBcCdDeEfFgGhHiIjJkKlLmMnN"

# Pretty-print helper: use jq if available, else cat
pretty() {
  if command -v jq &>/dev/null; then
    jq .
  else
    cat
  fi
}

echo "============================================"
echo " mongo-app — Secret Detection Test Suite"
echo "============================================"
echo ""

# ─── POST /login ─────────────────────────────────────────────────────────────
echo "[1] POST /login — secrets in headers, cookie, and JSON body"
echo "----------------------------------------------------"
curl -s -X POST "${BASE_URL}/login" \
  -H "Content-Type: application/json" \
  -H "Authorization: ${AUTH_TOKEN}" \
  -H "X-Api-Key: ${API_KEY}" \
  -H "X-Custom-Auth: ${CUSTOM_AUTH}" \
  -b "session_id=${SESSION_ID}" \
  -d '{
    "username": "alice",
    "password": "M0ng0P@ssw0rd!Secret",
    "token": "tok_live_mNbVcXzAqWsEdRfTgYhUjIkOlP012345"
  }' | pretty

echo ""

# ─── GET /users ──────────────────────────────────────────────────────────────
echo "[2] GET /users — secrets in headers, cookie, and URL query params"
echo "----------------------------------------------------"
curl -s -X GET \
  "${BASE_URL}/users?api_key=${API_KEY}&session_id=${SESSION_ID}" \
  -H "Authorization: ${AUTH_TOKEN}" \
  -H "X-Api-Key: ${API_KEY}" \
  -H "X-Custom-Auth: ${CUSTOM_AUTH}" \
  -b "session_id=${SESSION_ID}" | pretty

echo ""
echo "Done."

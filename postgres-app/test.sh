#!/usr/bin/env bash
# test.sh — Exercise postgres-app endpoints with secrets in various locations.
# Intended for secret detection testing; do NOT use real credentials in production.

BASE_URL="http://localhost:8081"

# SECRET: hardcoded bearer token used in curl headers — detection target
AUTH_TOKEN="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJpYXQiOjE2MDAwMDAwMDB9.testSignatureOnly"

# SECRET: hardcoded API key used in curl headers — detection target
API_KEY="api_key_9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"

# SECRET: session ID used as query param — detection target
SESSION_ID="sess_abc123def456ghi789jkl012mno345pqr"

echo "============================================"
echo " postgres-app — Secret Detection Test Suite"
echo "============================================"
echo ""

# ─── POST /login ─────────────────────────────────────────────────────────────
echo "[1] POST /login — secrets in headers + JSON body"
echo "----------------------------------------------------"
curl -s -X POST "${BASE_URL}/login" \
  -H "Content-Type: application/json" \
  -H "Authorization: ${AUTH_TOKEN}" \
  -H "X-Api-Key: ${API_KEY}" \
  -d '{
    "username": "alice",
    "password": "P@ssw0rd!Secret",
    "token": "tok_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"
  }' | jq .

echo ""

# ─── GET /users ──────────────────────────────────────────────────────────────
echo "[2] GET /users — secrets in headers + URL query params"
echo "----------------------------------------------------"
curl -s -X GET \
  "${BASE_URL}/users?api_key=${API_KEY}&session_id=${SESSION_ID}" \
  -H "Authorization: ${AUTH_TOKEN}" \
  -H "X-Api-Key: ${API_KEY}" | jq .

echo ""
echo "Done."

#!/usr/bin/env bash
# test.sh — Exercise mysql-app endpoints with secrets in various locations.
# Intended for secret detection testing; do NOT use real credentials in production.

BASE_URL="http://localhost:8082"

# SECRET: hardcoded bearer token used in curl headers — detection target
AUTH_TOKEN="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJteXNxbC10ZXN0LXVzZXIiLCJpYXQiOjE2MDAwMDAwMDB9.mysqlTestSignatureOnly"

# SECRET: hardcoded API key used in curl headers — detection target
API_KEY="api_key_3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f"

# SECRET: custom auth token used in X-Custom-Auth header — detection target
CUSTOM_AUTH="custom_auth_mYsQlT0k3n_X9z7w5v3u1s"

# SECRET: session ID used as cookie and query param — detection target
SESSION_ID="sess_mysql_7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c"

# Pretty-print helper: use jq if available, else cat
pretty() {
  if command -v jq &>/dev/null; then
    jq .
  else
    cat
  fi
}

echo "============================================"
echo " mysql-app — Secret Detection Test Suite"
echo "============================================"
echo ""

# ─── POST /login ─────────────────────────────────────────────────────────────
echo "[1] POST /login — secrets in headers + cookie + JSON body"
echo "------------------------------------------------------------"
curl -s -X POST "${BASE_URL}/login" \
  -H "Content-Type: application/json" \
  -H "Authorization: ${AUTH_TOKEN}" \
  -H "X-Api-Key: ${API_KEY}" \
  -H "X-Custom-Auth: ${CUSTOM_AUTH}" \
  -b "session_id=${SESSION_ID}" \
  -d '{
    "username": "alice",
    "password": "MySQLP@ssw0rd!Secret",
    "token": "tok_mysql_aBcDeFgHiJkLmNoPqRsTuVwXyZ9876543"
  }' | pretty

echo ""

# ─── GET /users ──────────────────────────────────────────────────────────────
echo "[2] GET /users — secrets in headers + URL query params"
echo "------------------------------------------------------------"
curl -s -X GET \
  "${BASE_URL}/users?api_key=${API_KEY}&session_id=${SESSION_ID}" \
  -H "Authorization: ${AUTH_TOKEN}" \
  -H "X-Api-Key: ${API_KEY}" \
  -H "X-Custom-Auth: ${CUSTOM_AUTH}" | pretty

echo ""
echo "Done."

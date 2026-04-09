#!/usr/bin/env bash
# test.sh — Integration tests for http-auth-app
# Intentionally includes hardcoded secrets for secret detection validation.

set -euo pipefail

BASE_URL="http://localhost:8080"

# Pretty-print helper: use jq if available, else raw output
pretty() {
  if command -v jq &>/dev/null; then
    jq .
  else
    cat
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Shared secret values
# All values below are intentional detection targets.
# ─────────────────────────────────────────────────────────────────────────────

# SECRET: JWT token (HS256, realistic format)
JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsIm5hbWUiOiJKb2huIERvZSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDg2NDAwfQ.4Gdnl5BPBqAXbKFwmGp9V8fLqcW2vRjYkZo3nTsE1HM"

# SECRET: API key (sk-live- prefix, realistic format)
API_KEY="sk-live-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd"

# SECRET: Session ID used in Cookie header and query param
SESSION_ID="sess_abc123XYZprod9876"

# SECRET: OAuth2 client secret
CLIENT_SECRET="cs_prod_XyZ9876aBcDeFgHiJkLmNoPqRsTuV54321"

# SECRET: Short-lived token passed in request body
BODY_TOKEN="tok_live_9aB3cD7eF2gH5iJ1kL"

# SECRET: Custom auth header value
CUSTOM_AUTH="custom-auth-v1:sig_XkP92mNzQrLwVbTyUoD4sA"

# ─────────────────────────────────────────────────────────────────────────────
# 1. POST /login
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  POST /login"
echo "════════════════════════════════════════"
echo ""

# Secrets in this request:
#   Headers : Authorization (JWT), X-Api-Key, Cookie (session_id), X-Custom-Auth
#   Body    : password, client_secret, token

curl --silent --show-error \
  --request POST \
  --url "${BASE_URL}/login" \
  --header "Content-Type: application/json" \
  --header "Authorization: Bearer ${JWT_TOKEN}" \
  --header "X-Api-Key: ${API_KEY}" \
  --header "Cookie: session_id=${SESSION_ID}" \
  --header "X-Custom-Auth: ${CUSTOM_AUTH}" \
  --data @- <<EOF | pretty
{
  "username":      "john.doe",
  "password":      "s3cr3tP@ssw0rd!",
  "client_secret": "${CLIENT_SECRET}",
  "token":         "${BODY_TOKEN}"
}
EOF

# ─────────────────────────────────────────────────────────────────────────────
# 2. GET /profile
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  GET /profile"
echo "════════════════════════════════════════"
echo ""

# Secrets in this request:
#   Query params : api_key (API key), session_id
#   Headers      : Authorization (JWT), X-Api-Key

curl --silent --show-error \
  --request GET \
  --url "${BASE_URL}/profile?api_key=${API_KEY}&session_id=${SESSION_ID}" \
  --header "Authorization: Bearer ${JWT_TOKEN}" \
  --header "X-Api-Key: ${API_KEY}" \
  | pretty

echo ""

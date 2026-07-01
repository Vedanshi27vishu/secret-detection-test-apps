#!/usr/bin/env bash
BASE="http://172.19.0.2:30081"

JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsIm5hbWUiOiJKb2huIERvZSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDg2NDAwfQ.4Gdnl5BPBqAXbKFwmGp9V8fLqcW2vRjYkZo3nTsE1HM"
API_KEY="sk-live-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd"
SESSION_ID="sess_abc123XYZprod9876"
CLIENT_SECRET="cs_prod_XyZ9876aBcDeFgHiJkLmNoPqRsTuV54321"
BODY_TOKEN="tok_live_9aB3cD7eF2gH5iJ1kL"
CUSTOM_AUTH="custom-auth-v1:sig_XkP92mNzQrLwVbTyUoD4sA"

curl -s -X POST "${BASE}/login" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "X-Api-Key: ${API_KEY}" \
  -H "Cookie: session_id=${SESSION_ID}" \
  -H "X-Custom-Auth: ${CUSTOM_AUTH}" \
  -d '{"username":"john.doe","password":"s3cr3tP@ssw0rd!","client_secret":"'"${CLIENT_SECRET}"'","token":"'"${BODY_TOKEN}"'"}'
echo "  ✓ POST /login"

curl -s "${BASE}/profile?api_key=${API_KEY}&session_id=${SESSION_ID}" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "X-Api-Key: ${API_KEY}"
echo "  ✓ GET /profile"

echo "✅ http-auth-app traffic done"

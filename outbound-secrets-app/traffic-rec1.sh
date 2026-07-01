#!/usr/bin/env bash
# Recording 1 — 7 unique testcases
BASE="http://172.19.0.2:30082"
CLIENT_API_KEY="sk_live_keploy_client_api_key_SECRET_001"
SESSION_TOKEN="sess_tok_keploy_inbound_session_ABCDEF0123"
ACCESS_TOKEN="acc_tok_stripe_keploy_ABCDEF0123456789"
REFUND_TOKEN="rf_tok_keploy_refund_SECRET_REF001"
KYC_AUTH_TOKEN="kyc_auth_keploy_SECRET_TOKEN_KYC002"

echo "🚀 Recording 1 — sending 7 unique requests..."

curl -sf "${BASE}/api/health" > /dev/null; echo "  ✓ 1/7  GET  /api/health"

curl -sf "${BASE}/api/balance?user_id=usr_1" \
  -H "X-Session-Token: ${SESSION_TOKEN}" > /dev/null
echo "  ✓ 2/7  GET  /api/balance"

curl -sf "${BASE}/api/statement?user_id=usr_1&months=1" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -H "X-Session-Token: ${SESSION_TOKEN}" > /dev/null
echo "  ✓ 3/7  GET  /api/statement"

curl -sf -X POST "${BASE}/api/transfer" \
  -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -H "X-Session-Token: ${SESSION_TOKEN}" \
  -d "{\"access_token\":\"${ACCESS_TOKEN}\",\"amount\":75.5,\"currency\":\"USD\",\"user_id\":\"usr_1\",\"xray_1\":\"cattify\"}" > /dev/null
echo "  ✓ 4/7  POST /api/transfer (75.5)"

curl -sf -X POST "${BASE}/api/refund" \
  -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -d "{\"amount\":20,\"charge_id\":\"ch_1\",\"reason\":\"duplicate\",\"refund_token\":\"${REFUND_TOKEN}\",\"user_id\":\"usr_1\"}" > /dev/null
echo "  ✓ 5/7  POST /api/refund (ch_1)"

curl -sf -X POST "${BASE}/api/kyc/verify" \
  -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -d "{\"doc_number\":\"PASS001\",\"doc_type\":\"passport\",\"kyc_auth_token\":\"${KYC_AUTH_TOKEN}\",\"user_id\":\"usr_1\"}" > /dev/null
echo "  ✓ 6/7  POST /api/kyc/verify"

curl -sf -X POST "${BASE}/api/fraud/check" \
  -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -H "X-Session-Token: ${SESSION_TOKEN}" \
  -d "{\"amount\":500,\"ip_address\":\"10.0.0.1\",\"user_id\":\"usr_1\"}" > /dev/null
echo "  ✓ 7/7  POST /api/fraud/check"

echo ""
echo "✅ Recording 1 done — stop recording in UI now."

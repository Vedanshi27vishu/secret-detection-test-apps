#!/usr/bin/env bash

BASE="http://172.19.0.2:30082"

CLIENT_API_KEY="sk_live_keploy_client_api_key_SECRET_001"
SESSION_TOKEN="sess_tok_keploy_inbound_session_ABCDEF0123"
WEBHOOK_SIG="whsec_keploy_webhook_signing_secret_XYZ789"
ACCESS_TOKEN="acc_tok_stripe_keploy_ABCDEF0123456789"
REFUND_TOKEN="rf_tok_keploy_refund_SECRET_REF001"
KYC_AUTH_TOKEN="kyc_auth_keploy_SECRET_TOKEN_KYC002"
PAYOUT_TOKEN="pay_tok_keploy_payout_SECRET_PAY003"
SIGNING_SECRET="signing_secret_keploy_webhook_SIGN004"
ANALYTICS_TOKEN="analytics_tok_keploy_SECRET_ANL005"

# ── send traffic ──────────────────────────────────────────────────────────────
echo "🚀 Sending traffic..."

curl -sf "${BASE}/api/health" 2>/dev/null; true
echo "  ✓ GET /api/health"

curl -sf "${BASE}/api/balance?user_id=usr_1" \
  -H "X-Session-Token: ${SESSION_TOKEN}" 2>/dev/null; true
echo "  ✓ GET /api/balance"

curl -sf "${BASE}/api/statement?user_id=usr_1&months=1" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -H "X-Session-Token: ${SESSION_TOKEN}" 2>/dev/null; true
echo "  ✓ GET /api/statement"

for amount in 75.5 150.0 200.0; do
  curl -sf -X POST "${BASE}/api/transfer" \
    -H "Content-Type: application/json" \
    -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
    -H "X-Session-Token: ${SESSION_TOKEN}" \
    -d "{\"access_token\":\"${ACCESS_TOKEN}\",\"amount\":${amount},\"currency\":\"USD\",\"user_id\":\"usr_1\",\"xray_1\":\"cattify\"}" 2>/dev/null; true
  echo "  ✓ POST /api/transfer (${amount})"
done

for i in 1 2 3; do
  curl -sf -X POST "${BASE}/api/refund" \
    -H "Content-Type: application/json" \
    -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
    -d "{\"amount\":20,\"charge_id\":\"ch_${i}\",\"reason\":\"duplicate\",\"refund_token\":\"${REFUND_TOKEN}\",\"user_id\":\"usr_1\"}" 2>/dev/null; true
  echo "  ✓ POST /api/refund (ch_${i})"
done

curl -sf -X POST "${BASE}/api/kyc/verify" \
  -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -d "{\"doc_number\":\"PASS001\",\"doc_type\":\"passport\",\"kyc_auth_token\":\"${KYC_AUTH_TOKEN}\",\"user_id\":\"usr_1\"}" 2>/dev/null; true
echo "  ✓ POST /api/kyc/verify"

curl -sf -X POST "${BASE}/api/fraud/check" \
  -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -H "X-Session-Token: ${SESSION_TOKEN}" \
  -d "{\"amount\":500,\"ip_address\":\"10.0.0.1\",\"user_id\":\"usr_1\"}" 2>/dev/null; true
echo "  ✓ POST /api/fraud/check"

curl -sf -X POST "${BASE}/api/payout" \
  -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -d "{\"amount\":250,\"bank_code\":\"HDFC_001\",\"currency\":\"USD\",\"payout_token\":\"${PAYOUT_TOKEN}\",\"user_id\":\"usr_1\"}" 2>/dev/null; true
echo "  ✓ POST /api/payout"

for i in 1 2 3; do
  curl -sf -X POST "${BASE}/api/webhook" \
    -H "Content-Type: application/json" \
    -H "X-Webhook-Signature: ${WEBHOOK_SIG}" \
    -d "{\"event\":\"payment.completed\",\"payload\":\"payload_${i}\",\"signing_secret\":\"${SIGNING_SECRET}\"}" 2>/dev/null; true
  echo "  ✓ POST /api/webhook (${i})"
done

curl -sf -X POST "${BASE}/api/analytics/event" \
  -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -d "{\"analytics_token\":\"${ANALYTICS_TOKEN}\",\"event_name\":\"purchase\",\"properties\":{\"item\":\"prod_1\"},\"user_id\":\"usr_1\"}" 2>/dev/null; true
echo "  ✓ POST /api/analytics/event"

echo ""
echo "✅ Done! Check frontend for recorded test cases."

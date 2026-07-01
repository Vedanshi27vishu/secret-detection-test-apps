#!/usr/bin/env bash
# Recording 2 — 7 requests: 2 SAME as rec1 + 5 NEW
# Smart testset result: 7 (rec1) + 5 (new) = 12 unique
BASE="http://172.19.0.2:30082"
CLIENT_API_KEY="sk_live_keploy_client_api_key_SECRET_001"
SESSION_TOKEN="sess_tok_keploy_inbound_session_ABCDEF0123"
ACCESS_TOKEN="acc_tok_stripe_keploy_ABCDEF0123456789"
REFUND_TOKEN="rf_tok_keploy_refund_SECRET_REF001"
PAYOUT_TOKEN="pay_tok_keploy_payout_SECRET_PAY003"
WEBHOOK_SIG="whsec_keploy_webhook_signing_secret_XYZ789"
SIGNING_SECRET="signing_secret_keploy_webhook_SIGN004"
ANALYTICS_TOKEN="analytics_tok_keploy_SECRET_ANL005"

echo "🚀 Recording 2 — 2 same + 5 new..."

# ── SAME as rec1 (2) ─────────────────────────────────────────────────────────
curl -sf "${BASE}/api/health" > /dev/null; echo "  ♻️  1/7  GET  /api/health          (SAME)"

curl -sf "${BASE}/api/balance?user_id=usr_1" \
  -H "X-Session-Token: ${SESSION_TOKEN}" > /dev/null
echo "  ♻️  2/7  GET  /api/balance          (SAME)"

# ── NEW (5) ──────────────────────────────────────────────────────────────────
curl -sf -X POST "${BASE}/api/transfer" \
  -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -H "X-Session-Token: ${SESSION_TOKEN}" \
  -d "{\"access_token\":\"${ACCESS_TOKEN}\",\"amount\":150.0,\"currency\":\"USD\",\"user_id\":\"usr_1\",\"xray_1\":\"cattify\"}" > /dev/null
echo "  ✨ 3/7  POST /api/transfer (150.0)   (NEW)"

curl -sf -X POST "${BASE}/api/refund" \
  -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -d "{\"amount\":20,\"charge_id\":\"ch_2\",\"reason\":\"duplicate\",\"refund_token\":\"${REFUND_TOKEN}\",\"user_id\":\"usr_1\"}" > /dev/null
echo "  ✨ 4/7  POST /api/refund (ch_2)      (NEW)"

curl -sf -X POST "${BASE}/api/payout" \
  -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -d "{\"amount\":250,\"bank_code\":\"HDFC_001\",\"currency\":\"USD\",\"payout_token\":\"${PAYOUT_TOKEN}\",\"user_id\":\"usr_1\"}" > /dev/null
echo "  ✨ 5/7  POST /api/payout             (NEW)"

curl -sf -X POST "${BASE}/api/webhook" \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Signature: ${WEBHOOK_SIG}" \
  -d "{\"event\":\"payment.completed\",\"payload\":\"payload_1\",\"signing_secret\":\"${SIGNING_SECRET}\"}" > /dev/null
echo "  ✨ 6/7  POST /api/webhook            (NEW)"

curl -sf -X POST "${BASE}/api/analytics/event" \
  -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -d "{\"analytics_token\":\"${ANALYTICS_TOKEN}\",\"event_name\":\"purchase\",\"properties\":{\"item\":\"prod_1\"},\"user_id\":\"usr_1\"}" > /dev/null
echo "  ✨ 7/7  POST /api/analytics/event   (NEW)"

echo ""
echo "✅ Recording 2 done — stop recording in UI now."
echo "   Smart testset should show 12 (7 from rec1 + 5 new)."

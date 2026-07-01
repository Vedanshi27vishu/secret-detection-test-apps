#!/usr/bin/env bash
# Traffic that produces OUTBOUND MOCKS whose secrets the DEFAULT detector encrypts.
#
# Only hits the endpoints whose gateway calls carry an Authorization header
# (always encrypted by exact name) and/or high-entropy *_secret / *_token /
# *_key response fields (entropy >= 4.0 -> ENC: at record time).
#
# Deliberately SKIPS /api/balance, /api/statement, /api/kyc, /api/profile:
# the gateway returns LOW-entropy readable fakes there (e.g.
# "stmt_auth_token_keploy_st4t3m3nt_789" = 3.91) that the default detector
# misses. To force those too, set CustomValuePatterns = keploy in the UI.
#
# Target = cluster NodePort for outbound-secrets-app (UI recording flow).
set -u
BASE="http://172.19.0.2:30082"

CLIENT_API_KEY="sk_live_keploy_client_api_key_SECRET_001"
SESSION_TOKEN="sess_tok_keploy_inbound_session_ABCDEF0123"
WEBHOOK_SIG="whsec_keploy_webhook_signing_secret_XYZ789"
ACCESS_TOKEN="acc_tok_stripe_keploy_ABCDEF0123456789"
REFUND_TOKEN="rf_tok_keploy_refund_SECRET_REF001"
PAYOUT_TOKEN="pay_tok_keploy_payout_SECRET_PAY003"
SIGNING_SECRET="signing_secret_keploy_webhook_SIGN004"
ANALYTICS_TOKEN="analytics_tok_keploy_SECRET_ANL005"

echo "🚀 Sending traffic that yields ENCRYPTED mock secrets ..."

# /api/transfer -> mock POST /charge  : Authorization + received_key + txn_ref_secret => ENC
for amount in 75.5 150.0; do
  curl -sf -X POST "${BASE}/api/transfer" -H "Content-Type: application/json" \
    -H "X-Client-Api-Key: ${CLIENT_API_KEY}" -H "X-Session-Token: ${SESSION_TOKEN}" \
    -d "{\"access_token\":\"${ACCESS_TOKEN}\",\"amount\":${amount},\"currency\":\"USD\",\"user_id\":\"usr_1\"}" >/dev/null 2>&1 || true
  echo "  ✓ /api/transfer    -> /charge   (Authorization, received_key, txn_ref_secret)"
done

# /api/refund -> mock POST /refund + /notify : client_key + received_key + refund_ref_secret + notify_secret + received_secret => ENC
for i in 1 2; do
  curl -sf -X POST "${BASE}/api/refund" -H "Content-Type: application/json" \
    -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
    -d "{\"amount\":20,\"charge_id\":\"ch_${i}\",\"reason\":\"duplicate\",\"refund_token\":\"${REFUND_TOKEN}\",\"user_id\":\"usr_1\"}" >/dev/null 2>&1 || true
  echo "  ✓ /api/refund      -> /refund + /notify (client_key, received_key, refund_ref_secret, notify_secret)"
done

# /api/fraud/check -> mock POST /fraud + /notify : fraud_secret + received_token + notify_secret + received_secret => ENC
curl -sf -X POST "${BASE}/api/fraud/check" -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" -H "X-Session-Token: ${SESSION_TOKEN}" \
  -d "{\"amount\":500,\"ip_address\":\"10.0.0.1\",\"user_id\":\"usr_1\"}" >/dev/null 2>&1 || true
echo "  ✓ /api/fraud/check -> /fraud + /notify  (fraud_secret, received_token, notify_secret)"

# /api/payout -> mock POST /charge + /notify : Authorization + received_key + txn_ref_secret + notify_secret => ENC
curl -sf -X POST "${BASE}/api/payout" -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -d "{\"amount\":250,\"bank_code\":\"HDFC_001\",\"currency\":\"USD\",\"payout_token\":\"${PAYOUT_TOKEN}\",\"user_id\":\"usr_1\"}" >/dev/null 2>&1 || true
echo "  ✓ /api/payout      -> /charge + /notify  (Authorization, received_key, txn_ref_secret)"

# /api/webhook -> mock POST /notify : sig + notify_secret + received_secret => ENC
for i in 1 2; do
  curl -sf -X POST "${BASE}/api/webhook" -H "Content-Type: application/json" \
    -H "X-Webhook-Signature: ${WEBHOOK_SIG}" \
    -d "{\"event\":\"payment.completed\",\"payload\":\"payload_${i}\",\"signing_secret\":\"${SIGNING_SECRET}\"}" >/dev/null 2>&1 || true
  echo "  ✓ /api/webhook     -> /notify   (sig, notify_secret, received_secret)"
done

# /api/analytics/event -> mock POST /analytics : analytics_secret + received_key => ENC
curl -sf -X POST "${BASE}/api/analytics/event" -H "Content-Type: application/json" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" \
  -d "{\"analytics_token\":\"${ANALYTICS_TOKEN}\",\"event_name\":\"purchase\",\"properties\":{\"item\":\"prod_1\"},\"user_id\":\"usr_1\"}" >/dev/null 2>&1 || true
echo "  ✓ /api/analytics   -> /analytics (analytics_secret, received_key)"

echo ""
echo "✅ Done. Every mock above carries 2-5 ENC: secret fields (request Authorization + response *_secret)."
echo "   Open these mocks in the UI; you should see ENC:k-... on every secret field."

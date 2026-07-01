#!/usr/bin/env bash
# traffic-outbound-smart.sh
# -----------------------------------------------------------------------------
# Traffic that forms SMART TEST CASES which each make an OUTBOUND dependency
# call (so every resulting smart case references at least one consumed mock).
#
# Only hits endpoints whose handler calls the downstream gateway — so unlike
# /api/health or /api/balance (no outbound), each request here records an
# inbound test case PLUS its outbound mock(s):
#
#   /api/transfer        -> POST /charge
#   /api/payout          -> POST /charge  + POST /notify
#   /api/refund          -> POST /refund  + POST /notify
#   /api/fraud/check     -> POST /fraud   + POST /notify
#   /api/webhook         -> POST /notify
#   /api/analytics/event -> POST /analytics
#
# 6 distinct (method, endpoint) shapes => 6 unique smart test cases, each with
# an outbound mock. Re-running is idempotent: same schema_ref => REPLACE in the
# smart set, not a new case.
#
# Flow: start recording in the UI -> run this -> stop recording. The auto-replay
# tick then folds these into the smart set (UpsertCase), and each recording's
# DEK lands in the STS manifest.
# -----------------------------------------------------------------------------
set -u

# Cluster NodePort for outbound-secrets-app. Override for your env:
#   BASE=http://localhost:8080 ./traffic-outbound-smart.sh   (needs a port-forward)
BASE="${BASE:-http://172.19.0.2:30082}"

# send METHOD PATH LABEL [JSON] [HDR...] — prints the REAL HTTP status and fails
# loud (no silent || true). Anything other than 2xx means the app never saw it.
send() {
  local method="$1" path="$2" label="$3" data="${4:-}"; shift 4 2>/dev/null || shift $#
  local args=(-s -o /dev/null -w '%{http_code}' -X "$method" "${BASE}${path}")
  [ -n "$data" ] && args+=(-H "Content-Type: application/json" -d "$data")
  args+=("$@")
  local code; code=$(curl "${args[@]}" 2>/dev/null || echo "000")
  if [ "${code:0:1}" = "2" ]; then
    echo "  ✓ ${label}  [HTTP ${code}]"
  else
    echo "  ✗ ${label}  [HTTP ${code}]  <- NOT recorded"
    return 1
  fi
}

# Reachability gate: if /api/health isn't 2xx, nothing below will record either.
echo "🔎 Probing ${BASE}/api/health ..."
hc=$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/api/health" 2>/dev/null || echo "000")
if [ "${hc:0:1}" != "2" ]; then
  echo "❌ ${BASE}/api/health -> HTTP ${hc}. The app is not reachable at this BASE."
  echo "   • NodePort path:    BASE=http://172.19.0.2:30082 ./traffic-outbound-smart.sh"
  echo "   • port-forward path: kubectl -n test-apps port-forward svc/outbound-secrets-app 8080:8080 &"
  echo "                        BASE=http://localhost:8080 ./traffic-outbound-smart.sh"
  echo "   Also confirm recording is ACTIVE in the UI before sending traffic."
  exit 1
fi
echo "✅ health OK [HTTP ${hc}]"

CLIENT_API_KEY="sk_live_keploy_client_api_key_SECRET_001"
SESSION_TOKEN="sess_tok_keploy_inbound_session_ABCDEF0123"
ACCESS_TOKEN="acc_tok_stripe_keploy_ABCDEF0123456789"
REFUND_TOKEN="rf_tok_keploy_refund_SECRET_REF001"
PAYOUT_TOKEN="pay_tok_keploy_payout_SECRET_PAY003"
WEBHOOK_SIG="whsec_keploy_webhook_signing_secret_XYZ789"
SIGNING_SECRET="signing_secret_keploy_webhook_SIGN004"
ANALYTICS_TOKEN="analytics_tok_keploy_SECRET_ANL005"

echo "🚀 Sending OUTBOUND-call traffic to ${BASE} ..."
ok=0
send POST /api/transfer        "1/6  POST /api/transfer        -> /charge" \
  "{\"access_token\":\"${ACCESS_TOKEN}\",\"amount\":75.5,\"currency\":\"USD\",\"user_id\":\"usr_1\"}" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" -H "X-Session-Token: ${SESSION_TOKEN}" && ok=$((ok+1))

send POST /api/payout          "2/6  POST /api/payout          -> /charge + /notify" \
  "{\"amount\":250,\"bank_code\":\"HDFC_001\",\"currency\":\"USD\",\"payout_token\":\"${PAYOUT_TOKEN}\",\"user_id\":\"usr_1\"}" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" && ok=$((ok+1))

send POST /api/refund          "3/6  POST /api/refund          -> /refund + /notify" \
  "{\"amount\":20,\"charge_id\":\"ch_1\",\"reason\":\"duplicate\",\"refund_token\":\"${REFUND_TOKEN}\",\"user_id\":\"usr_1\"}" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" && ok=$((ok+1))

send POST /api/fraud/check     "4/6  POST /api/fraud/check     -> /fraud + /notify" \
  "{\"amount\":500,\"ip_address\":\"10.0.0.1\",\"user_id\":\"usr_1\"}" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" -H "X-Session-Token: ${SESSION_TOKEN}" && ok=$((ok+1))

send POST /api/webhook         "5/6  POST /api/webhook         -> /notify" \
  "{\"event\":\"payment.completed\",\"payload\":\"payload_1\",\"signing_secret\":\"${SIGNING_SECRET}\"}" \
  -H "X-Webhook-Signature: ${WEBHOOK_SIG}" && ok=$((ok+1))

send POST /api/analytics/event "6/6  POST /api/analytics/event -> /analytics" \
  "{\"analytics_token\":\"${ANALYTICS_TOKEN}\",\"event_name\":\"purchase\",\"properties\":{\"item\":\"prod_1\"},\"user_id\":\"usr_1\"}" \
  -H "X-Client-Api-Key: ${CLIENT_API_KEY}" && ok=$((ok+1))

echo ""
echo "✅ ${ok}/6 requests returned 2xx (the app actually saw them)."
echo "   Stop recording in the UI; the auto-replay tick forms the smart set."
[ "$ok" -eq 6 ] || { echo "⚠️  only ${ok}/6 reached the app — fix the failures above; nothing will record otherwise."; exit 1; }

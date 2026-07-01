#!/usr/bin/env bash
# traffic-more-cases.sh
# Mints NEW smart-set cases by producing distinct (method, path, STATUS) tuples.
# The smart-set dedups by schema_ref = (method, endpoint, status), so re-hitting
# the existing 200 endpoints REPLACES; these error-status variants are NEW cases.
# Run this DURING a recording (UI Record on, app pod 2/2), then Stop.
set -u
BASE="${BASE:-http://172.19.0.2:30082}"

c(){ local label="$1"; shift; printf "  %-46s -> HTTP %s\n" "$label" "$(curl -s -o /dev/null -w '%{http_code}' "$@")"; }

echo "🚀 Sending error-variant traffic for NEW smart cases ..."

# ── 400 validation errors (distinct from the 200 case on same path) ──────────
c "POST /api/transfer (no auth)       [400]" -X POST "$BASE/api/transfer" \
  -H 'Content-Type: application/json' -d '{"amount":10,"currency":"USD","user_id":"usr_1"}'
c "POST /api/kyc/verify (bad json)    [400]" -X POST "$BASE/api/kyc/verify" \
  -H 'Content-Type: application/json' -d 'not-json'

# ── 405 wrong-method on POST-only routes (each path+405 is a new schema_ref) ──
for p in transfer refund payout webhook fraud/check kyc/verify analytics/event; do
  c "GET  /api/$p (wrong method)        [405]" "$BASE/api/$p"
done

# ── 404 unknown paths ────────────────────────────────────────────────────────
c "GET  /api/unknown                  [404]" "$BASE/api/unknown"
c "GET  /api/v2/ping                   [404]" "$BASE/api/v2/ping"

echo ""
echo "✅ Done. ~11 new distinct schema_refs → new smart cases (different statuses)."
echo "   Stop recording in the UI; auto-replay folds them into the smart set."

#!/usr/bin/env bash
#
# traffic-primitives.sh — sends ONE request whose JSON body contains every
# primitive type as a SECRET field, so you can verify the typed-encryption
# format ENC:<datatype>:<keyID>:<base64> per type after recording.
#
# Record config to use in the UI (Encrypt Secrets ON):
#   Custom Body Keys      = prim_number_secret,prim_bool_secret,prim_string_secret,prim_null_secret
#   Custom Value Patterns = keploy
#
# Expected stored result (raw, unmasked):
#   prim_string_secret  -> ENC:string:k-...:<b64>
#   prim_number_secret  -> ENC:number:k-...:<b64>
#   prim_bool_secret    -> ENC:boolean:k-...:<b64>
#   prim_null_secret    -> null            (NOT encrypted — a null carries no secret;
#                                            the encrypt walk has no case for nil)
#   prim_plain_number   -> 99.5            (control: not a secret key -> plaintext)
#   prim_plain_string   -> "USD"           (control)
#
# The UI shows the encrypted ones masked as ENC:<b64>; the type+keyID are only
# visible in the raw API payload (DevTools -> Network) or object storage.

BASE="${BASE:-http://172.19.0.2:30082}"   # cluster NodePort used for recording

echo "🚀 Sending all-primitive-types payload to ${BASE}/api/transfer ..."

curl -sf -X POST "${BASE}/api/transfer" \
  -H "Content-Type: application/json" \
  -d '{
        "prim_string_secret": "sk_live_keploy_PRIM_STRING_001",
        "prim_number_secret": 424242,
        "prim_bool_secret": true,
        "prim_null_secret": null,
        "prim_plain_number": 99.5,
        "prim_plain_string": "USD",
        "user_id": "usr_primtest"
      }' 2>/dev/null
true
echo ""
echo "  ✓ POST /api/transfer (all primitive secrets: string / number / boolean / null)"
echo "✅ Done. Open this test case in the UI, then DevTools → Network → the test-case"
echo "   fetch response to see the raw ENC:<datatype>:<keyID>:<base64> per field."

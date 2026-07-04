#!/usr/bin/env bash
# Fully headless OpenID4VP presentation to verifier.eudiw.dev.
#
# 1) Issues a real PID (pre-authorized flow) and persists its holder key.
# 2) Drives verifier.eudiw.dev to request PID (dc+sd-jwt, family_name+given_name) over OpenID4VP.
# 3) Presents the real PID: resolves the request, DCQL-matches, builds the vp_token + KB-JWT,
#    encrypts it (direct_post.jwt / JWE) and submits to the verifier's response_uri.
#
#   cd tools/headless-interop && npm install && ./run-vp.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KOTLIN="$HERE/../../kotlin"
TMP="${TMPDIR:-/tmp}"

echo "== 1/4 issue a real PID (pre-authorized) + persist holder key"
node "$HERE/drive.js" preauth "$TMP/eudi-preauth-offer.txt" "$TMP/eudi-preauth-txcode.txt"
( cd "$KOTLIN" && EUDI_LIVE=preauth EUDI_OFFER="$(cat "$TMP/eudi-preauth-offer.txt")" EUDI_TXCODE="$(cat "$TMP/eudi-preauth-txcode.txt")" \
    ./gradlew :openid4vci:test --tests '*LiveIssuanceTest.preAuthIssue' --console=plain --rerun-tasks 2>&1 \
    | grep -E 'credentials received|credential . holder key saved|PASSED|FAILED' )

echo "== 2/4 drive verifier.eudiw.dev -> OpenID4VP request URL (headless Chrome)"
node "$HERE/drive.js" verifier "$TMP/eudi-vp-request.txt"
echo "request: $(cut -c1-90 "$TMP/eudi-vp-request.txt")..."

echo "== 3/4 present the PID to the verifier (resolve -> DCQL match -> vp_token/JWE -> submit)"
( cd "$KOTLIN" && EUDI_VP=1 EUDI_VP_REQUEST="$(cat "$TMP/eudi-vp-request.txt")" \
    ./gradlew :trust:test --tests '*LiveTrustE2eTest.presentWithTrust' --console=plain --rerun-tasks 2>&1 \
    | grep -E 'verifier:|response_mode|dcql queries|satisfiable|candidate|PRESENTED TO TRUSTED|redirect_uri|PASSED|FAILED|VpException|Exception' )

echo "== 4/4 done"

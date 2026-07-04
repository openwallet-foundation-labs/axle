#!/usr/bin/env bash
# Fully headless OpenID4VP presentation of a real **mdoc** PID to verifier.eudiw.dev.
#
# 1) Issues a real mdoc PID (ISO 18013-5, pre-authorized flow) and persists its device key.
# 2) Drives verifier.eudiw.dev to request PID (mso_mdoc, family_name+given_name) over OpenID4VP.
# 3) Presents it: resolves the request, DCQL-matches, builds a DeviceResponse (selective
#    disclosure + DeviceSigned over the OpenID4VP-handover SessionTranscript), encrypts it
#    (direct_post.jwt / JWE) and submits to the verifier's response_uri.
#
#   cd tools/headless-interop && npm install && ./run-vp-mdoc.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KOTLIN="$HERE/../../kotlin"
TMP="${TMPDIR:-/tmp}"
MDOC_CONFIG="eu.europa.ec.eudi.pid_mdoc"

echo "== 1/4 issue a real mdoc PID (pre-authorized) + persist device key"
node "$HERE/drive.js" preauth "$TMP/eudi-mdoc-offer.txt" "$TMP/eudi-mdoc-txcode.txt" --config "$MDOC_CONFIG"
( cd "$KOTLIN" && EUDI_LIVE=preauth EUDI_OFFER="$(cat "$TMP/eudi-mdoc-offer.txt")" EUDI_TXCODE="$(cat "$TMP/eudi-mdoc-txcode.txt")" \
    ./gradlew :openid4vci:test --tests '*LiveIssuanceTest.preAuthIssue' --console=plain --rerun-tasks 2>&1 \
    | grep -E 'pre-auth offer|credentials received|holder key saved|PASSED|FAILED' )

echo "== 2/4 drive verifier.eudiw.dev -> OpenID4VP mso_mdoc request URL (headless Chrome)"
node "$HERE/drive.js" verifier "$TMP/eudi-mdoc-vp-request.txt" --format mso_mdoc
echo "request: $(cut -c1-90 "$TMP/eudi-mdoc-vp-request.txt")..."

echo "== 3/4 present the mdoc (resolve -> DCQL match -> DeviceResponse/JWE -> submit)"
( cd "$KOTLIN" && EUDI_MDOC=present EUDI_VP_REQUEST="$(cat "$TMP/eudi-mdoc-vp-request.txt")" \
    ./gradlew :trust:test --tests '*LiveTrustE2eTest.presentMdocWithTrust' --console=plain --rerun-tasks 2>&1 \
    | grep -E 'verifier:|candidate|disclose|PRESENTED TO TRUSTED|redirect_uri|PASSED|FAILED|Exception' )

echo "== 4/4 done"

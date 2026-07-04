#!/usr/bin/env bash
# Headless mdoc PID issuance via the pre-authorized_code grant, then verify it against the
# real EUDI IACA (X.509 chain + issuerAuth + digests).
#
#   cd tools/headless-interop && npm install && ./run-preauth-mdoc.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KOTLIN="$HERE/../../kotlin"
TMP="${TMPDIR:-/tmp}"
OFFER="$TMP/eudi-mdoc-offer.txt"
TXCODE="$TMP/eudi-mdoc-txcode.txt"

echo "== 1/3 portal (pre-auth mode) -> mdoc offer + tx_code (headless Chrome)"
node "$HERE/drive.js" preauth "$OFFER" "$TXCODE" --config eu.europa.ec.eudi.pid_mdoc
echo "tx_code: $(cat "$TXCODE")"

echo "== 2/3 redeem pre-authorized_code at token endpoint (Kotlin, no browser)"
( cd "$KOTLIN" && EUDI_LIVE=preauth EUDI_OFFER="$(cat "$OFFER")" EUDI_TXCODE="$(cat "$TXCODE")" \
    ./gradlew :openid4vci:test --tests '*LiveIssuanceTest.preAuthIssue' --console=plain --rerun-tasks 2>&1 \
    | grep -E 'pre-auth offer|credentials received|holder key saved|PASSED|FAILED' )

echo "== 3/3 verify the captured mdoc against the EUDI IACA (Kotlin)"
( cd "$KOTLIN" && EUDI_MDOC=verify ./gradlew :trust:test --tests '*LiveTrustE2eTest.verifyRealMdocWithChain' --console=plain --rerun-tasks 2>&1 \
    | grep -E 'REAL mdoc PID VERIFIED|docType|/ |PASSED|FAILED' )

echo "== done. mdoc credential at $TMP/eudi-credential.txt"

#!/usr/bin/env bash
# Headless mdoc PID issuance via the **authorization code** grant (PAR -> FormEU auth -> token),
# then verify it against the real EUDI IACA.
#
#   cd tools/headless-interop && npm install && ./run-mdoc.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KOTLIN="$HERE/../../kotlin"
TMP="${TMPDIR:-/tmp}"
OFFER="$TMP/eudi-mdoc-offer.txt"
AUTHURL="$TMP/eudi-mdoc-authurl.txt"
MDOC_CONFIG="eu.europa.ec.eudi.pid_mdoc"

echo "== 1/5 portal -> mdoc credential offer (headless Chrome)"
node "$HERE/drive.js" offer "$OFFER" --config "$MDOC_CONFIG"

echo "== 2/5 PAR -> authorization URL (Kotlin)"
rm -f "$TMP/eudi-redirect.txt"
( cd "$KOTLIN" && EUDI_LIVE=prepare EUDI_CONFIG_ID="$MDOC_CONFIG" EUDI_OFFER="$(cat "$OFFER")" \
    ./gradlew :openid4vci:test --tests '*LiveIssuanceTest.step1_prepare' --console=plain --rerun-tasks 2>&1 \
    | grep -oE 'https://issuer.eudiw.dev/oidc/authorization[^ ]*' | head -1 ) > "$AUTHURL"
echo "authorization URL: $(cut -c1-80 "$AUTHURL")..."

echo "== 3/5 FormEU auth -> authorization code (headless Chrome)"
node "$HERE/drive.js" auth "$AUTHURL" "$TMP/eudi-redirect.txt"

echo "== 4/5 token + credential exchange (Kotlin)"
( cd "$KOTLIN" && EUDI_LIVE=finish EUDI_CONFIG_ID="$MDOC_CONFIG" \
    ./gradlew :openid4vci:test --tests '*LiveIssuanceTest.step2_finish' --console=plain --rerun-tasks 2>&1 \
    | grep -E 'credentials received|credential saved|PASSED|FAILED' )

echo "== 5/5 verify the captured mdoc against the EUDI IACA (Kotlin)"
( cd "$KOTLIN" && EUDI_MDOC=verify ./gradlew :trust:test --tests '*LiveTrustE2eTest.verifyRealMdocWithChain' --console=plain --rerun-tasks 2>&1 \
    | grep -E 'REAL mdoc PID VERIFIED|docType|PASSED|FAILED' )

echo "== done. mdoc credential at $TMP/eudi-credential.txt"

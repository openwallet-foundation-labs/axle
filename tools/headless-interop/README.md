# Headless live interop

Drives real issuance and presentation against the EUDI reference deployment
(`issuer.eudiw.dev`, `verifier.eudiw.dev`) with no human in the loop.

`drive.js` runs headless Chrome (puppeteer-core) for the two steps that need a browser — taking a
credential offer from the issuer portal, and filling the FormEU test-auth form for an authorization code.
Everything else is the Kotlin SDK doing the actual protocol.

```sh
npm install
./run.sh                # SD-JWT VC PID, authorization code grant
./run-preauth.sh        # SD-JWT VC PID, pre-authorized code grant
./run-mdoc.sh           # mdoc PID,      authorization code grant
./run-preauth-mdoc.sh   # mdoc PID,      pre-authorized code grant
./run-vp.sh             # present the captured SD-JWT VC to verifier.eudiw.dev
./run-vp-mdoc.sh        # present the captured mdoc
```

Each issuance runner ends by verifying the credential it captured against the real EUDI IACA, so a green
run means the credential chained, not just that a response came back. Credentials land in
`$TMPDIR/eudi-credential.txt`.

## The Key Attestation the runners send

The four issuance runners sign their own Key Attestation. That deserves an explanation, because the
obvious readings of it are both wrong.

Every `issuer.eudiw.dev` credential configuration declares `key_attestations_required`, asking for
`iso_18045_high` key storage and user authentication:

```json
"proof_types_supported": {
  "jwt":         { "key_attestations_required": { "key_storage": ["iso_18045_high"], … } },
  "attestation": { "key_attestations_required": { "key_storage": ["iso_18045_high"], … } }
}
```

**The issuer does not enforce any of that.** Measured against the live deployment on 2026-08-26:

| what the Credential Request carried | result |
| --- | --- |
| no attestation at all — a bare `jwt` proof | **200**, PID issued |
| attestation asserting `iso_18045_moderate` (below the level asked for) | **200**, PID issued |
| attestation with no `x5c` header | **500 Internal Server Error** |

So the level is not checked, the presence of an attestation is not checked, and the one thing that does
break is a JWT the issuer cannot parse a certificate out of — which it answers with a crash rather than a
clean `invalid_proof`. That last row is an issuer-side bug; the harness works around it by carrying a
self-signed certificate in `x5c`.

What blocks the harness, then, is our own conformance rather than the server: `Openid4VciClient` refuses
to send a proof when the metadata declares an attestation required and no source is configured, because
HAIP §4.5.1 makes that declaration binding on the Wallet. That stays as it is — one lenient server is no
reason to weaken the client — so the harness has to supply *something*.

It signs that something itself, on purpose. The demo wallet gets a real attestation from its Wallet
Provider (`POST /key-attestation`, an `x5c` to the WP CA, `iso_18045_high` once an Android-keystore chain
is verified), and the harness could call the same endpoint — it works. But then a Wallet Provider outage
would fail a run whose subject is the issuer, and a JVM run has no keystore chain to submit anyway, so it
would only ever earn `iso_18045_moderate`. A self-signed attestation keeps these runs dependent on
nothing but the EUDI deployment.

None of this holds for an issuer that actually validates key attestations. One that does will reject a
self-signed attestation, and a harness pointed at it needs a real Wallet Provider.

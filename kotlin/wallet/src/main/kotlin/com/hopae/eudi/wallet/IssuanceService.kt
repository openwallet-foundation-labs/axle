package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.mdoc.IssuerSigned
import com.hopae.eudi.wallet.sdjwt.Base64Url
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.SdJwt
import com.hopae.eudi.wallet.sdjwt.SdJwtHolder
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.CredentialPolicy
import com.hopae.eudi.wallet.spi.KeyInfo
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.Rng
import com.hopae.eudi.wallet.spi.SecureArea
import com.hopae.eudi.wallet.spi.WalletClock
import com.hopae.eudi.wallet.store.CredentialEnvelope
import com.hopae.eudi.wallet.store.CredentialInstance
import com.hopae.eudi.wallet.store.CredentialStore
import com.hopae.eudi.wallet.store.EnvelopeLifecycle
import com.hopae.eudi.wallet.vci.CredentialResponse
import com.hopae.eudi.wallet.vci.IssuanceKeys
import com.hopae.eudi.wallet.vci.IssuedCredential
import com.hopae.eudi.wallet.vci.Openid4VciClient
import com.hopae.eudi.wallet.vci.ProofKey
import com.hopae.eudi.wallet.vci.VciException
import kotlinx.coroutines.CoroutineScope

/** OpenID4VCI issuance (API-CONTRACT.md §6.1). Owns key creation, issuance, and persistence. */
class IssuanceService internal constructor(
    private val vci: Openid4VciClient,
    private val store: CredentialStore,
    private val secureArea: SecureArea,
    private val scope: CoroutineScope,
    private val rng: Rng,
    private val clock: WalletClock,
) {
    /** Step 1 of the 2-phase flow: resolve an offer deep link / QR / raw JSON. */
    suspend fun resolveOffer(offerUri: String): CredentialOffer =
        CredentialOffer(catchingVci { vci.resolveCredentialOffer(offerUri) })

    /** Starts an issuance session. Pre-authorized code flow (auth-code arrives in a later slice). */
    fun start(request: IssuanceRequest): IssuanceSession {
        val session = IssuanceSession(scope) {
            emit(IssuanceState.Processing)
            val (keys, proofKeys) = buildKeys(request)
            val response = catchingVci {
                vci.issueWithPreAuthorizedCode(request.offer.raw, request.configurationId, keys, request.txCode)
            }
            emit(IssuanceState.Completed(IssuanceResult(listOf(persist(response, proofKeys, request.policy)))))
        }
        session.launch()
        return session
    }

    /** One key per credential in the batch (HAIP one-time-use), plus a DPoP key. */
    private suspend fun buildKeys(request: IssuanceRequest): Pair<IssuanceKeys, List<KeyInfo>> {
        val spec = KeySpec(
            secureArea = secureArea.id, algorithm = request.keySpec.algorithm,
            userAuthentication = request.keySpec.userAuthentication, hardware = request.keySpec.hardware,
            attestationChallenge = request.keySpec.attestationChallenge,
        )
        val proofKeys = (1..request.policy.batchSize.coerceAtLeast(1)).map { secureArea.createKey(spec) }
        val dpopKey = secureArea.createKey(spec)
        fun signer(k: KeyInfo) = SecureAreaJwsSigner(secureArea, k.handle, k.algorithm)
        val keys = IssuanceKeys(
            signer(proofKeys[0]), proofKeys[0].publicKey,
            signer(dpopKey), dpopKey.publicKey,
            additionalProofKeys = proofKeys.drop(1).map { ProofKey(signer(it), it.publicKey) },
        )
        return keys to proofKeys
    }

    /** Maps the issued credential(s) to one envelope with N instances (one per proof key), and saves it. */
    private suspend fun persist(response: CredentialResponse, proofKeys: List<KeyInfo>, policy: CredentialPolicy): CredentialId {
        if (response.credentials.isEmpty()) throw WalletError.Issuance.CredentialRequestFailed("issuer returned no credentials")
        val format = decode(response.credentials.first()).first
        val instances = response.credentials.mapIndexed { i, credential ->
            CredentialInstance(proofKeys[i].handle, decode(credential).second)
        }
        val id = CredentialId("cred-" + Base64Url.encode(rng.nextBytes(12)))
        store.save(CredentialEnvelope(id, format, clock.now(), EnvelopeLifecycle.Issued(policy, instances)))
        return id
    }

    /** Determines the format + raw payload bytes for storage (SD-JWT compact string / mdoc IssuerSigned CBOR). */
    private fun decode(credential: IssuedCredential): Pair<CredentialFormat, ByteArray> = when (credential.format) {
        "mso_mdoc" -> {
            val bytes = Base64Url.decode(credential.credential)
            CredentialFormat.MsoMdoc(IssuerSigned.decode(bytes).parseMso().docType) to bytes
        }
        else -> {
            val vct = (SdJwtHolder.processedClaims(SdJwt.parse(credential.credential))["vct"] as? JsonValue.Str)?.value ?: ""
            CredentialFormat.SdJwtVc(vct) to credential.credential.encodeToByteArray()
        }
    }

    private suspend fun <T> catchingVci(block: suspend () -> T): T = try {
        block()
    } catch (e: VciException) {
        throw when (e) {
            is VciException.InvalidOffer -> WalletError.Issuance.InvalidOffer(e.message ?: "")
            is VciException.OAuthError -> WalletError.Issuance.AuthorizationFailed(e.oauthError, e.message ?: "")
            is VciException.IssuancePending -> WalletError.Issuance.DeferredNotReady()
            else -> WalletError.Issuance.CredentialRequestFailed(e.message ?: "", e)
        }
    }
}

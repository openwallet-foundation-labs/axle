package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.mdoc.MdocTestIssuer
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.SdJwtIssuer
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.CredentialPolicy
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SecureArea
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.StorageDriver
import com.hopae.eudi.wallet.spi.TransactionLog
import com.hopae.eudi.wallet.spi.TransactionLogEntry
import com.hopae.eudi.wallet.spi.TransactionStatus
import com.hopae.eudi.wallet.spi.TransactionType
import com.hopae.eudi.wallet.store.CredentialEnvelope
import com.hopae.eudi.wallet.store.CredentialInstance
import com.hopae.eudi.wallet.store.CredentialStore
import com.hopae.eudi.wallet.store.EnvelopeLifecycle
import com.hopae.eudi.wallet.testkit.InMemoryStorageDriver
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import com.hopae.eudi.wallet.vp.MockMdocVerifier
import com.hopae.eudi.wallet.vp.MockVerifier
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Phase C: OpenID4VP remote presentation through the facade session (resolve → consent → submit → audit). */
class WalletPresentationTest {

    private val now: Instant = Instant.parse("2026-06-01T00:00:00Z")

    private class RecordingLog : TransactionLog {
        val entries = mutableListOf<TransactionLogEntry>()
        override suspend fun record(entry: TransactionLogEntry) { entries.add(entry) }
        override suspend fun list(): List<TransactionLogEntry> = entries.toList()
    }

    /** Seeds a holder-bound PID SD-JWT VC and returns the issuer public key (for the verifier). */
    private suspend fun seedPid(area: SecureArea, storage: StorageDriver) = run {
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val holderKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        var n = 0
        val pid = SdJwtIssuer({ "salt-${++n}" }).issue(
            SecureAreaJwsSigner(area, issuerKey.handle, SigningAlgorithm.ES256),
            holderKey = holderKey.publicKey,
        ) {
            claim("iss", "https://issuer.example")
            claim("vct", "urn:eudi:pid:1")
            sd("family_name", "Han")
            sd("given_name", "Jongho")
            sd("birthdate", "1990-05-15")
        }
        CredentialStore(storage).save(
            CredentialEnvelope(
                CredentialId("pid-1"), CredentialFormat.SdJwtVc("urn:eudi:pid:1"), now,
                EnvelopeLifecycle.Issued(CredentialPolicy(), listOf(CredentialInstance(holderKey.handle, pid.serialize().encodeToByteArray()))),
            ),
        )
        issuerKey.publicKey
    }

    @Test
    fun remotePresentationDisclosesOnlyRequestedClaims() = runBlocking {
        val area = SoftwareSecureArea()
        val storage = InMemoryStorageDriver()
        val issuerPublic = seedPid(area, storage)
        val verifier = MockVerifier(issuerPublic)
        val log = RecordingLog()
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), storage, verifier, transactionLog = log))

        val session = wallet.presentation.start(verifier.requestUri("direct_post"))
        val resolved = withTimeout(15_000) { session.state.first { it is PresentationState.RequestResolved || it is PresentationState.Failed } }
        assertTrue(resolved is PresentationState.RequestResolved, "resolved: $resolved")
        val request = resolved.request
        assertTrue(request.satisfiable, "PID query satisfiable")
        assertEquals("verifier.example", request.verifier.clientId)
        assertEquals(CredentialId("pid-1"), request.queries.single().candidates.single().credentialId)

        session.respond(PresentationSelection.auto(request))
        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is PresentationState.Completed, "terminal: $terminal")
        assertEquals("https://verifier.example/done", terminal.redirectUri)

        // verifier received only the requested claims, holder+nonce bound
        val claims = verifier.verifiedClaims!!
        assertEquals(JsonValue.Str("Han"), claims["family_name"])
        assertEquals(JsonValue.Str("Jongho"), claims["given_name"])
        assertNull(claims["birthdate"], "unrequested claim must not be disclosed")

        // audit recorded
        val entry = log.entries.single()
        assertEquals(TransactionType.Presentation, entry.type)
        assertEquals(TransactionStatus.Success, entry.status)
        assertEquals("verifier.example", entry.relyingParty)
        assertTrue(entry.credentialIds.contains("pid-1"))
        assertTrue(entry.claimsDisclosed.containsAll(listOf("family_name", "given_name")))
        wallet.close()
    }

    @Test
    fun declineTerminatesAndRecordsAudit() = runBlocking {
        val area = SoftwareSecureArea()
        val storage = InMemoryStorageDriver()
        val issuerPublic = seedPid(area, storage)
        val verifier = MockVerifier(issuerPublic)
        val log = RecordingLog()
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), storage, verifier, transactionLog = log))

        val session = wallet.presentation.start(verifier.requestUri("direct_post"))
        withTimeout(15_000) { session.state.first { it is PresentationState.RequestResolved } }
        session.decline()
        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is PresentationState.Declined, "terminal: $terminal")

        assertNull(verifier.verifiedClaims, "nothing presented on decline")
        assertEquals(TransactionStatus.Declined, log.entries.single().status)
        wallet.close()
    }

    @Test
    fun mdocRemotePresentationSignsDeviceResponse() = runBlocking {
        val area = SoftwareSecureArea()
        val storage = InMemoryStorageDriver()
        val issuerKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val deviceKey = area.createKey(KeySpec(secureArea = area.id, algorithm = SigningAlgorithm.ES256))
        val bytes = MdocTestIssuer.issue(
            area = area, issuerKey = issuerKey, deviceKey = deviceKey.publicKey,
            docType = "org.iso.18013.5.1.mDL", namespace = "org.iso.18013.5.1",
            elements = listOf("family_name" to Cbor.Text("Kim"), "given_name" to Cbor.Text("Minsu"), "age_over_18" to Cbor.Bool(true)),
            x5chain = listOf(byteArrayOf(0x30, 0x01)),
            signed = now, validFrom = now, validUntil = now.plusSeconds(31_536_000),
        )
        CredentialStore(storage).save(
            CredentialEnvelope(
                CredentialId("mdl-1"), CredentialFormat.MsoMdoc("org.iso.18013.5.1.mDL"), now,
                EnvelopeLifecycle.Issued(CredentialPolicy(), listOf(CredentialInstance(deviceKey.handle, bytes))),
            ),
        )

        val verifier = MockMdocVerifier()
        val log = RecordingLog()
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), storage, verifier, transactionLog = log))

        val session = wallet.presentation.start(verifier.requestUri())
        val resolved = withTimeout(15_000) { session.state.first { it is PresentationState.RequestResolved || it is PresentationState.Failed } }
        assertTrue(resolved is PresentationState.RequestResolved, "resolved: $resolved")
        assertTrue(resolved.request.satisfiable, "mDL query satisfiable")

        session.respond(PresentationSelection.auto(resolved.request))
        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is PresentationState.Completed, "terminal: $terminal")

        // verifier verified the device signature and got only the requested elements (age_over_18 withheld)
        assertEquals(setOf("family_name", "given_name"), verifier.disclosedElements)
        val entry = log.entries.single()
        assertEquals(TransactionStatus.Success, entry.status)
        assertTrue(entry.credentialIds.contains("mdl-1"))
        wallet.close()
    }
}

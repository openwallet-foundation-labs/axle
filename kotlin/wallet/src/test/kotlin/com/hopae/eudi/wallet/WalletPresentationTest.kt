package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.cbor.Cbor
import com.hopae.eudi.wallet.mdoc.MdocTestIssuer
import com.hopae.eudi.wallet.sdjwt.JsonValue
import com.hopae.eudi.wallet.sdjwt.SdJwtIssuer
import com.hopae.eudi.wallet.sdjwt.SecureAreaJwsSigner
import com.hopae.eudi.wallet.spi.CredentialFormat
import com.hopae.eudi.wallet.spi.CredentialId
import com.hopae.eudi.wallet.spi.CredentialPolicy
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import com.hopae.eudi.wallet.spi.KeySpec
import com.hopae.eudi.wallet.spi.SecureArea
import com.hopae.eudi.wallet.spi.SigningAlgorithm
import com.hopae.eudi.wallet.spi.StorageDriver
import com.hopae.eudi.wallet.store.CredentialEnvelope
import com.hopae.eudi.wallet.store.CredentialInstance
import com.hopae.eudi.wallet.store.CredentialStore
import com.hopae.eudi.wallet.store.EnvelopeLifecycle
import com.hopae.eudi.wallet.testkit.InMemoryStorageDriver
import com.hopae.eudi.wallet.testkit.SoftwareSecureArea
import com.hopae.eudi.wallet.txlog.InMemoryTransactionLogStore
import com.hopae.eudi.wallet.txlog.TransactionStatus
import com.hopae.eudi.wallet.txlog.TransactionType
import com.hopae.eudi.wallet.vp.MockDcApiVerifier
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
        val logStore = InMemoryTransactionLogStore()
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), storage, verifier, transactionLogStore = logStore))

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
        val entry = logStore.all().single()
        assertEquals(TransactionType.PRESENTATION, entry.type)
        assertEquals(TransactionStatus.SUCCESS, entry.status)
        assertEquals("verifier.example", entry.relyingParty?.id)
        assertEquals(false, entry.relyingParty?.trusted) // unsigned request → not cryptographically trusted
        assertTrue(entry.documents.any { it.type == "urn:eudi:pid:1" && it.format == "dc+sd-jwt" })
        val loggedPaths = entry.documents.flatMap { it.claims.map { c -> c.path } }
        assertTrue(loggedPaths.containsAll(listOf(listOf("family_name"), listOf("given_name"))))
        wallet.close()
    }

    @Test
    fun declineTerminatesAndRecordsAudit() = runBlocking {
        val area = SoftwareSecureArea()
        val storage = InMemoryStorageDriver()
        val issuerPublic = seedPid(area, storage)
        val verifier = MockVerifier(issuerPublic)
        val logStore = InMemoryTransactionLogStore()
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), storage, verifier, transactionLogStore = logStore))

        val session = wallet.presentation.start(verifier.requestUri("direct_post"))
        withTimeout(15_000) { session.state.first { it is PresentationState.RequestResolved } }
        session.decline()
        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is PresentationState.Declined, "terminal: $terminal")

        assertNull(verifier.verifiedClaims, "nothing presented on decline")
        assertEquals(TransactionStatus.INCOMPLETE, logStore.all().single().status)
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
        val logStore = InMemoryTransactionLogStore()
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), storage, verifier, transactionLogStore = logStore))

        val session = wallet.presentation.start(verifier.requestUri())
        val resolved = withTimeout(15_000) { session.state.first { it is PresentationState.RequestResolved || it is PresentationState.Failed } }
        assertTrue(resolved is PresentationState.RequestResolved, "resolved: $resolved")
        assertTrue(resolved.request.satisfiable, "mDL query satisfiable")

        session.respond(PresentationSelection.auto(resolved.request))
        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is PresentationState.Completed, "terminal: $terminal")

        // verifier verified the device signature and got only the requested elements (age_over_18 withheld)
        assertEquals(setOf("family_name", "given_name"), verifier.disclosedElements)
        val entry = logStore.all().single()
        assertEquals(TransactionStatus.SUCCESS, entry.status)
        assertTrue(entry.documents.any { it.type == "org.iso.18013.5.1.mDL" })
        wallet.close()
    }

    @Test
    fun digitalCredentialsApiPresentationBindsOrigin() = runBlocking {
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

        val verifier = MockDcApiVerifier()
        val logStore = InMemoryTransactionLogStore()
        // DC API must not perform any HTTP — the request/response are handed over by the platform.
        val noHttp = object : HttpTransport {
            override suspend fun execute(request: HttpRequest): HttpResponse = throw AssertionError("DC API must not do HTTP")
        }
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), storage, noHttp, transactionLogStore = logStore))

        val session = wallet.presentation.startDcApi(verifier.requestObject(), verifier.origin)
        val resolved = withTimeout(15_000) { session.state.first { it is PresentationState.RequestResolved || it is PresentationState.Failed } }
        assertTrue(resolved is PresentationState.RequestResolved, "resolved: $resolved")

        session.respond(PresentationSelection.auto(resolved.request))
        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is PresentationState.Completed, "terminal: $terminal")
        assertNull(terminal.redirectUri, "DC API has no redirect")
        val dcResponse = terminal.dcApiResponse ?: error("missing DC API response")

        // response is origin-bound and selectively disclosed
        assertEquals(setOf("family_name", "given_name"), verifier.verify(dcResponse))
        assertEquals(TransactionStatus.SUCCESS, logStore.all().single().status)
        wallet.close()
    }

    @Test
    fun failedSubmissionRecordsErrorWhenEnabled() = runBlocking {
        val area = SoftwareSecureArea()
        val storage = InMemoryStorageDriver()
        val issuerPublic = seedPid(area, storage)
        val verifier = MockVerifier(issuerPublic).apply { rejectResponse = true }
        val logStore = InMemoryTransactionLogStore()
        val wallet = Wallet.create(
            WalletConfig(transactionLog = TransactionLogConfig(recordFailures = true)),
            WalletPorts(listOf(area), storage, verifier, transactionLogStore = logStore),
        )

        val session = wallet.presentation.start(verifier.requestUri("direct_post"))
        val resolved = withTimeout(15_000) { session.state.first { it is PresentationState.RequestResolved } }
        session.respond(PresentationSelection.auto((resolved as PresentationState.RequestResolved).request))
        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is PresentationState.Failed, "terminal: $terminal")

        // the failed final submission is recorded with ERROR + the attempted disclosure
        val entry = logStore.all().single()
        assertEquals(TransactionType.PRESENTATION, entry.type)
        assertEquals(TransactionStatus.ERROR, entry.status)
        assertEquals("verifier.example", entry.relyingParty?.id)
        assertTrue(entry.documents.any { it.type == "urn:eudi:pid:1" }, "attempted document logged")
        wallet.close()
    }

    @Test
    fun failedSubmissionNotRecordedByDefault() = runBlocking {
        val area = SoftwareSecureArea()
        val storage = InMemoryStorageDriver()
        val issuerPublic = seedPid(area, storage)
        val verifier = MockVerifier(issuerPublic).apply { rejectResponse = true }
        val logStore = InMemoryTransactionLogStore()
        val wallet = Wallet.create(WalletConfig(), WalletPorts(listOf(area), storage, verifier, transactionLogStore = logStore))

        val session = wallet.presentation.start(verifier.requestUri("direct_post"))
        val resolved = withTimeout(15_000) { session.state.first { it is PresentationState.RequestResolved } }
        session.respond(PresentationSelection.auto((resolved as PresentationState.RequestResolved).request))
        val terminal = withTimeout(15_000) { session.state.first { it.isTerminal } }
        assertTrue(terminal is PresentationState.Failed, "terminal: $terminal")

        // default config → failures are NOT recorded
        assertTrue(logStore.all().isEmpty(), "no transaction recorded by default")
        wallet.close()
    }
}

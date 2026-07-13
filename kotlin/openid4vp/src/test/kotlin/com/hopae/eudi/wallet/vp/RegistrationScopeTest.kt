package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.sdjwt.JsonValue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** ETSI TS 119 475 RPRC_21 attribute-scope check + registrar_dataset parsing. */
class RegistrationScopeTest {

    private fun mdocQuery(vararg elements: String) = CredentialQuery(
        id = "q",
        format = "mso_mdoc",
        meta = CredentialMeta(vctValues = null, doctypeValue = "org.iso.18013.5.1.mDL"),
        claims = elements.map { ClaimQuery(id = null, path = listOf(PathElement.Key("org.iso.18013.5.1"), PathElement.Key(it)), values = null) },
        claimSets = null,
    )

    private val mdlRegistered = RegisteredCredential(
        format = "mso_mdoc",
        docType = "org.iso.18013.5.1.mDL",
        vctValues = null,
        claims = listOf(listOf("org.iso.18013.5.1", "given_name"), listOf("org.iso.18013.5.1", "family_name")),
    )

    @Test
    fun allRequestedWithinRegistrationIsEmpty() {
        val dcql = DcqlQuery(listOf(mdocQuery("given_name", "family_name")), null)
        assertTrue(RegistrationScope.unregistered(dcql, listOf(mdlRegistered)).isEmpty())
    }

    @Test
    fun overAskingSurfacesUnregisteredClaims() {
        val dcql = DcqlQuery(listOf(mdocQuery("given_name", "birth_date", "portrait")), null)
        val out = RegistrationScope.unregistered(dcql, listOf(mdlRegistered))
        assertEquals(
            listOf(listOf("org.iso.18013.5.1", "birth_date"), listOf("org.iso.18013.5.1", "portrait")),
            out.map { it.path },
        )
    }

    @Test
    fun formatMismatchIsUnregistered() {
        // The RP registered mdoc claims; an SD-JWT query for the same element name is not covered.
        val sdjwt = CredentialQuery(
            id = "q", format = "dc+sd-jwt",
            meta = CredentialMeta(vctValues = listOf("urn:eudi:pid:1"), doctypeValue = null),
            claims = listOf(ClaimQuery(id = null, path = listOf(PathElement.Key("given_name")), values = null)),
            claimSets = null,
        )
        val out = RegistrationScope.unregistered(DcqlQuery(listOf(sdjwt), null), listOf(mdlRegistered))
        assertEquals(listOf(listOf("given_name")), out.map { it.path })
    }

    @Test
    fun noRegisteredCredentialsSkipsCheck() {
        // Nothing to check against (e.g. WRPRC declared no `credentials`) → don't flag anything.
        val dcql = DcqlQuery(listOf(mdocQuery("given_name")), null)
        assertTrue(RegistrationScope.unregistered(dcql, emptyList()).isEmpty())
    }

    @Test
    fun wildcardPathIsSkipped() {
        // A wildcard may appear as a deeper segment (indexing into a structured element value). Such a path
        // can't be pinned to a registered path, so it is neither matched nor flagged.
        val q = CredentialQuery(
            id = "q", format = "mso_mdoc",
            meta = CredentialMeta(vctValues = null, doctypeValue = "org.iso.18013.5.1.mDL"),
            claims = listOf(ClaimQuery(id = null, path = listOf(PathElement.Key("org.iso.18013.5.1"), PathElement.Key("driving_privileges"), PathElement.Wildcard), values = null)),
            claimSets = null,
        )
        assertTrue(RegistrationScope.unregistered(DcqlQuery(listOf(q), null), listOf(mdlRegistered)).isEmpty())
    }

    @Test
    fun datasetParsesIdentifierAndCredentials() {
        val data = JsonValue.parse(
            """{"identifier":[{"type":"LEI","identifier":"RP-1"}],"registryURI":"https://r.example/registrar",""" +
                """"policyURI":"https://rp.example/p","intendedUseIdentifier":"iu-1",""" +
                """"srvDescription":[{"lang":"en","content":"Svc"}],"purpose":[{"lang":"en","content":"Age"}],""" +
                """"credential":[{"format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claim":[{"path":["org.iso.18013.5.1","given_name"]}]}]}""",
        ) as JsonValue.Obj
        val ds = RegistrarDataset.fromData(data)
        assertEquals("RP-1", ds.identifier)
        assertEquals("https://r.example/registrar", ds.registryURI)
        assertEquals("https://rp.example/p", ds.policyURI)
        assertEquals("iu-1", ds.intendedUseIdentifier)
        assertEquals("Age", ds.purpose.first().value)
        assertEquals(1, ds.credentials.size)
        assertEquals("org.iso.18013.5.1.mDL", ds.credentials.first().docType)
        assertEquals(listOf(listOf("org.iso.18013.5.1", "given_name")), ds.credentials.first().claims)
    }
}

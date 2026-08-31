package com.hopae.eudi.wallet

import com.hopae.eudi.wallet.spi.CredentialId
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The User's pick must survive into the selection.
 *
 * Under the Digital Credentials API the OS selector resolves the choice before the wallet is started, so
 * "first candidate" is not a neutral default there — it silently answers with a credential other than the one
 * the User tapped, and nothing in the flow says so. These pin the preference rule for both selection types.
 */
class SelectionPreferenceTest {

    private val hopae = CredentialId("cred-hopae-mdl")
    private val geneva = CredentialId("cred-geneva-mdl")

    private fun query(id: String, multiple: Boolean, candidates: List<CredentialId>) =
        QueryPresentation(id, required = true, candidates = candidates.map { PresentationCandidate(it, emptyList()) }, multiple = multiple)

    private fun doc(docType: String, candidates: List<CredentialId>) =
        RequestedDocumentView(docType, mapOf("org.iso.18013.5.1" to listOf("family_name")), candidates)

    @Test
    fun `preferring picks the chosen credential, not the first candidate`() {
        val r = listOf(query("mdl", multiple = false, listOf(hopae, geneva)))
        assertEquals(listOf(geneva), PresentationSelection.preferring(r, listOf(geneva)).chosen["mdl"])
    }

    @Test
    fun `preferring falls back to the first candidate when the pick cannot answer the query`() {
        val r = listOf(query("mdl", multiple = false, listOf(hopae)))
        // The selector named a credential this query has no candidate for: answer, do not drop the query.
        assertEquals(listOf(hopae), PresentationSelection.preferring(r, listOf(geneva)).chosen["mdl"])
        assertEquals(listOf(hopae), PresentationSelection.preferring(r, emptyList()).chosen["mdl"])
    }

    @Test
    fun `a multiple query still takes every candidate`() {
        // §6.1: the verifier asked for all of them, so there is nothing for the pick to disambiguate.
        val r = listOf(query("mdl", multiple = true, listOf(hopae, geneva)))
        assertEquals(listOf(hopae, geneva), PresentationSelection.preferring(r, listOf(geneva)).chosen["mdl"])
    }

    @Test
    fun `no pick keeps the first-candidate behaviour`() {
        val r = listOf(query("mdl", multiple = false, listOf(hopae, geneva)))
        assertEquals(listOf(hopae), PresentationSelection.preferring(r, emptyList()).chosen["mdl"])
    }

    @Test
    fun `proximity preferring picks the chosen credential per doctype`() {
        val docs = listOf(doc("org.iso.18013.5.1.mDL", listOf(hopae, geneva)))
        assertEquals(geneva, ProximitySelection.preferring(docs, listOf(geneva)).chosen["org.iso.18013.5.1.mDL"])
        assertEquals(hopae, ProximitySelection.preferring(docs, emptyList()).chosen["org.iso.18013.5.1.mDL"])
    }

    @Test
    fun `proximity preferring only pins the doctype the pick can answer`() {
        val docs = listOf(doc("org.iso.18013.5.1.mDL", listOf(hopae, geneva)), doc("eu.europa.ec.eudi.pid.1", listOf(hopae)))
        val chosen = ProximitySelection.preferring(docs, listOf(geneva)).chosen
        assertEquals(geneva, chosen["org.iso.18013.5.1.mDL"])
        assertEquals(hopae, chosen["eu.europa.ec.eudi.pid.1"])
    }
}

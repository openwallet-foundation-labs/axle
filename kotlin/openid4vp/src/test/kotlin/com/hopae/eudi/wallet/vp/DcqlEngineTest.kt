package com.hopae.eudi.wallet.vp

import com.hopae.eudi.wallet.sdjwt.JsonValue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DcqlEngineTest {

    private class FakeCred(
        override val credentialId: String,
        override val vct: String?,
        override val claims: JsonValue.Obj,
        override val format: String = "dc+sd-jwt",
        override val docType: String? = null,
    ) : QueryableCredential

    private fun obj(vararg e: Pair<String, JsonValue>) = JsonValue.Obj(e.toList())
    private fun arr(vararg v: JsonValue) = JsonValue.Arr(v.toList())
    private fun str(s: String) = JsonValue.Str(s)

    private val pid = FakeCred(
        "pid-1", "urn:eudi:pid:1",
        obj(
            "family_name" to str("Han"),
            "given_name" to str("Jongho"),
            "nationalities" to arr(str("LU"), str("KR")),
            "address" to obj("country" to str("LU"), "locality" to str("Luxembourg")),
            "age_over" to arr(obj("age" to JsonValue.NumInt(18), "over" to JsonValue.Bool(true))),
        ),
    )

    private fun query(json: String) = DcqlQuery.parse(JsonValue.parse(json) as JsonValue.Obj)

    @Test
    fun simpleClaimMatch() {
        val q = query("""{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
            "claims":[{"path":["family_name"]},{"path":["given_name"]}]}]}""")
        val r = DcqlEngine.match(q, listOf(pid))
        assertTrue(r.isSatisfiable())
        val cand = r.candidatesByQuery["c"]!!.single()
        assertEquals(setOf(listOf("family_name"), listOf("given_name")), cand.disclosedPaths.toSet())
    }

    @Test
    fun vctMismatchExcludes() {
        val q = query("""{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{"vct_values":["urn:other"]},
            "claims":[{"path":["family_name"]}]}]}""")
        val r = DcqlEngine.match(q, listOf(pid))
        assertFalse(r.isSatisfiable())
        assertTrue(r.candidatesByQuery["c"]!!.isEmpty())
    }

    @Test
    fun missingClaimExcludes() {
        val q = query("""{"credentials":[{"id":"c","format":"dc+sd-jwt","claims":[{"path":["email"]}]}]}""")
        assertTrue(DcqlEngine.match(q, listOf(pid)).candidatesByQuery["c"]!!.isEmpty())
    }

    @Test
    fun nestedPath() {
        val q = query("""{"credentials":[{"id":"c","format":"dc+sd-jwt","claims":[{"path":["address","locality"]}]}]}""")
        val cand = DcqlEngine.match(q, listOf(pid)).candidatesByQuery["c"]!!.single()
        assertEquals(listOf(listOf("address", "locality")), cand.disclosedPaths)
    }

    @Test
    fun arrayIndexPath() {
        val q = query("""{"credentials":[{"id":"c","format":"dc+sd-jwt","claims":[{"path":["nationalities",0]}]}]}""")
        val cand = DcqlEngine.match(q, listOf(pid)).candidatesByQuery["c"]!!.single()
        assertEquals(listOf(listOf("nationalities", "0")), cand.disclosedPaths)
    }

    @Test
    fun nullWildcardOverArray() {
        // path [nationalities, null] fans out over every element
        val q = query("""{"credentials":[{"id":"c","format":"dc+sd-jwt","claims":[{"path":["nationalities",null]}]}]}""")
        val cand = DcqlEngine.match(q, listOf(pid)).candidatesByQuery["c"]!!.single()
        assertEquals(setOf(listOf("nationalities", "0"), listOf("nationalities", "1")), cand.disclosedPaths.toSet())
    }

    @Test
    fun valuesMatchOnWildcard() {
        // nationalities contains "KR" -> matches; only the matching leaf is disclosed
        val q = query("""{"credentials":[{"id":"c","format":"dc+sd-jwt",
            "claims":[{"path":["nationalities",null],"values":["KR"]}]}]}""")
        val cand = DcqlEngine.match(q, listOf(pid)).candidatesByQuery["c"]!!.single()
        assertEquals(listOf(listOf("nationalities", "1")), cand.disclosedPaths)
    }

    @Test
    fun valuesNoMatchExcludes() {
        val q = query("""{"credentials":[{"id":"c","format":"dc+sd-jwt",
            "claims":[{"path":["nationalities",null],"values":["US"]}]}]}""")
        assertTrue(DcqlEngine.match(q, listOf(pid)).candidatesByQuery["c"]!!.isEmpty())
    }

    @Test
    fun nullWildcardValuesOnObjectArray() {
        // age_over[*].over == true (Lukas's null array-wildcard + values on nested objects)
        val q = query("""{"credentials":[{"id":"c","format":"dc+sd-jwt",
            "claims":[{"path":["age_over",null,"over"],"values":[true]}]}]}""")
        val cand = DcqlEngine.match(q, listOf(pid)).candidatesByQuery["c"]!!.single()
        assertEquals(listOf(listOf("age_over", "0", "over")), cand.disclosedPaths)
    }

    @Test
    fun claimSetsChoosesFirstSatisfiable() {
        // first claim_set requires email (absent) -> falls to second [family_name, given_name]
        val q = query("""{"credentials":[{"id":"c","format":"dc+sd-jwt",
            "claims":[{"id":"e","path":["email"]},{"id":"f","path":["family_name"]},{"id":"g","path":["given_name"]}],
            "claim_sets":[["e"],["f","g"]]}]}""")
        val cand = DcqlEngine.match(q, listOf(pid)).candidatesByQuery["c"]!!.single()
        assertEquals(setOf(listOf("family_name"), listOf("given_name")), cand.disclosedPaths.toSet())
    }

    @Test
    fun credentialSetsOptionalNotRequired() {
        val q = query("""{"credentials":[
            {"id":"pid","format":"dc+sd-jwt","claims":[{"path":["family_name"]}]},
            {"id":"mdl","format":"dc+sd-jwt","meta":{"vct_values":["urn:mdl"]},"claims":[{"path":["x"]}]}],
            "credential_sets":[{"options":[["pid"]],"required":true},{"options":[["mdl"]],"required":false}]}""")
        val r = DcqlEngine.match(q, listOf(pid))
        // pid required and present; mdl optional and absent -> still satisfiable
        assertTrue(r.isSatisfiable())
        assertEquals(setOf("pid"), r.requiredQueryIds)
    }

    @Test
    fun credentialSetsRequiredMissingUnsatisfiable() {
        val q = query("""{"credentials":[
            {"id":"mdl","format":"dc+sd-jwt","meta":{"vct_values":["urn:mdl"]},"claims":[{"path":["x"]}]}],
            "credential_sets":[{"options":[["mdl"]],"required":true}]}""")
        assertFalse(DcqlEngine.match(q, listOf(pid)).isSatisfiable())
    }
}

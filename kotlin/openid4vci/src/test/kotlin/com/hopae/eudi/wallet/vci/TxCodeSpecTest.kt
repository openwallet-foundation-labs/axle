package com.hopae.eudi.wallet.vci

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * OpenID4VCI §4.1.1 transaction-code input hints. `TxCodeSpec.violations` is advisory only — it reports
 * how a code departs from the offer's hints so a wallet can warn, but never blocks issuance (a hint can
 * be wrong; the Authorization Server is the authority on the code).
 */
class TxCodeSpecTest {

    private fun spec(length: Int? = null, inputMode: String? = null) =
        CredentialOffer.TxCodeSpec(length, inputMode, description = null)

    @Test
    fun aMatchingNumericCodeHasNoViolations() {
        assertTrue(spec(length = 5, inputMode = "numeric").violations("12345").isEmpty())
    }

    @Test
    fun numericIsTheDefaultInputMode() {
        // §4.1.1: "The default is numeric." — non-digits are flagged even when input_mode is absent.
        assertTrue(spec().violations("abc").any { "digits" in it })
        assertTrue(spec().violations("123").isEmpty())
    }

    @Test
    fun nonDigitsViolateNumeric() {
        val v = spec(inputMode = "numeric").violations("12a45")
        assertEquals(1, v.size)
        assertTrue("digits" in v.single())
    }

    @Test
    fun textInputModeAcceptsAnyCharacters() {
        assertTrue(spec(inputMode = "text").violations("a-b C!").isEmpty())
    }

    @Test
    fun wrongLengthIsFlagged() {
        val v = spec(length = 6).violations("123")
        assertTrue(v.any { "6 characters" in it && "got 3" in it }, "$v")
    }

    @Test
    fun reportsBothMismatchesAtOnce() {
        // wrong charset AND wrong length — a wallet can show every problem in one pass.
        val v = spec(length = 4, inputMode = "numeric").violations("ab")
        assertEquals(2, v.size, "$v")
    }
}

package com.hopae.eudi.wallet

/** Typed wallet errors (API-CONTRACT.md §8). Spec error codes are preserved on the relevant cases. */
sealed class WalletError(message: String, cause: Throwable? = null) : Exception(message, cause) {

    sealed class Issuance(message: String, cause: Throwable? = null) : WalletError(message, cause) {
        class InvalidOffer(message: String) : Issuance("invalid offer: $message")
        class AuthorizationFailed(val oauthError: String?, message: String) : Issuance("authorization failed: $message")
        class CredentialRequestFailed(message: String, cause: Throwable? = null) : Issuance("credential request failed: $message", cause)
        class DeferredNotReady : Issuance("deferred credential not ready")
        class Unexpected(cause: Throwable) : Issuance("unexpected issuance error: ${cause.message}", cause)
    }
}

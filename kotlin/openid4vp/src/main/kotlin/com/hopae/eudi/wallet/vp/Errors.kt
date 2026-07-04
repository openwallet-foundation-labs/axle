package com.hopae.eudi.wallet.vp

/** Typed OpenID4VP errors. */
sealed class VpException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class InvalidRequest(message: String) : VpException("invalid request: $message")
    class VerifierNotTrusted(message: String) : VpException("verifier not trusted: $message")
    class QueryNotSatisfiable(val missingQueryIds: Set<String>) :
        VpException("DCQL query not satisfiable; missing: $missingQueryIds")
    class SelectionIncomplete(message: String) : VpException("selection incomplete: $message")
    class ResponseFailed(message: String, cause: Throwable? = null) : VpException("response failed: $message", cause)
    class Unsupported(message: String) : VpException("unsupported: $message")
}

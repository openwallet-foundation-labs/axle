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

/**
 * The `error` values of an OpenID4VP Authorization Error Response (§8.5) — the RFC 6749 codes this
 * specification clarifies, plus the ones it adds. Sent to the verifier's `response_uri` by
 * [Openid4VpClient.reportError].
 */
enum class VpErrorCode(val code: String) {
    /** Requested scope value is invalid, unknown, or malformed. */
    INVALID_SCOPE("invalid_scope"),

    /** Malformed request: conflicting/absent DCQL, an unsupported Client Identifier Prefix, prefix rules violated. */
    INVALID_REQUEST("invalid_request"),

    /** `client_metadata` conflicts with metadata the wallet already knows for this Client Identifier. */
    INVALID_CLIENT("invalid_client"),

    /** No credentials to satisfy the request, the user refused, or end-user authentication failed. */
    ACCESS_DENIED("access_denied"),

    /** The wallet supports none of the formats the verifier requested. */
    VP_FORMATS_NOT_SUPPORTED("vp_formats_not_supported"),

    /** `request_uri_method` was neither `get` nor `post` (case-sensitive). */
    INVALID_REQUEST_URI_METHOD("invalid_request_uri_method"),

    /** A `transaction_data` entry is of an unknown type, malformed, or references credentials the wallet lacks. */
    INVALID_TRANSACTION_DATA("invalid_transaction_data"),

    /** The wallet could not be invoked and another component answered on its behalf. */
    WALLET_UNAVAILABLE("wallet_unavailable"),
}

/**
 * The §8.5 code that best describes this failure. Deliberately conservative: everything the wallet
 * refuses to answer maps to `access_denied` (which reveals nothing about what it holds), and every
 * malformed request to `invalid_request`.
 */
val VpException.errorCode: VpErrorCode
    get() = when (this) {
        is VpException.InvalidRequest -> VpErrorCode.INVALID_REQUEST
        is VpException.Unsupported -> VpErrorCode.INVALID_REQUEST
        is VpException.ResponseFailed -> VpErrorCode.INVALID_REQUEST
        is VpException.VerifierNotTrusted -> VpErrorCode.ACCESS_DENIED
        is VpException.QueryNotSatisfiable -> VpErrorCode.ACCESS_DENIED
        is VpException.SelectionIncomplete -> VpErrorCode.ACCESS_DENIED
    }

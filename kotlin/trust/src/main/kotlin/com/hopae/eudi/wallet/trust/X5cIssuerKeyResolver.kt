package com.hopae.eudi.wallet.trust

import com.hopae.eudi.wallet.sdjwt.IssuerKeyResolver
import com.hopae.eudi.wallet.sdjwt.IssuerSigningKey
import com.hopae.eudi.wallet.sdjwt.JsonValue
import java.util.Base64

/**
 * Resolves an SD-JWT VC issuer key from the JWS `x5c` header, validating the certificate chain
 * to a trust anchor (the production form of the earlier leaf-only test helper). This is how the
 * real EUDI issuer signs — an x5c leaf chaining to `PID Issuer CA`, not a metadata endpoint.
 */
class X5cIssuerKeyResolver(private val validator: X509ChainValidator) : IssuerKeyResolver {

    override suspend fun resolve(iss: String, header: JsonValue.Obj): IssuerSigningKey {
        val x5c = (header["x5c"] as? JsonValue.Arr)?.items?.map { el ->
            Base64.getDecoder().decode((el as? JsonValue.Str)?.value ?: throw TrustException("x5c entries must be strings"))
        } ?: throw TrustException("issuer JWS has no x5c header")

        val chain = validator.validate(x5c) // throws if not trusted
        val leaf = chain.first()
        return IssuerSigningKey(X509Support.ecPublicKey(leaf), X509Support.signingAlgorithm(leaf))
    }
}

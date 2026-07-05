package com.hopae.eudi.demo.adapters

import com.hopae.eudi.wallet.spi.HttpMethod
import com.hopae.eudi.wallet.spi.HttpRequest
import com.hopae.eudi.wallet.spi.HttpResponse
import com.hopae.eudi.wallet.spi.HttpTransport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/** [HttpTransport] backed by OkHttp — honours the per-request redirect policy the OpenID flows rely on. */
class OkHttpTransport(private val base: OkHttpClient = OkHttpClient()) : HttpTransport {

    override suspend fun execute(request: HttpRequest): HttpResponse = withContext(Dispatchers.IO) {
        val client = if (request.followRedirects) base
        else base.newBuilder().followRedirects(false).followSslRedirects(false).build()

        val builder = Request.Builder().url(request.url)
        request.headers.forEach { builder.addHeader(it.first, it.second) }
        val body = request.body?.toRequestBody()
        when (request.method) {
            HttpMethod.GET -> builder.get()
            HttpMethod.POST -> builder.post(body ?: ByteArray(0).toRequestBody())
            HttpMethod.PUT -> builder.put(body ?: ByteArray(0).toRequestBody())
            HttpMethod.PATCH -> builder.patch(body ?: ByteArray(0).toRequestBody())
            HttpMethod.DELETE -> if (body != null) builder.delete(body) else builder.delete()
        }
        client.newCall(builder.build()).execute().use { response ->
            HttpResponse(response.code, response.headers.map { it.first to it.second }, response.body?.bytes() ?: ByteArray(0))
        }
    }
}

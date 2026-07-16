---
title: Digital Credentials API (Android)
---

# Digital Credentials API (Android)

[W3C Digital Credentials API](https://w3c-fedid.github.io/digital-credentials/)는 웹사이트가
`navigator.credentials.get({ digital })`를 호출하면 OS가 지갑 선택창을 중개하게 해줍니다 — QR도, HTTP
왕복도 없습니다. 크리덴셜 로직은 SDK가 처리하고, 이 가이드는 브라우저가 지갑을 호출할 수 있도록
**Android Credential Manager**에 연결하는 방법을 다룹니다.

지갑은 세 가지 DC API 프로토콜에 응답하며, 모두 실기기에서 `verifier.eudiw.dev`·`digital-credentials.dev`로
검증되었습니다:

| 프로토콜 | 설명 | SDK 진입점 |
| --- | --- | --- |
| `openid4vp-v1-unsigned` | OpenID4VP 1.0 요청 객체 (평문 JSON) | `wallet.presentation.startDcApi(json, origin)` |
| `openid4vp-v1-signed` | OpenID4VP 1.0 JAR — `{"request":"<JWS>"}` | `wallet.presentation.startDcApi(json, origin)` |
| `org-iso-mdoc` | ISO 18013-7 Annex C 원시 mdoc, HPKE 암호화 | `wallet.proximity.respondDcApiMdoc(deviceRequest, encryptionInfo, origin)` |

두 진입점 모두 크로스플랫폼입니다 (Kotlin·Swift 동일). 이 페이지의 나머지는 Android 프로바이더 배선입니다.

:::note iOS는 다릅니다
iOS에서는 지갑이 **프로바이더 앱 익스텐션**(Apple IdentityDocumentServices)이고, 매칭은 OS가 담당하며(WASM 매처 없음),
플랫폼은 서드파티 지갑에 **`org-iso-mdoc`만** 라우팅합니다 — 브라우저 DC API를 통한 OpenID4VP는 Apple이 지원하지 않습니다.
전용 **[Digital Credentials API — iOS](./dc-api-ios)** 가이드를 참고하세요.
:::

:::note 왜 커스텀 matcher인가
Credential Manager는 선택창을 띄우기 전에 **matcher**(작은 WASM 프로그램)를 실행해 들어온 요청에 대해
크리덴셜을 필터링합니다. androidx `OpenId4VpRegistry`가 번들하는 matcher는 (`registry:1.0.0-alpha04`
기준) 현재 EUDI verifier들이 보내는 `openid4vp-v1-*` 프로토콜 ID를 인식하지 **못하고**, 원시
`org-iso-mdoc`는 아예 지원하지 않습니다. 그래서 matcher WASM을 직접 번들하고 저수준 Google Play
Services **IdentityCredentials** API로 등록합니다. 따라서 DC API는 GMS 기기가 필요하지만, 나머지 기능
(발급·원격/근접 제시)은 이것 없이도 정상 동작합니다.
:::

## 1. 의존성

```kotlin
implementation("androidx.credentials:credentials:1.6.0-rc01")
implementation("com.google.android.gms:play-services-identity-credentials:16.0.0-alpha08")
```

그리고 번들 에셋 두 개:

- `assets/identitycredentialmatcher.wasm` — matcher 프로그램
  ([Multipaz](https://github.com/openwallet-foundation-labs/identity-credential)의 것 등).
- `assets/privileged_allowlist.json` — Google의 특권 브라우저 목록,
  `https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json` (웹 origin 해석용).

## 2. 크리덴셜 등록

등록 시 Credential Manager에 **matcher**와 그것이 읽을 **크리덴셜 데이터베이스** 두 가지를 넘깁니다.
데이터베이스를 matcher 스키마에 맞는 CBOR로 만들고, 지원 프로토콜을 선언하고, 두 크리덴셜 타입으로
등록합니다. 크리덴셜이 바뀔 때마다(발급/삭제) 재등록하세요.

```kotlin
object DcApiRegistrar {
    private val PROTOCOLS = listOf(
        "openid4vp-v1-signed", "openid4vp-v1-unsigned", "openid4vp-v1-multisigned", "org-iso-mdoc", "openid4vp",
    )

    suspend fun register(context: Context, wallet: Wallet) {
        val creds = wallet.credentials.list()
        val db = buildDatabase(creds)                                  // CBOR: { protocols, credentials }
        val matcher = context.assets.open("identitycredentialmatcher.wasm").use { it.readBytes() }
        val client = IdentityCredentialManager.getClient(context)
        // androidx 디지털 크리덴셜 타입 + 레거시 Credman 타입 두 가지로 등록.
        listOf("androidx.credentials.TYPE_DIGITAL_CREDENTIAL", "com.credman.IdentityCredential").forEach { type ->
            client.registerCredentials(
                RegistrationRequest(credentials = db, matcher = matcher, type = type, requestType = "", protocolTypes = emptyList()),
            )
        }
    }
}
```

크리덴셜 데이터베이스는 CBOR 맵 `{ "protocols": [...], "credentials": [...] }`입니다. 각 크리덴셜 항목은
표시 필드와, matcher가 검색하는 포맷별 블록을 담습니다:

```kotlin
// mSO mdoc 항목 — matcher가 docType + 네임스페이스 요소를 DeviceRequest와 매칭.
map(common + ("mdoc" to map(listOf(
    "documentId" to txt(c.id.value),
    "docType"    to txt(f.docType),
    "namespaces" to map(namespaces),   // ns -> { element -> [displayName, value, rawMatchString] }
))))

// SD-JWT VC 항목 — vct + 클레임 이름으로 매칭.
map(common + ("sdjwt" to map(listOf(
    "documentId" to txt(c.id.value),
    "vct"        to txt(f.vct),
    "claims"     to map(claims),
))))
```

앱 시작 시, 그리고 `wallet.credentials.changes`가 방출할 때마다 `register`를 실행하세요.

## 3. 프로바이더 액티비티

`GET_CREDENTIAL` 인텐트용 액티비티 하나를 선언합니다 — UI는 필요 없습니다(OS 선택창이 곧 동의).
**androidx와 identity-credentials 액션 둘 다** 필요합니다:

```xml
<activity
    android:name=".GetCredentialActivity"
    android:exported="true"
    android:theme="@android:style/Theme.Translucent.NoTitleBar">
    <intent-filter>
        <action android:name="androidx.credentials.registry.provider.action.GET_CREDENTIAL" />
        <action android:name="androidx.identitycredentials.action.GET_CREDENTIALS" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

요청 봉투를 꺼낸 뒤 프로토콜로 분기합니다. DC API 요청은
`{"requests":[{"protocol":"…","data":{…}}]}` — `org-iso-mdoc`는 mdoc 경로로, 나머지는 OpenID4VP
경로로 보냅니다:

```kotlin
@OptIn(androidx.credentials.ExperimentalDigitalCredentialApi::class)
override fun onCreate(savedInstanceState: Bundle?) {
    val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: return finishNoResult()
    val option = request.credentialOptions.filterIsInstance<GetDigitalCredentialOption>().firstOrNull() ?: return finishNoResult()
    val origin = request.callingAppInfo.getOrigin(privilegedAllowlistJson) ?: appOrigin(request)

    // org-iso-mdoc (ISO 18013-7): 원시 mdoc DeviceRequest -> HPKE 암호화된 DeviceResponse.
    val mdoc = matchProtocol(option.requestJson, listOf("org-iso-mdoc", "org.iso.mdoc"))
    if (mdoc != null) {
        val (proto, data) = mdoc
        lifecycleScope.launch {
            val response = wallet.proximity.respondDcApiMdoc(
                data.getString("deviceRequest"), data.getString("encryptionInfo"), origin,
            )
            val content = JSONObject().put("protocol", proto)
                .put("data", JSONObject().put("response", response))
            respond(DigitalCredential(content.toString())); finish()
        }
        return
    }

    // openid4vp-v1-unsigned / -signed.
    val openid4vp = extractOpenId4Vp(option.requestJson) ?: return failAndFinish("no openid4vp request")
    lifecycleScope.launch {
        val session = wallet.presentation.startDcApi(openid4vp, origin)
        val resolved = session.state.first { it is RequestResolved || it is Failed } as RequestResolved
        session.respond(PresentationSelection.auto(resolved.request))
        val done = session.state.first { it.isTerminal } as PresentationState.Completed
        respond(DigitalCredential(done.dcApiResponse!!)); finish()
    }
}
```

## 4. org-iso-mdoc와 HPKE

`org-iso-mdoc` 요청 `data`는 `{ "deviceRequest": base64url(CBOR), "encryptionInfo": base64url(CBOR) }`
— 순수 ISO 18013-5 `DeviceRequest`와 verifier의 임시 암호화 키입니다. `respondDcApiMdoc`는:

1. 요청된 docType의 `DeviceResponse`를 만들고, ISO 18013-7 **dcapi** `SessionTranscript`
   `[null, null, ["dcapi", SHA-256(CBOR([encryptionInfoB64, origin]))]]`에 대해 서명하고;
2. verifier의 `recipientPublicKey`로 **HPKE 봉인**하며 (RFC 9180 base mode,
   `DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM`, `info = CBOR(SessionTranscript)`, `aad` 없음);
3. `base64url(CBOR(["dcapi", { "enc": …, "cipherText": … }]))`를 반환합니다.

HPKE는 SDK에 있습니다 (`Hpke.sealBaseP256`, Kotlin `mdoc` 모듈 / Swift `MDoc`). RFC 9180 Appendix A.3
테스트 벡터로 검증되어 있어 크립토가 이식 가능하며 플랫폼 HPKE가 필요 없습니다. 데모는 반환된 문자열을
`{"protocol","data":{"response":…}}`로 감싸기만 합니다.

## 5. Verifier origin

`callingAppInfo.getOrigin(allowlistJson)`은 호출자가 허용목록의 특권 브라우저일 때 **웹 origin**
(예: `https://verifier.example`)을 반환합니다. **네이티브 앱** verifier의 경우 origin이 비어 있으므로,
호출자의 서명 인증서에서 도출합니다:

```
android:apk-key-hash:<base64url SHA-256 of signingCertificateHistory[0]>
```

SDK는 이 origin을 mdoc `SessionTranscript`(ISO 18013-7 Annex C) / SD-JWT KB-JWT에 바인딩하므로,
응답은 요청한 호출자에 암호학적으로 묶입니다.

### `expected_origins` — 요청 재생 방어

**응답**을 origin에 바인딩해도 **요청**의 재생은 막지 못합니다. 서명된 요청 객체는 bearer 아티팩트라서,
악성 사이트가 정상 verifier에게서 캡처한 요청을 그대로 제시해도 서명은 여전히 검증됩니다 — 그러면 지갑은
공격자가 개시한 요청에 대해 그 verifier의 신뢰된 신원을 표시하게 됩니다.

OpenID4VP Appendix A.2가 `expected_origins`로 이를 막고, SDK가 이를 강제합니다:

| 요청 | 규칙 |
| --- | --- |
| **서명됨** (`{"request":"<JWS>"}` 또는 bare JWS) | `expected_origins`는 **필수**. 플랫폼이 준 origin을 담은 비어 있지 않은 배열이 아니면 거부합니다. `client_id`도 필수. |
| **미서명** (평문 JSON) | origin이 곧 verifier의 신원. `expected_origins`와 `client_id`가 있어도 **무시**합니다. |

두 입력 모두 호출 페이지가 조작할 수 없는 경로에서 옵니다: origin은 플랫폼이 주입하고,
`expected_origins`는 서명으로 보호되는 payload 안에 있습니다. 불일치 시
`VpException.InvalidRequest` / `VpError.invalidRequest`(OpenID4VP의 `invalid_request`)가 발생합니다.

:::note 자기 주장일 뿐, 소유 증명이 아님
`expected_origins`는 *남의* 서명 요청 재생을 막습니다. verifier가 그 origin을 소유한다는 증명은 아니며,
유효한 인증서를 가진 공격자는 자기 origin을 넣어 자기 요청에 서명할 수 있습니다. 그 `client_id`를 신뢰할지는
트러스트 프레임워크(`readerAnchorsDer`)의 몫입니다.
:::

## 6. 테스트

1. 등록은 앱 시작 시 실행됩니다(로그 `registered N credential(s)`) — 이제 지갑이 프로바이더입니다.
2. Chrome에서 DC-API verifier(`verifier.eudiw.dev` 또는 `digital-credentials.dev`)를 열고 프로토콜을
   선택하세요 — **openid4vp**(unsigned·signed)와 **org-iso-mdoc**(mDL)를 모두 시도해 보세요.
3. `navigator.credentials.get({ digital })` → OS가 지갑 포함 선택창을 표시 → 선택 →
   `GetCredentialActivity`가 알맞은 SDK 경로로 라우팅해 응답을 반환합니다.

:::note
일부 Chrome 빌드는 `chrome://flags` → "Digital Credentials API" 뒤에서 이를 게이팅합니다. 응답이
verifier 자체의 발급자 신뢰 정책에 의해 거부될 수도 있는데, 이는 verifier 쪽 문제이지 지갑 문제가
아닙니다.
:::

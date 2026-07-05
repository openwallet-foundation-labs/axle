# Wallet 파사드 — 플로우별 사용 예시 (usage-driven design)

구현 전 API 인간공학 검증용. 각 플로우를 "개발자가 실제로 어떻게 쓸까"로 작성해 어색함을 드러낸다. Kotlin 주 + 헤드라인 플로우는 Swift 미러. 끝의 **인간공학 노트**가 이 연습으로 발견한 개선점.

---

## 0. 조립 (Assembly)

```kotlin
val wallet = Wallet.create(
    config = WalletConfig(
        issuance = IssuanceConfig(
            clientId = "eudi-wallet",
            clientAuth = ClientAuth.None,                 // 또는 ClientAuth.AttestationBased
            redirectUri = "eudi-wallet://authorize",
            // par = Required, dpop = Required 가 HAIP 기본값
        ),
        presentation = PresentationConfig(
            clientIdPrefixes = listOf(ClientIdScheme.X509SanDns, ClientIdScheme.X509Hash),
            responseEncryption = ResponseEncryption.Supported,
        ),
        trust = TrustConfig(
            issuerAnchors = TrustAnchorSource.fixed(TrustAnchors.ofDer(iacaDerList)),
            readerAnchors = TrustAnchorSource.fixed(TrustAnchors.ofDer(readerCaDerList)),
            readerAuthPolicy = ReaderAuthPolicy.EnforceIfPresent,
        ),
    ),
    ports = WalletPorts(
        secureArea = listOf(SoftwareSecureArea()),        // 앱: AndroidKeystoreSecureArea / SecureEnclaveArea
        storage = InMemoryStorage(),                      // 앱: 플랫폼 암호화 스토리지 어댑터
        http = JdkHttpTransport(),
        walletAttestation = myWuaProvider,                // 옵션 (WUA 백엔드)
    ),
)
// wallet은 스레드 세이프·멀티인스턴스. 앱 종료 시 wallet.close() (멱등).
```

```swift
let wallet = try Wallet(
    config: WalletConfig(
        issuance: .init(clientId: "eudi-wallet", clientAuth: .none, redirectUri: "eudi-wallet://authorize"),
        presentation: .init(clientIdPrefixes: [.x509SanDns, .x509Hash], responseEncryption: .supported),
        trust: .init(issuerAnchors: .fixed(try TrustAnchors(der: iacaDER)),
                     readerAnchors: .fixed(try TrustAnchors(der: readerCaDER)),
                     readerAuthPolicy: .enforceIfPresent)
    ),
    ports: WalletPorts(secureArea: [SoftwareSecureArea()], storage: InMemoryStorage(),
                       http: URLSessionTransport(), walletAttestation: myWuaProvider)
)
```

---

## 1. 발급 — pre-authorized code (+ tx_code)

```kotlin
// 1) 오퍼 해석 (딥링크 / QR / raw JSON)
val offer = wallet.issuance.resolveOffer(offerUri)

// 2) 발급 시작 — 키 생성·배치·정책은 요청 시점에 선결정 (콜백 없음)
val session = wallet.issuance.start(
    IssuanceRequest.fromOffer(
        offer,
        accepted = offer.credentials,                     // 또는 사용자가 고른 부분집합
        keySpec = KeySpec(userAuthentication = UserAuthPolicy.Required()),
        policy = CredentialPolicy(batchSize = 5, use = KeyUse.OneTime),   // HAIP 단일사용 배치
    )
)

// 3) 세션 상태 구동
session.state.collect { state ->
    when (state) {
        is IssuanceState.TxCodeRequired -> session.submitTxCode(promptUserForPin())
        is IssuanceState.Completed      -> render(state.result.issued)   // List<Credential>
        is IssuanceState.Failed         -> showError(state.error)        // WalletError.Issuance
        else -> Unit                                                     // Preparing / Processing / CredentialIssued(배치 증분)
    }
}
```

**중단점 없는 pre-auth라면** — 편의 확장으로 한 줄:
```kotlin
val result = wallet.issuance.start(request).await()   // 중단(txCode/브라우저) 필요 시 WalletError로 throw
```

```swift
let offer = try await wallet.issuance.resolveOffer(offerUri)
let session = wallet.issuance.start(.fromOffer(offer, accepted: offer.credentials,
    keySpec: KeySpec(userAuthentication: .required()),
    policy: CredentialPolicy(batchSize: 5, use: .oneTime)))

for await state in session.states {
    switch state {
    case .txCodeRequired:        try await session.submitTxCode(promptUserForPin())
    case .completed(let result): render(result.issued)
    case .failed(let error):     showError(error)
    default: break
    }
}
```

---

## 2. 발급 — authorization code (브라우저 중단점)

```kotlin
val session = wallet.issuance.start(IssuanceRequest.fromOffer(offer, accepted = offer.credentials))

session.state.collect { state ->
    when (state) {
        is IssuanceState.AuthorizationRequired -> openBrowser(state.authorizationUrl)  // 앱이 브라우저 오픈
        is IssuanceState.Completed             -> render(state.result.issued)
        is IssuanceState.Failed                -> showError(state.error)
        else -> Unit
    }
}

// 나중에, 브라우저가 redirectUri로 돌아오면 (딥링크 핸들러에서):
suspend fun onRedirect(uri: URL) {
    session.completeAuthorization(uri)   // 세션이 이어서 토큰교환→발급
}
```

wallet-initiated(오퍼 없이 이슈어 지정) 도 대칭:
```kotlin
val meta = wallet.issuance.issuerMetadata(IssuerRef("https://issuer.eudiw.dev"))
val session = wallet.issuance.start(IssuanceRequest.fromIssuer(meta.issuer, configurationIds = listOf("eu.europa.ec.eudi.pid.1")))
```

---

## 3. 발급 — deferred · reissue · notification

```kotlin
// deferred: 이슈어가 아직 준비 안 됨 → 크리덴셜이 Lifecycle.Deferred 로 저장됨
val cred = wallet.credentials.get(id)!!
if (cred.lifecycle is Lifecycle.Deferred) {
    val session = wallet.issuance.resumeDeferred(cred.id)   // 폴링 재시도 (issuance_pending이면 Failed(DeferredNotReady))
}

// reissue(갱신): 만료 임박 크리덴셜을 저장된 refresh token으로 재발급 (브라우저 없음)
if (cred.canReissue) {
    val session = wallet.issuance.reissue(cred.id)          // 새 키로 로테이션 발급
}

// notification: 저장 성공/실패를 이슈어에 통지 (발급 세션 Completed 시 SDK가 자동 CREDENTIAL_ACCEPTED,
//               삭제 시 CREDENTIAL_DELETED — 앱이 명시 호출도 가능)
wallet.credentials.notifyIssuer(cred.id, NotificationEvent.CredentialAccepted)
```

---

## 4. 크리덴셜 관리

```kotlin
val all = wallet.credentials.list()                        // List<Credential>
val pid = wallet.credentials.list(CredentialFilter.byVct("eu.europa.ec.eudi.pid.1")).firstOrNull()

pid?.let { c ->
    c.claims.forEach { println("${it.path} = ${it.value.display()}") }   // path 기반 포맷 불문 뷰
    println("valid: ${(c.lifecycle as Lifecycle.Issued).validity.validUntil}")
    println("남은 단일사용 인스턴스: ${c.lifecycle.instances.remaining}")
}

val status = wallet.credentials.status(pid!!.id)           // VALID / INVALID(revoked) / SUSPENDED — Token Status List
wallet.credentials.delete(pid.id)                          // 삭제 (+ 자동 CREDENTIAL_DELETED 통지)

// 리액티브 목록 갱신
wallet.credentials.changes.collect { refreshUi() }         // Added/Updated/Removed
```

---

## 5. 원격 제시 (OpenID4VP)

```kotlin
val session = wallet.presentation.start(requestUri)        // openid4vp:// 딥링크/QR 내용물

session.state.collect { state ->
    when (state) {
        is PresentationState.RequestResolved -> {
            val req = state.request
            // ── 동의 화면 데이터 (불변) ──
            //   req.verifier.trust  → VerifierTrust(신뢰여부·정책판정·CN·메시지)
            //   req.queries         → 쿼리별 요청 claim + 매칭된 보유 후보(candidates)
            //   req.transactionData → 있으면 트랜잭션 확인 UI

            if (!req.verifier.trust.isTrusted) showUntrustedWarning(req.verifier)

            // 사용자가 쿼리별 크리덴셜 선택 → 선택 제출
            val selection = PresentationSelection.auto(req)          // 또는 수동 매핑
            //   = PresentationSelection(chosen = mapOf("query_0" to chosenCredId))
            session.respond(selection)                              // consume→제시→txlog 기록
            // 필수 claim을 빼면 respond가 WalletError.Presentation.SelectionIncomplete
        }
        is PresentationState.Completed -> state.redirectUri?.let { follow(it) }  // 동적 발급 체인
        is PresentationState.Declined  -> Unit
        is PresentationState.Failed    -> showError(state.error)
        else -> Unit                                               // ResolvingRequest / Submitting
    }
}

// 거절: session.decline()   (NegativeConsensus 전송)
```

```swift
let session = wallet.presentation.start(requestUri)
for await state in session.states {
    switch state {
    case .requestResolved(let req):
        if !req.verifier.trust.isTrusted { showUntrustedWarning(req.verifier) }
        try await session.respond(.auto(req))
    case .completed(let redirect): redirect.map(follow)
    case .failed(let error):       showError(error)
    default: break
    }
}
```

---

## 6. 근접 제시 (ISO 18013-5) — 같은 제시 모델 공유

```kotlin
val session = wallet.proximity.startEngagement(EngagementMethod.Qr)

session.state.collect { state ->
    when (state) {
        is ProximityState.EngagementReady -> renderQr(state.qrPayload)         // 앱이 QR 표시
        is ProximityState.RequestReceived -> {
            val req = state.request                                            // §5와 동일 PresentationRequest
            session.respond(PresentationSelection.auto(req))                   // 동일 선택 모델
        }
        is ProximityState.ResponseSent    -> showDone()
        is ProximityState.Disconnected    -> Unit
        is ProximityState.Failed          -> showError(state.error)
        else -> Unit                                                           // Connecting / Connected / SendingResponse
    }
}
// session.terminate()  — 세션 종료
```

→ **원격·근접의 동의/선택 코드가 하나로 수렴** (`PresentationRequest`/`PresentationSelection` 공유).

---

## 7. DC API (브라우저 Digital Credentials) — 플랫폼 어댑터가 진입 제공

```kotlin
// Android CredentialManager / iOS IdentityDocumentServices 어댑터가 플랫폼 요청을 코어로 번역:
val session = wallet.presentation.startDcApi(requestJson = platformRequest, origin = callerOrigin)
// 이후 상태 구동은 §5와 동일 (respond → 응답 객체를 어댑터가 플랫폼에 반환, HTTP POST 없음)
```

---

## 8. 리더/베리파이어 측 (dual-role — mdoc reader)

Wallet(holder)과 **같은 SDK**로 verifier(reader)도 만든다. 별도 파사드 진입:

```kotlin
val reader = wallet.reader                                 // 또는 Reader.create(config, ports)

// 1) DeviceRequest 생성 (+ readerAuth 서명)
val deviceRequest = reader.buildDeviceRequest(
    documents = listOf(RequestedDocument("eu.europa.ec.eudi.pid.1",
        elements = mapOf("eu.europa.ec.eudi.pid.1" to listOf("family_name", "age_over_18")))),
    sessionTranscript = transcript,
)

// 2) wallet 응답 검증 (issuerAuth 신뢰 + deviceSignature holder 바인딩)
val verified = reader.verifyDeviceResponse(deviceResponse, sessionTranscript = transcript)
verified.forEach { doc -> println("${doc.docType} 인증됨: ${doc.elements}") }
```

---

## 9. 에러 처리 — 타입드 계층

```kotlin
try {
    wallet.issuance.start(request).await()
} catch (e: WalletError.Issuance.AuthorizationFailed) {
    log(e.oauthError, e.code, e.diagnostics)               // 스펙 에러코드 원문 보존
} catch (e: WalletError.Issuance.TxCodeInvalid) {
    promptRetry()
} catch (e: WalletError) {
    // 공통: e.code(안정 식별자), e.diagnostics(타임스탬프·컨텍스트·원인체인, PII 없음)
}
// 세션 기반 플로우에선 Failed(error) 상태로 전달 (throw 대신).
```

---

## 인간공학 노트 (이 연습으로 발견 — 구현에 반영)

1. **`session.state.collect`는 선형 플로우에 무겁다.** pre-auth·reissue처럼 중단점 없는 경우가 흔하므로 **편의 `suspend fun IssuanceSession.await(): IssuanceResult`** 제공(중단 필요 시 throw). Swift는 `await session.result()`. → 계약에 추가 제안.
2. **`PresentationSelection.auto(request)`** 편의 필수 — 후보 1개뿐인 일반 케이스에서 앱이 매핑 안 짜게. (VP 모듈에 `PresentationSelection.auto`가 이미 있음 → 파사드 노출.)
3. **reissue가 계약 IssuanceService에 없음** — vci 클라이언트엔 구현됨. 파사드 `issuance.reissue(credentialId)` + `Credential.canReissue` 노출로 추가.
4. **notification 자동화 범위** — 발급 Completed 시 자동 `CredentialAccepted`, 삭제 시 자동 `CredentialDeleted`가 기본. 수동 `notifyIssuer`도 노출(§3). 계약에 자동화 규칙 명문화 필요.
5. **`Credential.claims`의 값 표시** — `ClaimValue.display()`가 포맷별(mdoc CBOR vs SD-JWT JSON) 값을 통일 문자열로. path는 `List<String>`(namespace+element / JSON path) 통일.
6. **reader 진입점** — `wallet.reader` 서브파사드 vs 독립 `Reader.create`. dual-role이므로 wallet과 포트 공유가 자연스러움 → `wallet.reader` 권장, 독립 생성도 허용.
7. **`filter`/`status`의 네트워크성** — `credentials.status()`는 네트워크(Status List fetch), `list()`는 로컬. 이름/시그니처로 비용 차이 드러나게(status는 suspend·throws 명확).

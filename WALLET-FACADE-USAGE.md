# Wallet 파사드 — 플로우별 사용 예시 (usage-driven design)

구현 전 API 인간공학 검증용. 각 플로우를 "개발자가 실제로 어떻게 쓸까"로 작성해 어색함을 드러낸다. Kotlin 주 + 헤드라인 플로우는 Swift 미러. 끝의 **인간공학 노트**가 이 연습으로 발견한 개선점.

---

## 0. 조립 (Assembly)

```kotlin
val wallet = Wallet.create(
    config = WalletConfig(
        issuance = IssuanceConfig(
            clientId = "eudi-wallet",
            clientAuth = ClientAuth.AttestationBased,      // WUA 사용 (SDK가 인스턴스 키·PoP·캐싱 자동) / 또는 ClientAuth.None
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
        storage = InMemoryStorage(),                      // 앱: 플랫폼 암호화 스토리지 어댑터 (암호화는 어댑터 소관)
        http = JdkHttpTransport(),
        walletAttestation = myWuaProvider,                // WP 백엔드 링크만 — 인스턴스 키·PoP·캐싱은 SDK 자동
    ),
)
// wallet은 스레드 세이프·멀티인스턴스. 앱 종료 시 wallet.close() (멱등).
// 횡단 관심사(저장·holder 키·WUA) = 앱은 얇은 포트만 주입, SDK가 lifecycle 자동 소유 (PLAN §6).
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

> **발급은 세션 단일 방식.** 간편 one-shot API는 제공하지 않는다 — 중단점(txCode·브라우저)이 흔하고, 한 가지 진입점이 API를 단순하게 유지한다. pre-auth처럼 중단이 없으면 세션이 `Preparing → Processing → Completed`로 즉시 흘러간다.

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

## 4. 크리덴셜 관리 — 메타데이터와 함께 저장/조회

발급 시점에 **이슈어 메타데이터(display·issuer 정보)를 봉투에 함께 캡처**해 보관한다. 앱은 재조회 없이 이름·로고를 쓴다.

```kotlin
class Credential {                        // CredentialEnvelope의 뷰
    val id: CredentialId
    val format: CredentialFormat          // MsoMdoc(docType) | SdJwtVc(vct)
    val lifecycle: Lifecycle              // Issued | Deferred | Pending
    val issuer: IssuerInfo                // url, displayName            ← 발급 시 캡처
    val display: CredentialDisplay?       // name, logo, backgroundColor ← issuer metadata display 유래
    val configurationId: String          // reissue·재조회용
    val createdAt: Instant
    // Lifecycle.Issued 전용: claims(path 뷰), validity, instances(배치 잔량·policy), payload(타입드 원본)
}
```

```kotlin
// ── 조회 (로컬, 네트워크 없음) ──
val all = wallet.credentials.list()                        // List<Credential>
val pid = wallet.credentials.list(CredentialFilter.byVct("eu.europa.ec.eudi.pid.1")).firstOrNull()

pid?.let { c ->
    println("${c.display?.name} — ${c.issuer.displayName}")             // 메타데이터로 카드 렌더
    (c.lifecycle as? Lifecycle.Issued)?.let { issued ->
        issued.claims.forEach { println("${it.path} = ${it.value.display()}") }   // path 기반 포맷 불문 뷰
        println("valid until ${issued.validity.validUntil}, 남은 단일사용 ${issued.instances.remaining}")
    }
}

// ── 상태 (네트워크 — Token Status List fetch) ──
val status = wallet.credentials.status(pid!!.id)           // VALID / INVALID(revoked) / SUSPENDED

// ── 삭제 · 리액티브 갱신 ──
wallet.credentials.delete(pid.id)                          // + 자동 CREDENTIAL_DELETED 통지
wallet.credentials.changes.collect { refreshUi() }         // Added/Updated/Removed
```

### 4b. DCQL로 크리덴셜 매칭 조회 (제시와 무관하게)

"이 DCQL 쿼리를 만족하는 보유 크리덴셜?" — 제시 세션을 안 열고도 조회. (내부적으로 제시가 쓰는 것과 같은 DcqlEngine.)

```kotlin
val result: CredentialMatch = wallet.credentials.match(dcqlQuery)   // DcqlQuery (JSON 파싱 or 빌더)

result.satisfiable                                         // 전체 쿼리 만족 가능?
result.byQuery.forEach { (queryId, candidates) ->
    candidates.forEach { cand ->
        cand.credential                                    // 매칭된 보유 Credential
        cand.disclosedPaths                                // 제시 시 공개될 claim path
    }
}

// 활용: 특정 verifier 쿼리를 지금 만족하는지 사전 체크, 홈 화면에서 "제시 가능한 크리덴셜" 필터 등
```

`list(filter)` = 단순 필터(vct/docType/format), `match(dcqlQuery)` = DCQL 의미론(credential_sets·claim_sets·null 와일드카드·values) 전체.

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

## 결정·인간공학 노트 (이 연습으로 확정 — 구현에 반영)

1. **발급 = 세션 단일 방식 확정.** 간편 one-shot/`await()` API는 **제공하지 않음**(진입점 하나로 단순 유지). 중단점 없는 pre-auth는 세션이 즉시 `Completed`로 흐른다.
2. **크리덴셜은 메타데이터와 함께 저장(중요).** 봉투에 발급 시점 `issuer`(url·displayName) + `display`(name·logo·color, issuer metadata display 유래) + `configurationId` 캡처 → 앱이 재조회 없이 카드 렌더·reissue. **→ 잠금결정 #3 개정: display 최소가 아니라 "발급 시 캡처한 메타데이터 보관".** 봉투 모델·CredentialConfiguration에 display 파싱 추가(Phase A).
3. **DCQL 크리덴셜 조회(중요).** `credentials.match(dcqlQuery): CredentialMatch` — 제시와 무관하게 보유 크리덴셜을 DCQL로 매칭(내부 DcqlEngine 재사용). `list(filter)`(단순)와 분리. 홈 화면 필터·사전 만족도 체크에 필수.
4. **`PresentationSelection.auto(request)`** 편의 필수 — 후보 1개인 일반 케이스에서 앱이 매핑 안 짜게. (VP 모듈에 이미 있음 → 파사드 노출.)
5. **reissue 노출** — vci엔 구현됨. 파사드 `issuance.reissue(credentialId)`(세션) + `Credential.canReissue`.
6. **notification 자동화** — 발급 Completed 시 자동 `CredentialAccepted`, 삭제 시 자동 `CredentialDeleted` + 수동 `notifyIssuer`.
7. **`ClaimValue.display()` / path 통일** — mdoc CBOR vs SD-JWT JSON 값을 통일 문자열로, path는 `List<String>` 통일(namespace+element / JSON path).
8. **reader 진입점** — `wallet.reader` 서브파사드(dual-role·포트 공유) + 독립 `Reader.create` 허용.
9. **비용 가시성** — `status()`는 네트워크(Status List), `list()`·`match()`는 로컬. 시그니처로 구분.

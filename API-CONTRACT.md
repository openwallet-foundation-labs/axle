# EUDI Wallet SDK — API 계약 v0

작성: 2026-07-04 · 상태: 초안 (리뷰용) · 기준: EUDI wallet-core 0.28.1 / wallet-kit 0.31.2 API 표면 분석
홈: `~/eudi-wallet-sdk` 레포 · `API-CONTRACT.md`

---

## 1. 레퍼런스 분석 요약 — EUDI 양 플랫폼 비교

| 축            | Android wallet-core                                                                                      | iOS wallet-kit                                                                                        | 우리 계약                                                                                   |
| ------------- | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| 비동기 스타일 | 콜백 + `Executor?` 파라미터(발급), 리스너(제시). Flow 전무                                               | async/await 위주, 단 `@Published`/ObservableObject 결합                                               | suspend/async + Flow/AsyncSequence로 통일                                                   |
| 파사드 구성   | `EudiWallet : DocumentManager, PresentationManager, DocumentStatusResolver` — 상속으로 합친 갓오브젝트   | `EudiWallet` 단일 클래스 + `StorageManager`/`PresentationSession` 분리                                | 네임스페이스드 파사드 (`wallet.issuance` / `.presentation` / `.proximity` / `.credentials`) |
| 타입 누출     | multipaz·openid4vci/vp·document-manager 타입이 퍼블릭 시그니처에 대량 노출 (3개 lib이 `api()` 의존)      | MdocDataModel18013 등 8개 모듈 타입 노출                                                              | **자체 타입만 노출** (전 스택 소유라 가능)                                                  |
| 플랫폼 결합   | `Context` 필수, `Intent`/`ComponentActivity`/`@RawRes` API                                               | SwiftUI/Combine 결합 (`@Published` 체크박스 모델), `LAContext` 내장                                   | 코어 무결합, 어댑터로 격리                                                                  |
| 발급 UX       | `IssueEvent` sealed 스트림 + resume/cancel 연속 콜백                                                     | 메서드별 분리, 글로벌 `OpenId4VCIServiceRegistry.shared` + issuerName 문자열 키                       | 세션 상태 머신 (레지스트리·문자열 키 없음)                                                  |
| 키/배치 모델  | `CreateDocumentSettings(secureAreaIdentifier, createKeySettings, numberOfCredentials, credentialPolicy)` | `KeyOptions(secureAreaName, curve, accessControl)` + `CredentialOptions(batchSize, credentialPolicy)` | 단일 `KeySpec` + `CredentialPolicy` (양 플랫폼 동일 명명)                                   |
| 에러 모델     | `Throwable cause` 실어나르기 + `Result`/`Outcome` 혼용                                                   | `WalletError(description, code?, context)` 평면 구조                                                  | 도메인별 sealed 에러 + 스펙 에러코드 1:1                                                    |

## 2. Keep / Change / Drop

### Keep (EUDI가 잘한 것 — 개념 유지)

| 항목                                                                                     | 근거                                                                |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| 문서 수명주기 3태 (issued / deferred / pending)                                          | 양 플랫폼 공통 검증된 모델. `Credential.lifecycle`로 유지           |
| `CredentialPolicy` OneTimeUse/RotateUse + 배치 발급                                      | HAIP 단일사용 키(RP 연결불가성) 요구의 정석 구현                    |
| `ReaderAuthPolicy` (DoNotEnforce / EnforceIfPresent / AlwaysRequire)                     | verifier 인증 정책의 좋은 3단계 모델                                |
| 오퍼 2단계 플로우 (resolve → 사용자 선택 → issue) + txCode                               | UX 요구와 정확히 일치                                               |
| 브라우저 리다이렉트 재개 (`resumeWithAuthorization`)                                     | auth code flow의 필수 훅. 세션 메서드로 유지                        |
| `WalletAttestationsProvider` 추상화                                                      | WUA(wallet attestation)는 월렛 프로바이더 백엔드 소관 — 포트로 승격 |
| 트랜잭션 로그 콘텐츠 모델 (rawRequest/rawResponse/sessionTranscript/relyingParty/status) | ARF 요구 충족에 필요한 필드 구성 그대로                             |
| 상태 확인 clock skew 옵션                                                                | 실무 필수                                                           |
| verifier 신뢰 결과를 요청과 함께 앱에 노출 (readerCertIssuer, isTrusted, 메시지)         | 동의 화면에 필수인 정보                                             |

### Change (개념은 유지, 형태 교체)

| 항목              | EUDI                                                    | 우리                                                                    |
| ----------------- | ------------------------------------------------------- | ----------------------------------------------------------------------- |
| 비동기 모델       | 콜백+Executor / 리스너 / @Published 혼재                | suspend·async 함수 + `Flow`/`AsyncSequence` 세션 상태                   |
| 발급 중단점       | `DocumentRequiresUserAuth(resume:, cancel:)` 연속 콜백  | 세션 상태 + 어댑터 내 인증 처리 (§6.2)                                  |
| 제시 이벤트       | `TransferEvent` 9종 멀티플렉스 리스너                   | 플로우별 타입드 상태 머신 (`PresentationState`, `ProximityState`)       |
| 동의/선택 UI 모델 | iOS: `@Published isSelected` 체크박스 트리를 SDK가 제공 | 불변 `CredentialMatch` 데이터만 제공, UI 모델은 앱 소관 (헤드리스 원칙) |
| 발급자 참조       | iOS: issuerName 문자열 + 글로벌 레지스트리              | `IssuerRef(url)` 값 타입, 인스턴스 스코프 캐시                          |
| 설정              | Android: mutator 있는 준가변 config / iOS: public var   | 불변 `WalletConfig` 데이터 클래스 + 포트 주입                           |
| 문서 CRUD 위치    | 파사드가 DocumentManager를 상속                         | `wallet.credentials` 서브 API로 격리                                    |
| 키 옵션           | 플랫폼별 상이 (위 표)                                   | `KeySpec`/`CredentialPolicy` 단일 모델                                  |
| 결과 래핑         | `Result`/`Outcome`/예외 혼용                            | Kotlin: 타입드 예외 / Swift: `throws` — Result 래퍼 금지                |

### Drop (v0에서 제외)

| 항목                                                                                | 이유                                                                |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `Executor` 파라미터, `Intent`/`Uri` 코어 API, `@RawRes` 오버로드                    | 코어 순수성. Intent/딥링크 해석은 Android 어댑터가 코어 호출로 번역 |
| ObservableObject/`@Published` (코어)                                                | 헤드리스. SwiftUI 브리지는 향후 별도 모듈(`eudi-wallet-sdk-swiftui`)   |
| 글로벌 레지스트리 (`OpenId4VCIServiceRegistry.shared`, `SecureAreaRegistry.shared`) | 멀티 인스턴스 지원 + 테스트 격리                                    |
| `api()` 전이 노출, 의존성 타입 누출                                                 | 전부 `implementation`/internal. 퍼블릭 API는 자체 타입만            |
| `@IntDef` 플래그, deprecated docType 발급 경로                                      | Kotlin enum/sealed로                                                |
| ZKP 표면 (`zkSystemRepository`)                                                     | M7+. 확장 포인트 슬롯만 예약                                        |
| SIOP                                                                                | VP 1.0 기준 불필요 (EUDI도 이미 제거 수순)                          |

## 3. 캡슐화 규칙 (계약의 제1원칙)

퍼블릭 API에는 **자체 타입과 표준 라이브러리 타입만** 등장한다. 금지: 플랫폼 타입(Context, Intent, Activity, LAContext, SwiftUI), 내부 구현 타입, 서드파티 타입. 예외: `X509Certificate`(JVM java.security / Swift는 자체 `Certificate` 타입 제공 — swift-certificates 타입도 노출 금지), `URL`, 시간 타입(kotlinx `Instant` / Foundation `Date`).

효과: 내부 구현(파서, 크립토, 프로토콜 엔진)을 semver 부담 없이 교체 가능. EUDI의 최대 실패 지점(의존성 버전업 = 고객 API 파손)을 원천 차단.

## 4. 코어 개념 모델

```kotlin
// 식별자 — 전부 값 타입 (stringly-typed 금지)
@JvmInline value class CredentialId(val value: String)
@JvmInline value class IssuerRef(val url: String)

// 포맷
sealed interface CredentialFormat {
    data class MsoMdoc(val docType: String) : CredentialFormat
    data class SdJwtVc(val vct: String) : CredentialFormat
}

// 크리덴셜 (포맷 불문 단일 모델)
class Credential {
    val id: CredentialId
    val format: CredentialFormat
    val lifecycle: Lifecycle           // sealed: Issued | Deferred | Pending
    val display: CredentialDisplay     // 이름·로고 등 issuer metadata 유래
    val issuer: IssuerInfo
    val createdAt: Instant
    // Issued 전용 (Lifecycle.Issued에 탑재)
    //   claims: List<Claim>            — path 기반 포맷 불문 뷰
    //   validity: ValidityInfo         — validFrom/validUntil
    //   credentials: CredentialInstances — 배치 잔량/사용 카운트, policy
    //   payload: FormatPayload         — 타입드 원본 접근 (MsoMdocPayload | SdJwtVcPayload)
}

sealed interface Lifecycle {
    data class Issued(val claims: List<Claim>, val validity: ValidityInfo,
                      val instances: CredentialInstances, val payload: FormatPayload) : Lifecycle
    data class Deferred(val retryAfter: Instant?) : Lifecycle
    data class Pending(val authorizationUrl: URL?) : Lifecycle   // 동적 발급 재개용
}

data class Claim(val path: ClaimPath, val value: ClaimValue, val display: ClaimDisplay?)

// 키·배치 (양 플랫폼 동일 명명 — EUDI의 KeyOptions/CreateDocumentSettings 이원화 통합)
data class KeySpec(
    val secureArea: SecureAreaId = SecureAreaId.default,
    val algorithm: SigningAlgorithm = SigningAlgorithm.ES256,
    val userAuthentication: UserAuthPolicy = UserAuthPolicy.NotRequired,  // | Required(timeout)
    val hardware: HardwarePolicy = HardwarePolicy.Preferred,             // | Required | Software
    val attestationChallenge: ByteArray? = null,
)
data class CredentialPolicy(
    val batchSize: Int = 1,
    val use: KeyUse = KeyUse.Rotate,   // | OneTime  (HAIP 권장: OneTime + batch)
)
```

## 5. 파사드 구조

```kotlin
interface Wallet : AutoCloseable {
    val credentials: CredentialStore        // 조회·삭제·상태
    val issuance: IssuanceService           // OpenID4VCI
    val presentation: PresentationService   // OpenID4VP 원격
    val proximity: ProximityService         // ISO 18013-5
    val events: Flow<WalletEvent>           // 전역 이벤트 (트랜잭션 로그 소스)

    companion object {
        fun create(config: WalletConfig, ports: WalletPorts): Wallet
    }
}

// 조립 — 코어는 순수, 어댑터 아티팩트가 기본 포트 제공
data class WalletPorts(
    val secureArea: List<SecureArea>,          // 첫 번째가 기본
    val storage: StorageDriver,
    val http: HttpTransport,
    val deviceChannels: List<DeviceChannelFactory> = emptyList(),  // proximity 미사용시 생략
    val walletAttestation: WalletAttestationProvider? = null,      // WUA — 없으면 attestation 요구 이슈어와 상호작용 불가
    val clock: Clock = Clock.system, val rng: Rng = Rng.system, val logger: WalletLogger? = null,
)
```

Swift 미러:

```swift
public final class Wallet {
    public let credentials: CredentialStore
    public let issuance: IssuanceService
    public let presentation: PresentationService
    public let proximity: ProximityService
    public var events: AsyncStream<WalletEvent> { get }
    public init(config: WalletConfig, ports: WalletPorts) throws
}
```

- 멀티 인스턴스 허용 (글로벌 상태 전무). `close()`는 멱등.
- `WalletConfig`: 불변. `TrustConfig(readerRoots, issuerRoots, readerAuthPolicy)`, `IssuanceConfig(clientAuth: None(clientId)|AttestationBased, redirectUri, par: Required|IfSupported|Never = Required, dpop: … = Required)`, `PresentationConfig(clientIdPrefixes = [x509SanDns, x509Hash, redirectUri], responseEncryption)`, `ProximityConfig(bleRole = Peripheral, …)`. HAIP 기본값(PAR·DPoP Required)이 디폴트.

## 6. 플로우 API

### 6.1 발급 (OpenID4VCI)

```kotlin
interface IssuanceService {
    suspend fun resolveOffer(offerUri: String): CredentialOffer          // 2단계 플로우 1단
    suspend fun issuerMetadata(issuer: IssuerRef): IssuerMetadata        // wallet-initiated 탐색

    fun start(request: IssuanceRequest): IssuanceSession
    // IssuanceRequest.fromOffer(offer, accepted: List<OfferedCredential>, txCode: String? = null,
    //                           keySpec: KeySpec = default, policy: CredentialPolicy = default)
    // IssuanceRequest.fromIssuer(issuer, configurationIds: List<String>, keySpec, policy)

    fun resumeDeferred(credentialId: CredentialId): IssuanceSession      // deferred 재시도
    fun resumePending(credentialId: CredentialId, redirectUri: URL?): IssuanceSession
}

interface IssuanceSession {
    val state: StateFlow<IssuanceState>
    suspend fun completeAuthorization(redirectUri: URL)   // 브라우저 복귀 시 앱이 호출
    suspend fun submitTxCode(code: String)
    fun cancel()
}

sealed interface IssuanceState {
    data object Preparing : IssuanceState
    data class AuthorizationRequired(val authorizationUrl: URL) : IssuanceState  // 앱: 브라우저 열기
    data object TxCodeRequired : IssuanceState
    data object Processing : IssuanceState
    data class CredentialIssued(val credential: Credential) : IssuanceState      // 배치 중 증분 통지
    data class Completed(val result: IssuanceResult) : IssuanceState  // issued/deferred/failed 리스트
    data class Failed(val error: WalletError.Issuance) : IssuanceState
}
```

Swift: `IssuanceSession.states: AsyncStream<IssuanceState>` + `private(set) var currentState`, 나머지 동형.

EUDI 대비: `IssueEvent`의 resume/cancel 연속 콜백(`DocumentRequiresUserAuth`, `DocumentRequiresCreateSettings`)이 사라진다 — 키 생성 설정은 요청 시점에 `KeySpec`으로 선결정, 사용자 인증은 §6.2의 어댑터 처리.

### 6.2 사용자 인증(생체) 처리 규칙

키 unlock은 **SecureArea 어댑터의 소관**이다. 코어는 서명 요청에 `AuthorizationHint(promptTitle, promptSubtitle)`만 첨부하고, 어댑터가 BiometricPrompt(Android)/LAContext(iOS)를 띄운다. 앱은 `KeyUnlockData`를 만들거나 나를 일이 없다 (EUDI Android의 `getDefaultKeyUnlockData` 체인 제거). Android 어댑터는 생성 시 `ActivityProvider`를 받아 프롬프트를 띄운다 — 코어 계약에는 등장하지 않음.

### 6.3 원격 제시 (OpenID4VP)

```kotlin
interface PresentationService {
    fun start(requestUri: String): PresentationSession   // openid4vp:// deeplink/QR 내용물
}

interface PresentationSession {
    val state: StateFlow<PresentationState>
    suspend fun respond(selection: PresentationSelection)
    suspend fun decline()                                 // NegativeConsensus 전송
    fun cancel()                                          // 무응답 종료
}

sealed interface PresentationState {
    data object ResolvingRequest : PresentationState
    data class RequestResolved(val request: PresentationRequest) : PresentationState  // 동의 화면 데이터
    data object Submitting : PresentationState
    data class Completed(val redirectUri: URL?) : PresentationState   // 동적 발급 체인용
    data object Declined : PresentationState
    data class Failed(val error: WalletError.Presentation) : PresentationState
}

// 동의 화면에 필요한 전부 — 불변 데이터 (UI 모델 아님)
class PresentationRequest {
    val verifier: VerifierInfo            // name, trust: VerifierTrust(chain검증 결과·정책 판정·메시지)
    val queries: List<CredentialQuery>    // DCQL 쿼리별:
    //   query.id, query.requestedClaims: List<RequestedClaim(path, intentToRetain, values?)>
    //   query.candidates: List<Credential>  ← DCQL 매칭 통과한 보유 크리덴셜
    //   query.required: Boolean              ← credential_sets 반영
    val transactionData: List<TransactionData>?
}

class PresentationSelection {  // queryId → 선택한 credentialId (+ optional 쿼리 제외)
    // claim 단위 부분 제출 없음: DCQL이 요구한 claim은 전부 공개하거나 해당 쿼리를 거절하거나 둘 중 하나.
    // 요청 항목의 선택성은 verifier가 claim_sets/credential_sets로 표현하는 것이 스펙의 방식이며 그쪽을 지원.
    // (18013-5 근접은 프로토콜에 부분 응답(문서별 errors 구조)이 있으므로 근접 한정 재검토는 M5에서)
}
```

### 6.4 근접 제시 (ISO 18013-5)

```kotlin
interface ProximityService {
    fun startEngagement(method: EngagementMethod = EngagementMethod.Qr): ProximitySession
}

interface ProximitySession {
    val state: StateFlow<ProximityState>
    suspend fun respond(selection: PresentationSelection)
    suspend fun decline()
    suspend fun terminate(mode: TerminationMode = TerminationMode.SessionTermination)
}

sealed interface ProximityState {
    data class EngagementReady(val qrPayload: String) : ProximityState  // 앱이 QR 렌더
    data object Connecting : ProximityState
    data object Connected : ProximityState
    data class RequestReceived(val request: PresentationRequest) : ProximityState  // §6.3와 동일 모델
    data object SendingResponse : ProximityState
    data object ResponseSent : ProximityState
    data class Disconnected(val reason: DisconnectReason) : ProximityState
    data class Failed(val error: WalletError.Proximity) : ProximityState
}
```

원격/근접이 **같은 `PresentationRequest`/`PresentationSelection` 모델을 공유** — 앱의 동의 화면 코드가 하나로 수렴 (EUDI는 `RequestedDocuments`+`DocItem` vs `DocElements` 로 플랫폼·플로우마다 상이).

### 6.5 크리덴셜 관리

```kotlin
interface CredentialStore {
    suspend fun list(filter: CredentialFilter = CredentialFilter.all): List<Credential>
    suspend fun get(id: CredentialId): Credential?
    suspend fun delete(id: CredentialId)
    suspend fun status(id: CredentialId): CredentialStatus     // Token Status List 조회 (clockSkew는 config)
    val changes: Flow<CredentialStoreChange>                   // 목록 갱신 리액티브 소스
}
```

## 7. 포트 SPI (호스트 주입)

```kotlin
interface SecureArea {
    val id: SecureAreaId
    val capabilities: SecureAreaCapabilities   // 지원 알고리즘, 하드웨어 여부, userAuth 지원, attestation 지원
    suspend fun createKey(spec: KeySpec): KeyInfo              // handle + 공개키 (proof 작성에 항상 필요)
    suspend fun publicKey(key: KeyHandle): EcPublicKey
    suspend fun sign(key: KeyHandle, algorithm: SigningAlgorithm, data: ByteArray, hint: AuthorizationHint?): ByteArray
    suspend fun keyAgreement(key: KeyHandle, peerPublicKey: EcPublicKey, hint: AuthorizationHint?): ByteArray
    suspend fun attestation(key: KeyHandle, challenge: ByteArray): KeyAttestation?
    suspend fun deleteKey(key: KeyHandle)
}

interface StorageDriver {          // 도메인 로직 없음 — 암호화 블롭 저장만
    suspend fun put(collection: String, key: String, value: ByteArray)
    suspend fun get(collection: String, key: String): ByteArray?
    suspend fun delete(collection: String, key: String)
    suspend fun keys(collection: String): List<String>
    suspend fun transaction(block: suspend StorageTx.() -> Unit)
}

interface HttpTransport {
    suspend fun execute(request: HttpRequest): HttpResponse   // redirect 정책은 request 플래그
}

interface DeviceChannelFactory {   // 18013-5 전송 계층
    val method: RetrievalMethod                                // BleServer | BleClient | Nfc | ...
    suspend fun open(session: ChannelSessionInfo): DeviceChannel
}
interface DeviceChannel {
    suspend fun send(data: ByteArray)
    val incoming: Flow<ByteArray>
    suspend fun close()
}

interface WalletAttestationProvider {   // 월렛 프로바이더 백엔드 (WUA)
    suspend fun walletAttestation(keyInfo: KeyInfo): String                       // WUA JWT
    suspend fun keyAttestation(keys: List<KeyInfo>, nonce: String?): String
}
```

v0.1 (2026-07-04): 포트 SPI를 코드로 확정 — `kotlin/wallet-api` · `swift/Sources/WalletAPI`. 코드화하며 두 가지 변경: `createKey`는 `KeyInfo`(handle+공개키) 반환, `publicKey(key)` 조회 추가 — proof 작성에 공개키가 항상 필요해서. peer 키 타입은 `EcPublicKey`로 통일.

계약 테스트 스위트가 포트별로 제공된다 (`testkit`): 같은 스위트를 CI에선 `SoftwareSecureArea`/인메모리 구현으로, 디바이스 랩에선 실제 어댑터로 실행. **어댑터 자격 = 계약 테스트 통과.**

메모: 플랜 §4의 `PresentationConsent` 포트는 세션 상태 머신(§6.3)으로 흡수 — 동의는 주입이 아니라 세션 상호작용. 대신 `WalletAttestationProvider`가 포트로 승격.

## 8. 에러 모델

```kotlin
sealed class WalletError : Exception() {
    abstract val code: ErrorCode              // 안정적 식별자 (문서화·로깅·i18n 키)
    abstract val diagnostics: Diagnostics     // 타임스탬프, 요청 컨텍스트, 원인 체인 (PII 없음)

    sealed class Issuance : WalletError()     // InvalidOffer, IssuerUnreachable, AuthorizationFailed(oauthError),
                                              // CredentialRequestFailed(vciError), DeferredNotReady, TxCodeInvalid ...
    sealed class Presentation : WalletError() // InvalidRequest, VerifierNotTrusted(policy, chain), QueryNotSatisfiable(missing),
                                              // SelectionIncomplete(missingClaims), ResponseRejected(vpError), TransactionDataUnsupported ...
    sealed class Proximity : WalletError()    // ChannelUnavailable(reason), SessionEncryptionFailed, ReaderAuthFailed ...
    sealed class Credential : WalletError()   // NotFound, KeyInvalidated, NoUsableInstance(exhausted one-time keys) ...
    sealed class Key : WalletError()          // UserAuthDenied, UserAuthCanceled, HardwareUnavailable ...
    sealed class Trust : WalletError()        // ChainValidationFailed, TrustSourceUnavailable ...
}
```

- OAuth/VCI/VP 스펙 에러코드는 해당 케이스의 프로퍼티로 원문 보존 (`oauthError: "invalid_grant"` 등).
- Swift 미러: `WalletError: Error` enum 계층, 케이스·프로퍼티 동일 명명.
- 규칙: suspend/async 함수는 `WalletError`만 던진다. 세션은 `Failed(error)` 상태로 전달. Result 래퍼 금지.

## 9. 동시성·수명 규칙

1. 모든 suspend/async API는 메인 스레드에서 호출해도 안전 (내부 디스패치). 코어는 `@MainActor`/main-thread 훅 없음 — UI 스레드 홉은 앱 소관.
2. 취소는 구조적: Kotlin Job/Swift Task 취소가 진행 중 네트워크·채널 작업까지 전파. 세션 `cancel()` 멱등.
3. 세션은 1회용 — 완료/실패 후 재사용 불가, 새로 시작.
4. `Wallet`은 스레드 세이프. 동시 세션 허용 (단 proximity는 채널당 1개).

## 10. 오픈 퀘스천 (리뷰 시 결정)

1. ~~네이밍/패키지~~ → **확정 (2026-07-04)**: 제품명 **EUDI Wallet SDK**. Kotlin 패키지 `com.hopae.eudi.wallet`, Swift 모듈 `EudiWalletSDK`, 파사드 타입은 `Wallet`(패키지/모듈이 구분자 — ref 구현의 `EudiWallet` 클래스명과 충돌 회피). 아티팩트: `eudi-wallet-sdk-core` / `-android` / `-apple`.
2. ~~`allowPartialDisclosure`~~ → **확정 (2026-07-04): 드랍.** 부분 제출은 DCQL 의미론상 쿼리 불만족 → verifier가 거절하는 게 정상이라 기능 가치가 없음. 요청 항목의 선택성은 verifier가 `claim_sets`/`credential_sets`로 표현하는 게 스펙의 방식이고 그쪽을 온전히 지원. 사용자가 필수 claim을 빼려 하면 조용히 미제출(Android ref 앱의 동작)이 아니라 `SelectionIncomplete` 타입드 에러로 명시 피드백.
3. **Android 생체 프롬프트 플러밍**: 어댑터 `ActivityProvider` 방식 vs 앱 콜백 방식 — 어댑터 설계 시 결정.
4. **`events`/트랜잭션 로그의 영속 책임**: 코어가 StorageDriver에 저장 vs 앱이 Flow 구독해 자체 저장. v0: 코어 저장 + 조회 API 제공 쪽으로 기울어 있음 (ARF 요구 충족을 SDK가 보장).
5. ~~DC API~~ → **확정 (2026-07-04): 정식 스코프 편입 (플랜 M5b).** 플랫폼 종속은 등록/ingress(Android CredentialManager registry, iOS 26 IdentityDocumentServices 익스텐션)에 국한 — 요청 파싱·DCQL 매칭·응답 생성은 코어 openid4vp 엔진 재사용, DC API Handover용 SessionTranscript 변형은 M4에서 구현. Android 어댑터 선행.

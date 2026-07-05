# Wallet 통합 파사드 — 설계 플랜

API-CONTRACT.md가 **무엇을(API 표면)** 정의한다면, 이 문서는 **어떻게(실제 모듈 위에 조립)** + **어떤 순서로** 를 정의한다. 조사 기준: 2026-07-05, 모든 프로토콜 모듈 구현 완료(HAIP 발급 프로파일·mdoc·trust·status·txlog).

## 0. 모듈 배치

새 최상위 모듈 **`wallet`** (의존 그래프 꼭대기). `wallet-api`(SPI/값타입)는 그대로 두고, `wallet`이 그 위 + 모든 프로토콜 모듈에 의존한다.

```
wallet (파사드) ──▶ wallet-api, credential-store, openid4vci, openid4vp, mdoc, sdjwt, trust, txlog, statuslist
```

퍼블릭 API에는 자체 타입 + 표준 타입만 노출(계약 §3). 프로토콜 모듈 타입(Openid4VciClient, ResolvedRequest 등)은 `implementation` 의존으로 감춘다.

## 1. 재활용 — credential-store가 이미 하는 일

파사드가 재발명하지 **않는다**. 스토어가 이미 제공:
| 계약 개념 | 스토어 구현 |
|---|---|
| `Credential.lifecycle` (Issued/Deferred/Pending) | `EnvelopeLifecycle` 동형 |
| `CredentialInstances` (배치 잔량·useCount·policy) | `CredentialInstance(key, payload, useCount)` + `Issued.policy` |
| OneTime/Rotate 소비 | `consumeInstance(id)` — 정책대로 선택·변이 |
| `credentials.changes` 리액티브 | `CredentialStore.changes: SharedFlow` |

→ 파사드 `Credential`은 `CredentialEnvelope`의 **얇은 뷰**(payload를 claims로 파싱)일 뿐.

## 2. 파사드가 흡수할 조립 갭 (11개)

각 모듈 클라이언트는 순수(SecureArea·storage·trust·txlog·status를 안 건드림). 파사드가 오케스트레이션 소유:

1. **키 빌드**: `SecureArea.createKey(KeySpec)×batchSize` → `SecureAreaJwsSigner` → `IssuanceKeys(+additionalProofKeys)`
2. **영속**: `CredentialResponse.credentials` → `CredentialEnvelope`(instances 바인딩) → `store.save`
3. **follow-up 컨텍스트**: reissue/deferred/notification이 이전 `CredentialResponse`(accessToken·refreshToken·txId 등) 필요 → 앱 재시작 넘어 `Envelope.Deferred.transactionContext`/`Pending.resumeContext` 불투명 바이트로 직렬화
4. **clock/rng 브리지**: 클라이언트는 `()->Long`(epoch초), SPI는 `WalletClock.now():Instant` → `{ clock.now().epochSecond }`
5. **HAIP 조립 + WUA 인스턴스 키 소유**: SDK가 인스턴스 키 생성·보관(storage `wallet-instance`)·재사용, `walletAttestation` 호출·캐싱, PoP 서명. 앱은 `WalletAttestationProvider` + `clientAuth=AttestationBased`만 (§6)
6. **store→PresentableCredential**: envelope payload를 `SdJwt`/`IssuerSigned`로 파싱 → `HeldSdJwtVc`/`HeldMdoc`(signer 바인딩) → match·respond 양쪽에 전달
7. **usage 카운팅**: `consumeInstance`로 인스턴스 선택 → 그 payload/key로 Held 빌드 → 실패 시 보정(OneTime 롤백)
8. **VP 3스텝 루프**: resolveRequest→match→selection→respond를 세션으로 감쌈 (기존 PresentationSession은 SD-JWT 전용·internal 생성자 → 새로)
9. **ID 브리지**: `CredentialId(String)` ↔ VP `credentialId: String`
10. **txlog/status 자동 호출**: 발급·제시 후 `recordIssuance`/`recordPresentation`, 유효성 확인 시 `StatusListClient.check`
11. **trust fan-out**: 한 `X509ChainValidator`(앵커풀별) → 4 어댑터(`X509RequestVerifier`→VP, `X5cIssuerKeyResolver`→SD-JWT+status, `X5cMdocIssuerTrust`→mdoc, `X5cMdocReaderTrust`→proximity[별도 reader-CA 앵커])

## 3. 단계별 구현 플랜

각 단계는 Linux에서 `SoftwareSecureArea`+인메모리 storage+MockIssuer/MockVerifier로 e2e 테스트 가능. 각 단계 끝에 Kotlin+Swift 페어 + 골든 벡터(해당 시).

### Phase A — 조립 + 메타데이터 리치 Credential 저장/조회 + credentials 서비스
- `Wallet` / `WalletConfig`(불변) / `WalletPorts`(어댑터 주입) / `Wallet.create(config, ports)` 조립기 (trust fan-out·clock 브리지·클라이언트 생성 = 갭 4·11)
- **봉투 메타데이터 확장**: `CredentialEnvelope`에 `metadata`(issuer url·displayName, display name·logo·color, configurationId) 필드 + `CredentialConfiguration` display 파싱. 발급 시 캡처.
- 통합 `Credential` + `Lifecycle` + `Claim`(path 뷰) + `issuer`/`display` — `CredentialEnvelope`→`Credential` 변환 (payload를 SD-JWT/mdoc claims로)
- `credentials` 서비스: `list(filter)` · `get` · `delete` · `status`(`StatusListClient.check`) · `changes` + **`match(dcqlQuery)`**(DcqlEngine 재사용, 제시 무관 조회)
- **검증 슬라이스**: 봉투(메타데이터 포함) 저장→list→Credential 뷰(claims·display)→`match(dcql)` 조회→status

### Phase B — issuance 서비스
- `IssuanceService`(resolveOffer/start/resumeDeferred/resumePending) + `IssuanceSession`(StateFlow<IssuanceState>)
- pre-auth(1샷)·auth-code(브라우저 중단점 completeAuthorization)·txCode·batch·deferred·notification·reissue를 상태머신으로 (갭 1·2·3·5·10)
- **검증 슬라이스**: MockIssuer로 pre-auth+auth-code 발급→봉투 저장→credentials에 등장. 라이브 e2e는 EUDI 인증서 복구 후.

### Phase C — presentation 서비스
- `PresentationService.start` + `PresentationSession`(StateFlow<PresentationState>) + 통합 `PresentationRequest`/`PresentationSelection`
- store→Held* 빌드·match·consumeInstance·respond·txlog (갭 6·7·8·9·10), SD-JWT+mdoc 양 포맷
- **검증 슬라이스**: MockVerifier로 요청 해석→후보 매칭→선택→제시→txlog 기록

### Phase D — proximity + DC API 진입 + events + 에러 폴리시
- `ProximityService`(DeviceChannel 포트 위 — 크립토 코어는 proximity 모듈 완비)
- DC API 진입(resolveDcApiRequest/respondDcApi 래핑; 플랫폼 등록은 어댑터)
- `events: Flow<WalletEvent>` (txlog + store.changes 소스)
- `WalletError` 계층 매핑 (VciException/VpException/TrustException → 타입드)

## 4. 결정 (2026-07-05 확정 — "설계만 확정")

1. **구현 순서**: **A → B → C → D** 확정. 착수 범위(어디까지 지금)는 구현 시작 시 재결정 — 이 문서는 설계 잠금까지.
2. **발급 = 세션 단일 방식**: ✅ StateFlow(Kotlin)/AsyncStream(Swift) 세션만. **간편 one-shot/`await()` API는 제공 안 함**(진입점 하나로 단순 유지, 2026-07-05 확정). 중단점 없는 pre-auth는 세션이 즉시 `Completed`로 흐름. auth-code·txCode·consent만 실제 중단.
3. **크리덴셜 = 메타데이터와 함께 저장** (개정, 중요): ✅ 발급 시점에 `issuer`(url·displayName) + `display`(name·logo·color) + `configurationId`를 봉투에 **캡처·보관** → 앱이 재조회 없이 카드 렌더·reissue. (이전 "display 최소 드랍"에서 개정 — 메타데이터 관리가 핵심 요구.) 봉투 모델 + `CredentialConfiguration` display 파싱 추가 = Phase A.
4. **DCQL 크리덴셜 조회** (중요): ✅ `credentials.match(dcqlQuery): CredentialMatch` — 제시와 무관하게 보유를 DCQL로 매칭(내부 DcqlEngine 재사용). `list(filter)`(단순 필터)와 분리 = Phase A.
5. **events/txlog 영속**: ✅ **코어가 StorageDriver 영속** + 조회 API(계약 §10.4). `events: Flow<WalletEvent>`는 txlog append + store.changes 병합.
6. **에러 매핑**: ✅ **점진** — 각 Phase에서 해당 도메인 에러만 `WalletError.{...}`로 매핑. Phase D 최종 정합.
7. **모듈**: ✅ 새 최상위 `wallet` 모듈(§0). `wallet-api`는 SPI로 유지.

설계 잠금. 구현 착수 시 §3 Phase A(조립 + **메타데이터 리치 Credential 저장/조회** + **DCQL 매칭** + status)부터.

## 5. 열린 리스크

- **follow-up 컨텍스트 직렬화**(갭 3): `CredentialResponse`의 internal `withContext` 필드를 봉투 불투명 바이트로 왕복시키는 코덱 필요 — deferred/reissue의 앱 재시작 내구성.
- **claims 파싱 이중화**: SD-JWT는 sdjwt, mdoc은 mdoc 모듈이 파싱 — `Credential.claims` path 뷰를 양 포맷 통일 매핑.
- **Swift 병행**: 각 Phase를 Kotlin/Swift 페어로 — 세션의 StateFlow↔AsyncStream 대응이 가장 큰 병행 작업.

## 6. 횡단 관심사 소유권 (storage · keys · WUA) — 확정 2026-07-05

**원칙: 앱은 얇은 포트 어댑터만 주입하고, SDK가 도메인 로직·수명주기를 자동 오케스트레이션한다.** "앱이 자유롭게"가 아니라 "SDK 자동 + 포트로 플랫폼 통제". 근거: ARF/HAIP 정확성(PoP·key attestation·OneTime 키 위생)을 SDK가 보장, 키 재료가 앱에 노출되지 않음, 앱은 어느 keystore/storage/backend인지만 어댑터로 통제.

| 관심사 | 앱 주입 포트 (얇음) | SDK 자동 소유 |
|---|---|---|
| **영속 저장** | `StorageDriver` (put/get/delete/keys — 암호화 블롭) | 봉투 인코딩·저장/로드·lifecycle·follow-up 컨텍스트 직렬화 |
| **holder 바인딩 키** | `SecureArea` (createKey/sign/deleteKey) | 발급 시 생성·핸들 보관·제시 서명·삭제 시 파기·OneTime 소비 시 키 삭제 |
| **wallet instance attestation (WUA)** | `WalletAttestationProvider` (WP 백엔드 링크) | 인스턴스 키 소유·재사용·PoP 서명·attestation 캐싱·만료 갱신 |

### 6a. WUA — SDK가 인스턴스 키 소유 (개선)
- 앱은 `WalletAttestationProvider`(백엔드 통신) + `IssuanceConfig(clientAuth = ClientAuth.AttestationBased)`만 제공.
- SDK 내부: ①인스턴스 키 1회 생성(SecureArea) → 핸들을 storage `wallet-instance` 컬렉션에 보관 → 재사용 ②`walletAttestation(instanceKeyInfo)` 호출 → `exp`까지 캐싱 ③`ClientAttestationPoP` 직접 서명 → PAR·토큰 자동 첨부.
- 앱은 인스턴스 키·PoP를 안 건드림. 기존 `WalletClientAuth.create(provider, instanceKey, signer, ...)`의 `instanceKey`/`signer` 인자를 **SDK 내부로 흡수** (파사드 조립기가 담당).

### 6b. 저장 암호화 = (a) 어댑터가 암호화 (확정)
- `StorageDriver`가 저장하는 블롭의 암호화는 **어댑터 소관** — 플랫폼 암호화 스토리지(Android EncryptedSharedPreferences / iOS Keychain-backed DB). ref 월렛 방식, v0 단순.
- SDK 레벨 봉투 암호화(SecureArea 키 래핑)는 **후속 옵션**(`StorageEncryption` 정책) — v0 미포함.

### 6c. 탈출구 (고급 앱)
- 키: `IssuanceRequest(keySpec = ...)`로 알고리즘·userAuth·하드웨어 정책 지정.
- WUA: 앱이 `provider` 내부에서 캐싱/갱신 스케줄 직접 제어(SDK는 provider 반환을 신뢰).
- 저장: 어댑터가 암호화·백업·마이그레이션 정책 소유.

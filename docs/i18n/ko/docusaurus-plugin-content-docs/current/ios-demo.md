---
title: iOS 어댑터 & 데모
---

# iOS 어댑터 & 데모 앱

리포지토리의 `demo-ios/`에는 SwiftUI로 작성된 **디버그 월렛** 앱(*Axle Wallet*)이 있고, `ios/`에는 SDK의
포트를 구현한 **재사용 가능한 iOS 플랫폼 어댑터 모듈**이 있습니다. 앱은 데모 코드를 복사하는 대신 이 `ios/`
패키지에 의존하면 됩니다. `demo-ios/`는 Android `demo/`를 1:1로 미러링합니다.

## `ios/` 어댑터 패키지

네 개의 프로덕트를 담은 단일 SwiftPM 패키지(`EudiWalletApple`)로, `android/` 모듈의 iOS 대응물입니다:

| 프로덕트 | 제공 | 주요 타입 |
|---|---|---|
| `AppleCore` | 1차 포트 | `SecureEnclaveSecureArea`(`SecureArea`, P-256 Secure Enclave), `KeychainStorageDriver`(`StorageDriver`), `URLSessionTransport`(`HttpTransport`), `FileTransactionLogStore`(`TransactionLogStore`), `OSLogWalletLogger`, `AppleTrust`(신뢰 목록 앵커) |
| `AppleProximity` | ISO 18013-5 트랜스포트 | `BlePeripheralTransport` / `BleCentralTransport`(`ProximityTransport`, BLE 양쪽 모드, 홀더 + 리더) |
| `AppleDcApi` | Digital Credentials API | `DcApiRegistrar`(등록), `DcApiResponder`(응답 생성), `DcApiReaderTrust`(리더 배지) |
| `AppleAttestation` | Wallet Provider 링크 | `WalletProviderAttestation`(`WalletAttestationProvider`), `AppAttestIntegrityTokenProvider`(App Attest, 개발용 폴백 포함) |

모듈별 상세 내용은 [iOS 어댑터 모듈](./guides/ios-adapters) 페이지에 있습니다.

## `Wallet` 조립

모든 것은 `WalletPorts`로 호스트가 주입합니다 — DI 프레임워크 없음. 데모의
[`DemoWallet.swift`](https://github.com/hopae-official/eudi-wallet-sdk/blob/main/demo-ios/AxleWallet/AxleWallet/DemoWallet.swift)가
표준 조립 예시이며, `boot()`는 빌드 전에 신뢰 앵커를 가져오므로 `async`입니다:

```swift
let secureArea = SecureEnclaveSecureArea(accessGroup: AppleSharedGroups.keychainAccessGroup)
let storage    = KeychainStorageDriver(accessGroup: AppleSharedGroups.keychainAccessGroup)
let http       = URLSessionTransport()
let trust      = await AppleTrust.resolve(http: http, cacheDir: cacheDir)   // JAdES 신뢰 목록 → 앵커

let wallet = Wallet.create(
  config: WalletConfig(
    issuance: IssuanceConfig(clientId: "wallet-dev", redirectUri: "eu.europa.ec.euidi://authorization"),
    trust: TrustConfig(issuerAnchorsDer: trust.issuer, readerAnchorsDer: trust.reader,
                       registrarAnchorsDer: trust.registrar),
    readerAuth: ReaderAuthLoader.load()),                                    // Read-mDL 리더 인증 (선택)
  ports: WalletPorts(
    secureAreas: [secureArea],                                              // AppleCore — 하드웨어 키
    storage: storage,                                                       // AppleCore
    http: http,                                                             // AppleCore
    walletAttestation: walletAttestation,                                   // AppleAttestation (선택)
    logger: OSLogWalletLogger(),
    transactionLogStore: FileTransactionLogStore()))                        // AppleCore — App Group NDJSON
```

**포트 커버리지.** `ios/` 패키지는 **필수** 포트(`SecureArea`, `StorageDriver`, `HttpTransport`) 전부와
`TransactionLogStore`, BLE 근접 트랜스포트, `WalletAttestationProvider`를 제공합니다. `WalletClock` / `Rng`는
SDK 기본값을 씁니다. 공유 **키체인 액세스 그룹**은 시큐어 에어리어와 스토리지에 전달되어, DC API 익스텐션이
크리덴셜을 읽고 디바이스 키에 서명할 수 있게 합니다 — 아래 참고.

## Wallet Provider 어태스테이션

`AppleAttestation`은 `wallet-provider/` 백엔드를 대상으로 `WalletAttestationProvider`를 구현합니다: 어태스테이션
기반 클라이언트 인증을 위한 WUA와 발급별 키 어태스테이션을 제공하며, 디바이스는 **App Attest**로 어태스트됩니다
(시뮬레이터에서는 개발용 토큰으로 폴백). 배포에 필요한 경우에만 연결하세요 — 공개 `client_id`를 받는 발급자에
대한 발급은 이것 없이도 동작합니다.

```swift
let walletAttestation = WalletProviderAttestation(
  baseUrl: "https://your-wallet-provider.example/wp",
  http: http, secureArea: secureArea,                 // 인스턴스 키 소유 증명에 서명
  integrity: AppAttestIntegrityTokenProvider(),       // App Attest; 시뮬레이터에서는 개발용 폴백
  clientId: "wallet-dev",                             // IssuanceConfig.clientId와 일치해야 함
  storage: storage)                                   // 재시작 간 인스턴스 id를 유지
```

백엔드는 플랫폼별로 토큰을 검증하며(Android는 Play Integrity, iOS는 App Attest), 어댑터는 `platform: "ios"`를
전송하여 App Attest 검증기로 라우팅되도록 합니다.

## 근접 (BLE)

트랜스포트를 만들어 파사드에 넘깁니다. BLE 양쪽 모드(peripheral-server와 central-client)와 양쪽 역할이
구현되어 있으며, Android 데모를 상대로 폰투폰 검증되었습니다:

```swift
// BLE peripheral-server 홀더 — QR 인게이지먼트로 제시:
let transport = BlePeripheralTransport.holder(logger: log)
try await transport.start()
let session = wallet.proximity.present(transport)

// 리더 — QR을 스캔한 뒤 읽기:
let documents = try await wallet.reader.read(BleCentralTransport.reader(engagement: engagement), ...)
```

전체 수명주기는 `demo-ios/AxleWallet/AxleWallet/ProximityHolderView.swift` / `ReaderView.swift`와
[근접 가이드](./guides/proximity)를 참고하세요.

## Digital Credentials API

iOS는 인프로세스 액티비티가 아닌 **프로바이더 앱 익스텐션**(`AxleWalletIDProvider`)을 통해 월렛을 브라우저
DC API 요청에 노출합니다. 앱은 크리덴셜이 변경될 때마다 문서를 등록합니다:

```swift
if #available(iOS 26.0, *) { await DcApiRegistrar.sync(wallet: wallet) }
```

익스텐션(`@main IdentityDocumentProvider` + SwiftUI 동의 화면)은 공유 Secure Enclave 키로 서명하여 요청에
응답합니다. iOS는 `org-iso-mdoc`만 라우팅합니다. 이는 Android와 의미 있게 다릅니다(ExtensionKit 익스텐션,
공유 컨테이너, 2단계 요청, 매처 없음) — 전체 설명은 **[Digital Credentials API — iOS](./guides/dc-api-ios)**
가이드에 있습니다.

## 빌드

Xcode 프로젝트를 열고 디바이스에서 실행하세요 — 로컬 SwiftPM 패키지(`swift/` 코어 + `ios/` 어댑터)는 상대
경로로 참조되므로 가져올 것이 없습니다:

```bash
open demo-ios/AxleWallet/AxleWallet.xcodeproj
# iOS 26 디바이스를 선택하고 Run (⌘R)
```

툴체인: Xcode 26+, iOS 26 배포 타깃, 실기기(Secure Enclave, App Attest, App Group 공유, DC API 익스텐션은
하드웨어가 필요합니다). DC API doctype 기능은 Apple이 승인하는 특수 엔타이틀먼트입니다 —
[DC API — iOS](./guides/dc-api-ios#1-entitlements--capabilities) 가이드를 참고하세요.

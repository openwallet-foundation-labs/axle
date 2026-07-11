---
title: Android 어댑터 & 데모
---

# Android 어댑터 & 데모 앱

리포지토리의 `demo/`에는 Jetpack Compose로 SDK를 구동하는 **디버그 월렛** 앱이 있고, `android/`에는 SDK의
포트를 구현한 **재사용 가능한 Android 플랫폼 어댑터 라이브러리**가 있습니다. 앱은 데모 코드를 복사하는 대신
이 `android/` 라이브러리에 의존하면 됩니다.

## `android/` 어댑터 라이브러리

Maven 그룹 **`com.hopae.eudi.android`** 아래 세 모듈입니다(SDK의 `com.hopae.eudi`와 구분되어 아티팩트가
충돌하지 않습니다):

| 모듈 | 제공 | 주요 클래스 |
|---|---|---|
| `core` | 1차 포트 | `AndroidKeystoreSecureArea`(`SecureArea`, 하드웨어 기반), `FileStorageDriver`(`StorageDriver`), `OkHttpTransport`(`HttpTransport`), `FileTransactionLogStore`(`TransactionLogStore`) |
| `proximity` | ISO 18013-5 트랜스포트 | `BleGattClientTransport` / `BleGattServerTransport`(`ProximityTransport`), `NfcEngagementService`(홀더 HCE), `NfcReader`(리더). **라이브러리 매니페스트**가 BLE/NFC 권한 + HCE 서비스를 앱에 병합합니다 |
| `dcapi` | Digital Credentials API | `DcApiRegistrar`(Credential Manager 등록 + 매처), `DcApiRequest` / `DcApiResult`(엔벌로프 + 마샬링), `DcApiBranding`(OS 셀렉터 로고/브랜딩) |

## `Wallet` 조립

모든 것은 `WalletPorts`로 호스트가 주입합니다 — DI 프레임워크 없음:

```kotlin
val logger = LogWalletLogger()   // 당신의 WalletLogger (데모는 logcat + 화면 + 파일로 라우팅)
val wallet = Wallet.create(
    config = WalletConfig(),
    ports = WalletPorts(
        secureAreas = listOf(AndroidKeystoreSecureArea()),                       // android/core — 하드웨어 키
        storage = FileStorageDriver(File(filesDir, "wallet")),                   // android/core
        http = OkHttpTransport(logger = logger),                                 // android/core
        transactionLogStore = FileTransactionLogStore(File(filesDir, "tx.log")), // android/core
        logger = logger,
        // walletAttestation = ...   // WUA (Wallet Provider) — 아직 어댑터 없음; 어태스테이션 트랙 참고
    ),
)
```

**포트 커버리지.** `android/` 라이브러리는 **필수** 포트(`SecureArea`, `StorageDriver`, `HttpTransport`)
전부와 `TransactionLogStore`, 근접 트랜스포트를 제공합니다. `WalletClock` / `Rng`는 SDK 기본값
(`WalletClock.System` / `Rng.Default`)을 씁니다. `WalletLogger`는 **의도적으로 앱이 제공** — 실제 로깅
(화면/파일)은 앱별이라 `android/core`에 구체 로거를 넣지 않습니다. **아직 어댑터가 없는** 유일한 포트는
`WalletAttestationProvider`(Wallet Unit Attestation)로, 어태스테이션 워크스트림에서 다룹니다.

## 근접 (BLE + NFC)

트랜스포트를 만들어 파사드에 넘깁니다. BLE 양쪽 모드와 NFC **static + negotiated** 핸드오버가 구현·폰투폰
실기기 검증되어 있습니다(`INTEROP.md` 참고).

```kotlin
// BLE peripheral-server 홀더:
val server = BleGattServerTransport(context, uuid, Ble.PERIPHERAL_SERVER, retrievalMethods, logger = logger)
val session = wallet.proximity.present(server)                      // QR 인게이지먼트

// 리더:
val docs = wallet.reader.read(clientTransport, engagement, requested)
```

NFC의 경우 홀더는 `NfcEngagementProcessor`(static, 또는 negotiated `hr → hs` 셀렉터)로 HCE를 무장하고,
리더는 `NfcReader.readHandover(...)`가 static vs TNEP negotiated를 자동 감지합니다. 전체 수명주기는
`demo/.../ui/ProximityScreens.kt`와 [근접 가이드](./guides/proximity)를 참고하세요.

## Digital Credentials API

```kotlin
DcApiRegistrar.register(activity, wallet, DcApiBranding(logoPng = appIconPng()), logger = logger)
```

월렛의 크리덴셜을 Credential Manager(OS 크리덴셜 셀렉터)에 등록하고 앱 아이콘으로 브랜딩합니다. 라우팅된
인텐트는 `DcApiRequest` / `DcApiResult`로 얇은 액티비티에서 처리합니다(데모의 `GetCredentialActivity` 참고).

## 빌드

데모는 SDK와 어댑터를 composite build(`includeBuild("../kotlin")` + `includeBuild("../android")`)로
소비합니다:

```kotlin
// demo/app/build.gradle.kts
implementation("com.hopae.eudi:wallet:0.0.1-SNAPSHOT")
implementation("com.hopae.eudi.android:core:0.0.1-SNAPSHOT")
implementation("com.hopae.eudi.android:proximity:0.0.1-SNAPSHOT")
implementation("com.hopae.eudi.android:dcapi:0.0.1-SNAPSHOT")
```

```bash
cd demo
./gradlew :app:assembleDebug        # → app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

툴체인: AGP 9.2.1, Gradle 9.5, `compileSdk` 36, `minSdk` 29. `android/` 빌드에는
`android/local.properties`에 `sdk.dir=/path/to/android-sdk`가 필요합니다.

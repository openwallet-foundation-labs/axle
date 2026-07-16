---
title: Digital Credentials API (iOS)
---

# Digital Credentials API (iOS)

[W3C Digital Credentials API](https://w3c-fedid.github.io/digital-credentials/)는 웹사이트가
`navigator.credentials.get({ digital })`를 호출하면 OS가 지갑 선택창을 중개하게 해줍니다 — QR도, HTTP
왕복도 없습니다. iOS에서는 이 과정이 Apple의 **[IdentityDocumentServices](https://developer.apple.com/documentation/identitydocumentservices)**
프레임워크(iOS/iPadOS 26+)를 통해 동작합니다. 지갑은 시스템이 요청에 응답하기 위해 깨우는 **프로바이더 앱
익스텐션**을 함께 제공합니다. 크리덴셜 로직은 SDK가 처리하고, 이 가이드는 그것을 iOS에 연결하는 방법을 다룹니다.

`ios/` 패키지는 이를 **`AppleDcApi`** 모듈에서 처음부터 끝까지 제공하며, `demo-ios/`(Axle Wallet)가 이를
조립합니다. 아래 코드는 그것이 무엇을 하는지, 그리고 어떻게 적용하는지 보여줍니다.

## 플랫폼의 한계 — `org-iso-mdoc` 전용

Apple은 서드파티 지갑에 정확히 **하나**의 DC API 프로토콜만 라우팅합니다: **`org-iso-mdoc`**(ISO/IEC TS
18013-7:2025 Annex C). 브라우저 DC API를 통한 OpenID4VP는 **iOS에서 도달할 수 없으며**, 이는 SDK의
제약이 아니라 플랫폼의 제약입니다.

| 프로토콜 | Android (Credential Manager) | iOS (IdentityDocumentServices) | SDK 진입점 |
| --- | --- | --- | --- |
| `openid4vp-v1-unsigned` / `-signed` | ✅ | ❌ 플랫폼 | `wallet.presentation.startDcApi(json, origin)` |
| `org-iso-mdoc` | ✅ | ✅ | `wallet.proximity.respondDcApiMdoc(deviceRequest, encryptionInfo, origin)` |

그 증거는 프레임워크 자체에 있습니다: `IdentityDocumentServicesUI.IdentityDocumentRequestScene`과
`IdentityDocumentServices.IdentityDocumentWebPresentmentRequest`는 각각 정확히 **하나**의 준수 타입만
가집니다 — `ISO18013MobileDocumentRequestScene` / `ISO18013MobileDocumentRequest`. 모든 iOS 브라우저는
WebKit이므로, 엔진과 무관하게 어떤 iOS 브라우저도 `openid4vp`를 라우팅하지 않습니다. W3C 커뮤니티
레퍼런스는 iOS에 대해 이렇게 명시합니다: *"제시에는 ISO 18013-7 Annex C. OpenID for Verifiable
Presentations(Annex D)는 지원되지 않음."*

:::note OpenID4VP는 iOS에서 여전히 동작합니다 — 다만 브라우저 DC API를 통해서는 아닙니다
`wallet.presentation.startDcApi`는 컴파일되고 테스트된 상태로 유지됩니다. 단지 Apple이 두 번째 scene
타입을 출시하기 전까지 iOS에서 이를 호출하는 브라우저가 없을 뿐입니다. 브라우저가 중개하는 OpenID4VP
요청은 대신 동일 기기 딥링크 / 교차 기기 `request_uri` 플로우(`wallet.presentation.start(requestUri)`)로
처리하고, verifier 프론트엔드는 Safari/iOS에서 OpenID4VP DC API 옵션을 숨겨야 합니다. OpenID4VP에서
사용할 수 없는 것은 오직 *브라우저 중개 DC API* 변형뿐입니다.
:::

두 진입점 모두 크로스플랫폼입니다 (Kotlin·Swift 동일). 이 페이지의 나머지는 iOS 프로바이더 배선입니다.

## iOS는 Android와 어떻게 다른가

| | Android (Credential Manager) | iOS (IdentityDocumentServices) |
| --- | --- | --- |
| 등록 | 크리덴셜 DB (CBOR) + 프로토콜 목록 | docType별 `MobileDocumentRegistration` |
| Matcher | 지갑이 WASM matcher를 제공 | **없음** — OS가 매칭 + 선택창을 담당 |
| 요청 핸들러 | 반투명 `Activity` (인프로세스) | **별도의 프로바이더 앱 익스텐션** (독립 프로세스) |
| 요청 형태 | 요청 객체 하나 | **두 개**: 타입이 지정된 `context.request` (표시용) + 원시 `DeviceRequest` (서명용) |
| 제시 가능 포맷 | mdoc + SD-JWT VC | **mdoc 전용** |

iOS에서의 두 가지 큰 결과: (1) 작성해야 할 **matcher가 없으며** — 이는 Android의 WASM matcher 문제
전체를 없앱니다; 그리고 (2) 요청 핸들러가 **별도의 프로세스**이므로, App Group + Keychain 공유를 통해
앱의 키와 저장된 크리덴셜을 공유해야 합니다.

## 아키텍처: 앱이 등록하고, 익스텐션이 응답한다

```
   Axle Wallet app                          AxleWalletIDProvider (extension)
   ───────────────                          ───────────────────────────────
   • has the doctype entitlement            • IdentityDocumentProvider (@main)
   • DcApiRegistrar.sync(wallet)   ──┐       • ISO18013MobileDocumentRequestScene
     on every credential change      │        → your consent view
                                     │       • signs DeviceResponse, HPKE-seals it
        shared App Group  ◄──────────┴──────►  reads the SAME credentials + device keys
        shared Keychain group                  (separate process)
```

브라우저는 앱이 아니라 **익스텐션**을 깨웁니다. 그래서 익스텐션은 앱이 사용하는 것과 *동일한* 어댑터로부터
`Wallet`을 구성하며, *동일한* 공유 그룹을 가리킵니다 — 앱이 발급한 크리덴셜을 읽고, 그 크리덴셜의 Secure
Enclave 기기 키로 `DeviceResponse`에 서명합니다.

## 1. 엔타이틀먼트와 Capability

세 가지 Capability로, 앱과 익스텐션에 나뉩니다:

| Capability | 앱 | 익스텐션 |
| --- | --- | --- |
| `com.apple.developer.identity-document-services.document-provider.mobile-document-types` | ✅ (제공할 doctype들) | — |
| `com.apple.security.application-groups` (`group.…`) | ✅ | ✅ |
| Keychain Sharing (`$(AppIdentifierPrefix)…`) | ✅ | ✅ |

doctype 엔타이틀먼트는 **앱**에 속하는데, `IdentityDocumentProviderRegistrationStore`를 호출하는 것이
앱이기 때문입니다. 이는 **Apple이 승인하는 관리형(managed)** 엔타이틀먼트입니다: 제공 가능한 모든
doctype이 배열에 나열되어야 하며, 배열에 없는 doctype은 등록하거나 제공할 수 없습니다.

```xml
<!-- AxleWallet.entitlements (앱) -->
<key>com.apple.developer.identity-document-services.document-provider.mobile-document-types</key>
<array>
  <string>org.iso.18013.5.1.mDL</string>
  <string>eu.europa.ec.eudi.pid.1</string>
</array>
```

:::warning 엔타이틀먼트는 런타임에 강제됩니다
이것이 없으면 익스텐션은 설치되지만 등록이 `notAuthorized`로 실패하므로, Safari는 지갑을 제안하지 않습니다.
서명된 빌드에 이것이 포함되었는지 확인하세요:

```bash
codesign -d --entitlements :- "/path/to/Axle Wallet.app"
# expect the mobile-document-types key with a non-empty array
```
:::

## 2. 공유 키 보관 (전제 조건)

`kSecAttrAccessGroup`은 **Secure Enclave 키가 생성될 때 고정되며 이후에는 변경할 수 없고**, SE 개인 키는
내보낼 수 없습니다. 따라서 앱은 처음부터 **공유** 키체인 액세스 그룹으로 키를 생성해야 합니다 — 그렇지
않으면 어떤 익스텐션도 그 키로 서명할 수 없으며, 유일한 해결책은 재발급뿐입니다. 앱과 익스텐션의
`SecureArea` / `StorageDriver` 모두를 공유 그룹으로 구성하세요:

```swift
let group = "P3A48743C4.com.hopae.axle.wallet"   // $(AppIdentifierPrefix) + 공유 id
let secureArea = SecureEnclaveSecureArea(accessGroup: group)
let storage    = KeychainStorageDriver(accessGroup: group)
```

`AppleCore`의 `AppleSharedGroups`는 App Group + 키체인 그룹 문자열을 중앙화하여 앱과 익스텐션이 어긋나지
않도록 합니다.

## 3. 문서 등록

등록은 저장된 mdoc 크리덴셜마다 한 번의 호출입니다 — **matcher도, 데이터베이스도 없습니다**. 앱 시작 시,
그리고 `wallet.credentials.changes()`가 방출할 때마다 실행하세요 (Android의 변경 시 재등록을 반영합니다):

```swift
@available(iOS 26.0, *)
enum DcApiRegistrar {
  static func sync(wallet: Wallet) async {
    let store = IdentityDocumentProviderRegistrationStore()
    let wanted = try await wallet.credentials.list().reduce(into: [String: MobileDocumentRegistration]()) {
      guard case let .msoMdoc(docType) = $1.format,           // mdoc 전용 — SD-JWT VC는 제공할 수 없음
            case let .issued(_, validity, _) = $1.lifecycle else { return }
      $0[$1.id.value] = MobileDocumentRegistration(
        mobileDocumentType: docType,
        supportedAuthorityKeyIdentifiers: [],                 // 발급자 필터링 없음 — 대신 reader를 표시
        documentIdentifier: $1.id.value,
        invalidationDate: validity?.validUntil)
    }
    for existing in (try? await store.registrations) ?? [] where wanted[existing.documentIdentifier] == nil {
      try? await store.removeRegistration(forDocumentIdentifier: existing.documentIdentifier)   // 오래된 항목 정리
    }
    for reg in wanted.values { try? await store.addRegistration(reg) }                          // 현재 항목 upsert
  }
}
```

:::note 등록 시 `notAuthorized`
거의 항상 다음 중 하나입니다: doctype이 앱의 엔타이틀먼트 배열에 없거나; 관리형 Capability가 해당 App
ID에 대해 승인되지 않았거나; 또는 **익스텐션 번들 설치가 실패**한 경우입니다 (§4 참고 — 유효하지 않은
익스텐션은 프로바이더 전체를 무효화하므로 `addRegistration`이 거부됩니다). 각 문서를 독립적으로 등록하고
docType을 로깅하여 어느 것인지 알 수 있게 하세요.
:::

## 4. 프로바이더 익스텐션

익스텐션 진입점은 아주 작습니다 — 각 요청을 SwiftUI 동의 뷰에 넘기는 scene 하나입니다:

```swift
import ExtensionKit
import IdentityDocumentServicesUI

@main
struct AxleDocumentProvider: IdentityDocumentProvider {
  var body: some IdentityDocumentRequestScene {
    ISO18013MobileDocumentRequestScene { context in
      DcApiConsentView(context: context)      // 동의 UI — OS가 호스팅
    }
  }
  func performRegistrationUpdates() async {}   // 등록은 앱이 담당
}
```

### Xcode 타깃 설정

이것은 레거시 앱 익스텐션이 아니라 **ExtensionKit** 익스텐션입니다 — 이 차이가 설치를 가능하게 합니다:

| 설정 | 값 |
| --- | --- |
| Product type | `com.apple.product-type.extensionkit-extension` |
| Embed build phase | **Embed ExtensionKit Extensions** → `dstSubfolderSpec = 16`, `$(EXTENSIONS_FOLDER_PATH)` |
| Info.plist | `EXAppExtensionAttributes.EXExtensionPointIdentifier = com.apple.identity-document-services.document-provider-ui` |
| Entitlements | App Groups + Keychain sharing만 |

:::warning 설치 시 함정
`.appex`를 **레거시** 앱 익스텐션으로(`PlugIns/`에) 임베드하면, `installd`는 이를 PlugInKit 번들로
취급하여 거부합니다: *"Appex bundle … does not define an NSExtension dictionary."* ExtensionKit 익스텐션은
**`Contents/Extensions/`**(`$(EXTENSIONS_FOLDER_PATH)`)에 위치하며, `NSExtension`이 아니라
`EXAppExtensionAttributes`를 선언합니다. 확인: 빌드된 앱에 `AxleWallet.app/Extensions/…​.appex`가 있어야
합니다.
:::

## 5. 2단계 요청과 응답 구성

Apple의 플로우는 의도적으로 2단계입니다:

- **동의 전(Pre-consent)**에는 OS가 파싱한 타입이 지정된 `context.request`를 가집니다 — **표시할** 문서,
  네임스페이스, 요소, 그리고 `context.requestingWebsiteOrigin`과 reader의 인증서 체인
  (`requestAuthentications`)입니다. 이것으로 동의 화면을 구성하세요.
- **동의 후(Post-consent)**에는 `context.sendResponse { rawRequest in … }` 내부에서 **원시** 요청 바이트가
  도착합니다 — `rawRequest.requestData`는 JSON `{ deviceRequest, encryptionInfo }`입니다 (둘 다 base64url
  CBOR). 이것이 실제로 서명하는 대상입니다.

```swift
try await context.sendResponse { rawRequest in
  let data = try await DcApiResponder.responseData(
    rawRequestData: rawRequest.requestData,
    origin: context.requestingWebsiteOrigin,
    wallet: extensionWallet)
  return ISO18013MobileDocumentResponse(responseData: data)   // Apple은 원시 Data를 요구
}
```

`DcApiResponder`는 `{ deviceRequest, encryptionInfo }`를 추출하고, origin을 정규화한 뒤(후행 `/`를 제거 —
이것이 SessionTranscript 해시를 바꾸기 때문입니다), SDK를 호출합니다:

```swift
let base64url = try await wallet.proximity.respondDcApiMdoc(
  deviceRequestBase64: deviceRequest, encryptionInfoBase64: encryptionInfo, origin: origin)
let data = Data(base64urlDecoded: base64url)   // respondDcApiMdoc은 base64url을 반환; Apple API는 Data를 받음
```

`respondDcApiMdoc`은 ISO 18013-7 **dcapi** SessionTranscript
`[null, null, ["dcapi", SHA-256(CBOR([encryptionInfoB64, origin]))]]`에 대해 mdoc `DeviceResponse`를
만들고, verifier의 `recipientPublicKey`로 이를 **HPKE 봉인**하며 (RFC 9180 base mode,
`DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM`), `base64url(CBOR(["dcapi", { enc, cipherText }]))`를
반환합니다. 이는 Android 경로 및 EUDI 레퍼런스와 바이트 단위로 동일하며 — HPKE + transcript는 SDK에
있으므로(`Hpke.sealBaseP256`, `MDoc` 모듈) 플랫폼 HPKE가 필요 없습니다. 와이어 포맷은
[Android DC API 가이드](./dc-api#4-org-iso-mdoc-and-hpke)를 참고하세요.

## 6. Reader 인증 — 검증 배지

ISO 18013-5 §9.1.4는 verifier가 자신의 요청에 서명할 수 있게 합니다(`readerAuth`). 두 가지 독립적인 것이
뒤따르며, iOS의 2단계 API는 이를 타임라인에 걸쳐 나눕니다:

- **신원 신뢰(배지)** — reader의 인증서가 신뢰된 reader 앵커까지 체인으로 연결되는가? 이는
  `context.request.requestAuthentications`로부터 **동의 전**에 확인할 수 있으므로, 동의 화면은
  *Verified* / *Unverified* 배지를 표시합니다. 익스텐션은 오프라인이므로, 앱이 해석한 reader 앵커를 공유
  App Group(`DcApiReaderTrust`)에 캐시하고, 익스텐션은 `SecTrust`로 그 앵커들에 대해 체인을 검증합니다.
- **서명 유효성** — SessionTranscript에 대한 `readerAuth` COSE 서명이 유효한가? 이는 원시 요청이
  필요하므로, **동의 후**에만 확인할 수 있습니다.

둘 중 어느 것도 강하게 차단하지 않습니다: 검증되지 않았거나 알 수 없는 reader는 단순히 *Unverified*로
표시되고 공유가 진행됩니다 — reader를 표시하되 거부하지는 않는 **Android와 동일**합니다. (변조된 요청은
이미 공격자에게 무용합니다: 응답은 verifier가 기대하는 origin + transcript에 HPKE로 묶여 있습니다.)

## 7. 동의 일관성 — iOS 고유의 검사

iOS는 요청을 **두 번** 넘기기 때문에 — 한 번은 표시용, 한 번은 서명용 — 두 표현이 원칙적으로 서로 어긋날
수 있습니다. Apple은 이 둘이 일치하는지 확인할 것을 권장하며(그들의 레퍼런스는 이를 스텁으로 남겨둡니다),
SDK 어댑터는 이를 구현합니다. 서명하기 전에, 원시 `DeviceRequest`를 디코드하여 동의 화면이 보여주지 않은
것을 **아무것도** 요청하지 않는지 확인하고, 그렇지 않으면 거부하세요:

```swift
for docRequest in deviceRequest.docRequests {
  guard let shownNamespaces = shown[docRequest.docType] else { throw .inconsistentRequest }
  for (namespace, elements) in docRequest.requested {
    for element in elements where !(shownNamespaces[namespace] ?? []).contains(element.identifier) {
      throw .inconsistentRequest   // 사용자가 보지 않은 속성은 절대 서명하지 않음
    }
  }
}
```

Android에는 이에 해당하는 것이 없는데, 그 DC API는 앱에 **단일** 요청 객체를 넘기므로 — 교차 검증할 것이
없기 때문입니다. 정상 동작에서는 이 검사가 결코 발동하지 않습니다 (OS가 동일한 바이트로부터
`context.request`를 파싱합니다). 이는 플랫폼이 도입하는 표시 대 서명 경계를 방어하기 위해 존재합니다.

## 8. 생체 인증 확인

인앱 제시 플로우와 완전히 동일하게 `Share`를 Face ID / Touch ID로 게이팅하세요. 익스텐션은 별도의
프로세스이므로, 공유 App Group에서 생체 인증 설정을 읽고(앱이 그곳에 미러링합니다) `LocalAuthentication`으로
프롬프트하세요 (익스텐션의 `Info.plist`에는 `NSFaceIDUsageDescription`이 필요합니다):

```swift
if biometricEnabled, await !LAContext().authenticate(reason: "Confirm to share your ID") {
  return   // 취소됨 — 응답을 보내지 않음
}
```

사용자의 설정을 존중하세요: 생체 인증이 꺼져 있으면 프롬프트하지 않으며, 이는 원격 / 근접 플로우와 완전히
동일합니다.

## 9. 빌드 및 테스트

1. 서명된 빌드를 **iOS 26** 기기에 설치하세요 (Secure Enclave + 엔타이틀먼트는 실제 하드웨어가 필요합니다).
2. 등록을 확인하세요: 앱 시작 / 크리덴셜 변경 시 `registered N mdoc document(s)`가 보여야 합니다.
3. Safari에서 `org-iso-mdoc` DC API verifier(예: `verifier.eudiw.dev`)를 열고, mDL 또는 PID를 요청하세요.
4. `navigator.credentials.get({ digital })` → OS 선택창이 **Axle Wallet**을 제안 → 선택 → 동의 뷰가
   reader, 속성, *Verified* 배지를 표시 → Face ID → 서명되고 HPKE로 암호화된 `DeviceResponse`가
   verifier에게 돌아갑니다.

:::note
응답이 verifier 자체의 발급자 신뢰 정책에 의해 거부될 수도 있는데, 이는 verifier 쪽 문제이지 지갑 문제가
아닙니다. 레퍼런스 iOS 어댑터(`AppleDcApi`)와 데모(Axle Wallet)는 [iOS 어댑터 모듈](./ios-adapters)과
[iOS 데모](../ios-demo) 페이지를 참고하세요.
:::

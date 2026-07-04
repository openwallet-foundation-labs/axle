# Spec Version Matrix

이 SDK가 구현·추적하는 스펙 버전의 단일 소스. 릴리스마다 이 파일이 함께 태깅된다 (PLAN.md §3 운영 원칙).

| 스펙 | 앵커 버전 | 구현 상태 (0.0.x) |
|---|---|---|
| CBOR | RFC 8949 (deterministic encoding §4.2.1) | ✅ `cbor` — Appendix A 82벡터 양 언어 통과, 8949 bytewise + 7049 length-first 키 정렬 프로파일 |
| COSE | RFC 9052 §4.2 COSE_Sign1 · RFC 9053 ES256/384/512 · RFC 9360 x5chain | ✅ 검증(JCA/swift-crypto) + 서명(CoseSigner → SecureArea 포트 위임). cose-wg sign1 벡터 통과 |
| OpenID4VCI | **1.0 Final** (2025-09-16) | ⬜ M2 |
| OpenID4VP | **1.0 Final** (2025-07-09), DCQL | ⬜ M3 |
| HAIP | **1.0 Final** | ⬜ M2–M3 기본값에 반영 (PAR·DPoP Required 등) |
| JOSE (JWS) | RFC 7515/7518 서브셋 (compact, ES256/384/512) | ✅ `sdjwt` — 자체 구현, alg 고정 검증(협상 금지) |
| SD-JWT | **RFC 9901** | ✅ `sdjwt` — 발급/제시/검증, KB-JWT, 재귀·배열 disclosure, RFC 예제 83벡터 양 언어 통과 |
| SD-JWT VC | draft-ietf-oauth-sd-jwt-vc (착수 시점 최신으로 핀) | 🔶 vct/cnf는 구현됨, VC 프로파일 규칙은 VCI와 함께 (M2 잔여) |
| Token Status List | IETF 최종 단계 — M6 시작 시 RFC 여부 재확인 | ⬜ M6 |
| ISO/IEC 18013-5 | :2021 (+ 18013-7 / DC API Handover) | ⬜ M4–M5 |
| W3C Digital Credentials API | Android CredMan / iOS 26 IdentityDocumentServices | ⬜ M5b (어댑터) |
| ARF | 2.7.x 추적 | 문서 단계 |

미결 인터롭 포인트 (구현은 양쪽 다 있음, 핀만 남음):
- **mdoc 맵 키 정렬**: RFC 8949 bytewise(기본) vs RFC 7049 length-first(옵션) — M4에서 EUDI ref 아티팩트로 확정.

## 알려진 갭 레지스터 (자체 모듈 = 범용 lib가 아니라 스펙-필요 서브셋. 갭은 여기서 추적)

| 갭 | 필요 시점 | 상태 |
|---|---|---|
| **JWE** (ECDH-ES + A128/256GCM — VP 응답 암호화 direct_post.jwt) | **M3 필수 경로** | 계획됨 |
| x5c 헤더 체인 검증 (VP request JWS, x509_san_dns) | M3 (trust 모듈과) | 계획됨 |
| exp/nbf/iat 시간 검증 유틸(clock skew) | M2 VCI부터 | 계획됨 |
| decoy digests 생성 (RFC 9901 권장; 검증측은 이미 무해 처리) | VCI 발급 연결 시 | 계획됨 |
| COSE_Key 파싱, COSE_Mac0 (mdoc deviceAuth MAC) | M4 | 계획됨 |
| Status List의 CWT 변형 | M6 검토 | 미정 |
| RSA(RS/PS), EdDSA, HMAC 서명 | — | **의도적 제외** (HAIP/ARF 요구는 ES256 계열; 필요 시 알고리즘 레지스트리로 확장) |
| `_sd_alg` sha-384/512 | — | 의도적 제외 (HAIP는 sha-256; 명시적 거부함) |
| JSON: >2^53 비정수 정밀도(BigDecimal), JWS JSON 직렬화 변형 | — | 의도적 제외 (토큰 페이로드에 불필요) |

해결된 갭 (이 레지스터가 작동한 기록): JSON 중복 키 거부(claim smuggling 방어), JWS 미지 `crit` 거부 — 2026-07-04 발견 즉시 수정, 테스트 포함.

# Spec Version Matrix

이 SDK가 구현·추적하는 스펙 버전의 단일 소스. 릴리스마다 이 파일이 함께 태깅된다 (PLAN.md §3 운영 원칙).

| 스펙 | 앵커 버전 | 구현 상태 (0.0.x) |
|---|---|---|
| CBOR | RFC 8949 (deterministic encoding §4.2.1) | ✅ `cbor` — Appendix A 82벡터 양 언어 통과, 8949 bytewise + 7049 length-first 키 정렬 프로파일 |
| COSE | RFC 9052 §4.2 COSE_Sign1 · RFC 9053 ES256/384/512 · RFC 9360 x5chain | ✅ 검증(JCA/swift-crypto) + 서명(CoseSigner → SecureArea 포트 위임). cose-wg sign1 벡터 통과 |
| OpenID4VCI | **1.0 Final** (2025-09-16) | ⬜ M2 |
| OpenID4VP | **1.0 Final** (2025-07-09), DCQL | ⬜ M3 |
| HAIP | **1.0 Final** | ⬜ M2–M3 기본값에 반영 (PAR·DPoP Required 등) |
| SD-JWT | **RFC 9901** | ⬜ M2 |
| SD-JWT VC | draft-ietf-oauth-sd-jwt-vc (착수 시점 최신으로 핀) | ⬜ M2 |
| Token Status List | IETF 최종 단계 — M6 시작 시 RFC 여부 재확인 | ⬜ M6 |
| ISO/IEC 18013-5 | :2021 (+ 18013-7 / DC API Handover) | ⬜ M4–M5 |
| W3C Digital Credentials API | Android CredMan / iOS 26 IdentityDocumentServices | ⬜ M5b (어댑터) |
| ARF | 2.7.x 추적 | 문서 단계 |

미결 인터롭 포인트 (구현은 양쪽 다 있음, 핀만 남음):
- **mdoc 맵 키 정렬**: RFC 8949 bytewise(기본) vs RFC 7049 length-first(옵션) — M4에서 EUDI ref 아티팩트로 확정.

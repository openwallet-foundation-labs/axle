# EUDI Wallet Provider (WUA) — NestJS

ARF **Wallet Provider** 백엔드. wallet 인스턴스 무결성을 보증하고 두 가지 attestation을 발급한다:

- **Wallet Unit Attestation (WUA)** — OAuth 2.0 Attestation-Based Client Authentication (`draft-ietf-oauth-attestation-based-client-auth`)의 client attestation JWT. wallet 인스턴스 키를 `cnf.jwk`로 바인딩.
- **Key Attestation** — OpenID4VCI §8.2.1.1 (`keyattestation+jwt`). 크리덴셜 proof 키가 secure area에 있음을 증명.

SDK의 `WalletAttestationProvider` 포트가 이 백엔드에 붙어 HAIP attestation-based client auth를 실물로 완성한다. (모노레포: `eudi-wallet-sdk/wallet-provider`.)

## 엔드포인트

| 메서드 | 경로 | 역할 |
|---|---|---|
| GET | `/nonce` | 단일사용 challenge nonce |
| POST | `/wallet-instances` | 등록: `{instanceKey(JWK), integrityToken, nonce}` → 무결성 검증 → `{instanceId}` |
| POST | `/wallet-attestation` | WUA 발급: `{instanceId, clientId?, pop}` → `{wallet_attestation}`. `pop`=인스턴스 키로 서명한 JWT(`aud`=WP, `nonce`) |
| POST | `/key-attestation` | `{attestedKeys(JWK[]), nonce?}` → `{key_attestation}`. `nonce`=이슈어 c_nonce |
| POST | `/wallet-instances/:id/revoke` | 인스턴스 revoke (이후 WUA 발급 거부) |
| GET | `/wallet-instances/:id/status` | 인스턴스 상태 `{revoked, createdAt, revokedAt}` — 이슈어의 revocation 체크 |
| GET | `/.well-known/jwks.json` | WP 서명 공개키 |
| GET | `/.well-known/wallet-provider-ca.pem` | WP CA 인증서(PEM) — 릴라잉 wallet/issuer가 trust anchor로 설치 |

## 트러스트 (x5c 체인)

WUA/key attestation 헤더의 `x5c` = `[signer 인증서, WP CA]`. 이슈어(또는 우리 SDK trust 모듈)가 **WP CA를 루트로 체인 검증**. dev에선 기동 시 self-signed CA + signer를 생성(`keystore.service.ts`); 프로덕션은 KMS/PKI에서 로드.

## 플랫폼 무결성

`integrity.service.ts`는 pluggable. 실제 Android Play Integrity / iOS App Attest는 Google/Apple 클라우드 크레덴셜 필요 → 기본은 **dev stub**(`dev-integrity:<nonce>` 수용). 프로덕션 verifier를 DI로 교체.

## 실행

```bash
npm install
npm run build && PORT=3200 node dist/main.js   # 또는 npm run start:dev
node test/wp-flow.mjs                            # 전체 플로우 e2e (서버 실행 중일 때)
```

## 영속 (Drizzle + SQLite)

인스턴스 레지스트리는 **Drizzle ORM + better-sqlite3**(`src/db/`). dev는 기동 시 `CREATE TABLE IF NOT EXISTS`, 프로덕션은 `drizzle.config.ts` + drizzle-kit 마이그레이션(드라이버만 Postgres로 교체). DB 파일 경로는 `DB_PATH`(기본 `wallet-provider.db`).

## 상태

- v0 완료: nonce·등록·WUA(PoP 게이트)·key attestation·**revocation**·jwks·CA pem, **SQLite 영속**. e2e(`test/wp-flow.mjs`) 통과.
- 잔여: 프로덕션 무결성 어댑터(Play Integrity/App Attest), Postgres 스왑, SDK `WalletAttestationProvider` 참조 어댑터 + 우리 trust로 WUA 검증 e2e(루프 닫기).

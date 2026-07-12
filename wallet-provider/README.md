# EUDI Wallet Provider (WUA) — NestJS

ARF **Wallet Provider** 백엔드. wallet 인스턴스 무결성을 보증하고 두 가지 attestation을 발급한다:

- **Wallet Unit Attestation (WUA)** — OAuth 2.0 Attestation-Based Client Authentication (`draft-ietf-oauth-attestation-based-client-auth`)의 client attestation JWT. wallet 인스턴스 키를 `cnf.jwk`로 바인딩.
- **Key Attestation** — OpenID4VCI §8.2.1.1 (`keyattestation+jwt`). 크리덴셜 proof 키가 secure area에 있음을 증명.

SDK의 `WalletAttestationProvider` 포트가 이 백엔드에 붙어 HAIP attestation-based client auth를 실물로 완성한다. (모노레포: `eudi-wallet-sdk/wallet-provider`.)

**Play Integrity 설정·검증**(Google Cloud 프로젝트·서비스 계정·클라이언트/백엔드 배선·verdict 읽기·내부테스트로 `PLAY_RECOGNIZED` 받기)은 [`PLAY-INTEGRITY.md`](PLAY-INTEGRITY.md) 참고.

## 엔드포인트

> 모든 경로에 글로벌 prefix **`/wp`**가 붙는다 (예: `GET /wp/nonce`). health는 `/wp/health`(liveness alias)·`/wp/live`·`/wp/ready`(DB 체크).

| 메서드 | 경로 | 역할 |
|---|---|---|
| GET | `/nonce` | 단일사용 challenge nonce |
| POST | `/wallet-instances` | 등록: `{instanceKey(JWK), integrityToken, nonce}` → 무결성 검증 → `{instanceId}` |
| POST | `/wallet-attestation` | WUA 발급: `{instanceId, clientId?, pop}` → `{wallet_attestation}`. `pop`=인스턴스 키로 서명한 JWT(`aud`=WP, `nonce`) |
| POST | `/key-attestation` | `{attestedKeys(JWK[]), nonce?}` → `{key_attestation}`. `nonce`=이슈어 c_nonce |
| POST | `/wallet-instances/:id/revoke` | 인스턴스 revoke (이후 WUA 발급 거부) |
| GET | `/wallet-instances/:id/status` | 인스턴스 상태 `{revoked, createdAt, revokedAt}` — 이슈어의 revocation 체크 |
| GET | `/status-lists/:id` | Token Status List Token(`statuslist+jwt`) — WUA가 `status.status_list{idx,uri}`로 참조. RP가 인스턴스별 조회 없이 압축 비트열로 revoke 확인 (IETF draft-ietf-oauth-status-list). revoke 시 해당 인스턴스의 비트가 INVALID로 flip |
| GET | `/.well-known/jwks.json` | WP 서명 공개키 |
| GET | `/.well-known/wallet-provider-ca.pem` | WP CA 인증서(PEM) — 릴라잉 wallet/issuer가 trust anchor로 설치 |

## 트러스트 (x5c 체인)

WUA/key attestation 헤더의 `x5c` = `[signer 인증서, WP CA]`. 이슈어(또는 우리 SDK trust 모듈)가 **WP CA를 루트로 체인 검증**. dev에선 기동 시 self-signed CA + signer를 생성(`keystore.service.ts`); 프로덕션은 KMS/PKI에서 로드.

## 플랫폼 무결성

`integrity.service.ts`는 pluggable. 실제 Android Play Integrity / iOS App Attest는 Google/Apple 클라우드 크레덴셜 필요 → 기본은 **dev stub**(`dev-integrity:<nonce>` 수용). 프로덕션 verifier를 DI로 교체.

## 설정 (config-less / 전부 환경변수)

설정은 전부 환경변수로 주입한다(이미지에 config 파일 없음). `.env.example`를 복사해 채운다:

```bash
cp .env.example .env      # PORT, STAGE, DATABASE_URL, WP_ISSUER (+ Play Integrity 옵션)
```

기동 시 `env.validation.ts`(class-validator)가 필수 변수를 검증하고, 누락되면 부팅을 거부한다.

## 실행

Postgres(Drizzle ORM)가 필요하다. `DATABASE_URL`을 `.env`에 설정한 뒤:

```bash
pnpm install                                     # pnpm (packageManager 고정)
pnpm db:generate                                 # 스키마 변경 시 SQL 마이그레이션 생성 (drizzle/)
pnpm build && pnpm migrate                       # 마이그레이션 적용 (node dist/migrate)
pnpm start                                        # .env 로드해 기동 (또는 pnpm start:dev)
node test/wp-flow.mjs                            # 전체 플로우 e2e (서버 실행 중일 때)
```

로컬 Postgres 예시: `docker run -d --name wp-pg -p 5432:5432 -e POSTGRES_USER=wp -e POSTGRES_PASSWORD=wp -e POSTGRES_DB=wallet_provider postgres:16`

## 옵저버빌리티

Fastify 어댑터 + `@willsoto/nestjs-prometheus`. Prometheus 메트릭은 글로벌 prefix 아래 **`GET /wp/metrics`** — default Node 메트릭 + HTTP 요청 지연 히스토그램(`http_request_duration_seconds{method,route,status_code}`, health/metrics 경로는 제외). 파드에 `prometheus.io/scrape:"true"`, `prometheus.io/port:"3200"`, `prometheus.io/path:"/wp/metrics"` 어노테이션으로 스크레이프.

## 컨테이너 / 배포

- **Dockerfile** — x64(amd64), node:24-alpine 멀티스테이지, non-root(`wp`), config 없음(런타임 env 주입). `docker build -t wp-api .`
- **시크릿** — `DATABASE_URL`, (선택) `GOOGLE_SERVICE_ACCOUNT_JSON`(서비스계정 키를 파일이 아닌 **JSON 문자열**로 주입)을 런타임 env로. 프로덕션은 AWS Secrets Manager → External Secrets Operator.
- **마이그레이션** — 배포 시 `node dist/migrate`(예: initContainer)로 부팅 전 스키마 적용.
- **k8s 매니페스트는 이 레포에 없음** — 별도 인프라 프로젝트(`k8s-manifests/…/dev/` 스타일)에서 관리한다.

## 영속 (Drizzle + SQLite)

인스턴스 레지스트리는 **Drizzle ORM + better-sqlite3**(`src/db/`). dev는 기동 시 `CREATE TABLE IF NOT EXISTS`, 프로덕션은 `drizzle.config.ts` + drizzle-kit 마이그레이션(드라이버만 Postgres로 교체). DB 파일 경로는 `DB_PATH`(기본 `wallet-provider.db`).

## 상태

- v0 완료: nonce·등록·WUA(PoP 게이트)·key attestation·**revocation**·jwks·CA pem, **SQLite 영속**. e2e(`test/wp-flow.mjs`) 통과.
- 잔여: 프로덕션 무결성 어댑터(Play Integrity/App Attest), Postgres 스왑, SDK `WalletAttestationProvider` 참조 어댑터 + 우리 trust로 WUA 검증 e2e(루프 닫기).

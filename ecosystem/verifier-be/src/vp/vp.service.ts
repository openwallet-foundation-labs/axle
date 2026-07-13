import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes, randomUUID } from 'node:crypto';
import { KeystoreService } from '../crypto/keystore.service';
import { SessionStore, type PresentationSession } from '../session/session.store';
import { RequestBuilderService } from './request-builder.service';
import { VpTokenVerifierService, type VpToken } from './vp-token-verifier.service';
import { REQUESTABLE, parseRequestedKeys, type RequestableKey } from './dcql';

export interface CreatePresentationInput {
  credentials?: unknown;
  mode?: 'qr' | 'dc_api';
  /** Which registrar-issued RP identity signs the request: `plain` (default) or `intermediary`. */
  rp?: string;
  /** dc_api: the web origins the response may come from. */
  origins?: string[];
}

@Injectable()
export class VpService {
  private readonly logger = new Logger(VpService.name);
  private readonly baseUrl: string;

  constructor(
    private readonly keystore: KeystoreService,
    private readonly requestBuilder: RequestBuilderService,
    private readonly verifier: VpTokenVerifierService,
    private readonly sessions: SessionStore,
    config: ConfigService,
  ) {
    this.baseUrl = config.getOrThrow<string>('VERIFIER_BASE_URL').replace(/\/$/, '');
  }

  /** Creates a presentation request. `qr` returns an openid4vp:// URL; `dc_api` returns the request object. */
  async createPresentation(input: CreatePresentationInput) {
    const keys = parseRequestedKeys(input.credentials);
    const mode = input.mode === 'dc_api' ? 'dc_api' : 'qr';
    const rp = this.keystore.resolve(input.rp === 'intermediary' ? 'intermediary' : 'plain');
    const id = randomUUID();
    const nonce = randomBytes(16).toString('base64url');

    let session: PresentationSession;
    if (mode === 'dc_api') {
      const origins = input.origins?.length ? input.origins : [this.baseUrl];
      const { jwt } = await this.requestBuilder.buildForDcApi(keys, nonce, origins, rp);
      session = { id, nonce, requested: keys, mode, rp, requestJwt: jwt, expectedOrigins: origins, createdAt: Date.now() };
    } else {
      const { jwt } = await this.requestBuilder.buildForQr(id, keys, nonce, rp);
      session = { id, nonce, requested: keys, mode, rp, requestJwt: jwt, createdAt: Date.now() };
    }
    await this.sessions.put(session);
    this.logger.log(`presentation ${id} created (mode=${mode}, rp=${rp}, credentials=${keys.join(',')})`);

    return {
      transaction_id: id,
      mode,
      rp,
      requested: keys.map((k) => ({ key: k, label: REQUESTABLE[k].label })),
      ...(mode === 'qr'
        ? {
            client_id: this.keystore.clientId(rp),
            request_uri: `${this.baseUrl}/request/${id}`,
            // The QR / deep-link the wallet scans (OpenID4VP §5, request_uri flow).
            qr: `openid4vp://?client_id=${encodeURIComponent(this.keystore.clientId(rp))}&request_uri=${encodeURIComponent(
              `${this.baseUrl}/request/${id}`,
            )}`,
          }
        : {
            // For the Digital Credentials API: the frontend passes this to navigator.credentials.get.
            dc_api_request: { protocol: 'openid4vp', request: { request: session.requestJwt } },
          }),
    };
  }

  async getRequestJwt(id: string): Promise<string> {
    const session = await this.sessions.get(id);
    if (!session) throw new Error('unknown or expired transaction');
    return session.requestJwt;
  }

  /** direct_post (QR channel): the wallet POSTs { vp_token, state } to the response_uri. */
  async submitDirectPost(id: string, body: Record<string, unknown>) {
    const session = await this.sessions.get(id);
    if (!session) throw new Error('unknown or expired transaction');
    const vpToken = this.parseVpToken(body.vp_token);
    await this.finish(session, vpToken, {
      nonce: session.nonce,
      mode: 'qr',
      clientId: this.keystore.clientId(session.rp),
      responseUri: `${this.baseUrl}/response/${id}`,
    });
    return { status: 'ok' };
  }

  /** Digital Credentials API channel: the frontend posts back the wallet's response + calling origin. */
  async submitDcApi(id: string, body: { vp_token?: unknown; origin?: string }) {
    const session = await this.sessions.get(id);
    if (!session) throw new Error('unknown or expired transaction');
    const origin = body.origin ?? '';
    if (session.expectedOrigins && !session.expectedOrigins.includes(origin)) {
      throw new Error(`origin '${origin}' is not in expected_origins`);
    }
    const vpToken = this.parseVpToken(body.vp_token);
    await this.finish(session, vpToken, {
      nonce: session.nonce,
      mode: 'dc_api',
      clientId: this.keystore.clientId(session.rp),
      origin,
    });
    return { status: 'ok' };
  }

  async getResult(id: string) {
    const session = await this.sessions.get(id);
    if (!session) throw new Error('unknown or expired transaction');
    return {
      transaction_id: id,
      status: session.result ? session.result.status : 'pending',
      credentials: session.result?.credentials,
      error: session.result?.error,
    };
  }

  private async finish(
    session: PresentationSession,
    vpToken: VpToken,
    binding: { nonce: string; mode: 'qr' | 'dc_api'; clientId: string; responseUri?: string; origin?: string },
  ): Promise<void> {
    try {
      const credentials = await this.verifier.verify(vpToken, session.requested, binding);
      session.result = { status: 'verified', credentials, verifiedAt: Date.now() };
      this.logger.log(`presentation ${session.id} VERIFIED (${credentials.map((c) => c.type).join(', ')})`);
    } catch (e) {
      // Record the failure for the polling frontend; the wallet's POST still gets a 200 acknowledgement.
      session.result = { status: 'failed', error: (e as Error).message, verifiedAt: Date.now() };
      this.logger.warn(`presentation ${session.id} FAILED: ${(e as Error).message}`);
    } finally {
      await this.sessions.put(session);
    }
  }

  private parseVpToken(raw: unknown): VpToken {
    if (raw == null) throw new Error('response has no vp_token');
    const value = typeof raw === 'string' ? (JSON.parse(raw) as unknown) : raw;
    if (typeof value !== 'object') throw new Error('vp_token must be a DCQL-keyed object');
    return value as VpToken;
  }

  /** Exposed for tests / introspection. */
  requestableKeys(): RequestableKey[] {
    return Object.keys(REQUESTABLE) as RequestableKey[];
  }
}

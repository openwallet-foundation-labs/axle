import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash, randomBytes } from 'node:crypto';
import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, jwtVerify, type JWK } from 'jose';
import { SessionStore } from '../session/session.store';
import { IssuerJwtService } from '../jwt/issuer-jwt.service';
import { SdJwtService } from '../credentials/sd-jwt.service';
import { MdocService } from '../credentials/mdoc.service';
import { StatusListService } from '../status-list/status-list.service';
import { KeyAttestationService } from '../attestation/key-attestation.service';
import type { AttestationResult } from '../attestation/wallet-attestation.guard';
import { CREDENTIAL_CONFIGS, getConfig, getConfigByScope, type CredentialConfig } from './credential-configs';
import { OAuthError } from './oauth-error';

const rand = (n = 32) => randomBytes(n).toString('base64url');
const s256 = (v: string) => createHash('sha256').update(v).digest('base64url');

interface AuthRequest {
  configIds: string[];
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  state?: string;
  dpop_jkt?: string;
}

/**
 * OpenID4VCI 1.0 + HAIP issuance logic. Authorization-code flow (PID) with a browser consent step delegated to
 * issuer-fe, and pre-authorized-code flow (mDL). DPoP-bound access tokens; proofs + key attestations verified
 * at the credential endpoint; each credential gets a Token Status List index; claims are hardcoded (sandbox).
 */
@Injectable()
export class VciService {
  private readonly logger = new Logger(VciService.name);

  constructor(
    private readonly store: SessionStore,
    private readonly issuerJwt: IssuerJwtService,
    private readonly sdJwt: SdJwtService,
    private readonly mdoc: MdocService,
    private readonly statusList: StatusListService,
    private readonly keyAttestation: KeyAttestationService,
    private readonly config: ConfigService,
  ) {}

  private get issuer(): string {
    return this.config.getOrThrow<string>('ISSUER_BASE_URL');
  }
  private get feUrl(): string {
    return this.config.get<string>('ISSUER_FE_URL') ?? 'http://localhost:5175';
  }

  // ---- Pushed Authorization Request (RFC 9126) ---------------------------------------------------------
  async pushAuthorizationRequest(body: Record<string, string>, att: AttestationResult): Promise<{ request_uri: string; expires_in: number }> {
    if (body.request_uri) throw new OAuthError('invalid_request', 'request_uri not allowed in PAR');
    if (body.response_type !== 'code') throw new OAuthError('invalid_request', 'response_type must be code');
    if (!body.code_challenge || body.code_challenge_method !== 'S256') {
      throw new OAuthError('invalid_request', 'PKCE S256 required');
    }
    if (!body.redirect_uri) throw new OAuthError('invalid_request', 'redirect_uri required');
    if (!att.dev && body.client_id !== att.sub) throw new OAuthError('invalid_request', 'client_id must equal attestation sub');

    const configIds = this.resolveAuthCodeConfigs(body.scope, body.authorization_details);
    if (!configIds.length) throw new OAuthError('invalid_scope', 'no authorization_code credential in scope');

    const requestUri = `urn:ietf:params:oauth:request_uri:${rand()}`;
    const session: AuthRequest = {
      configIds,
      client_id: body.client_id ?? att.sub,
      redirect_uri: body.redirect_uri,
      code_challenge: body.code_challenge,
      code_challenge_method: 'S256',
      state: body.state,
      dpop_jkt: body.dpop_jkt,
    };
    await this.store.set(`par:${requestUri}`, session, 300);
    return { request_uri: requestUri, expires_in: 300 };
  }

  private resolveAuthCodeConfigs(scope?: string, authorizationDetails?: string): string[] {
    const ids = new Set<string>();
    for (const s of (scope ?? '').split(' ').filter(Boolean)) {
      const c = getConfigByScope(s);
      if (c?.flow === 'authorization_code') ids.add(c.id);
    }
    if (authorizationDetails) {
      try {
        for (const d of JSON.parse(authorizationDetails) as Array<{ type: string; credential_configuration_id: string }>) {
          const c = d.type === 'openid_credential' ? getConfig(d.credential_configuration_id) : undefined;
          if (c?.flow === 'authorization_code') ids.add(c.id);
        }
      } catch {
        /* ignore malformed authorization_details */
      }
    }
    return [...ids];
  }

  // ---- Authorization endpoint → hand off to issuer-fe consent -----------------------------------------
  async authorize(query: Record<string, string>): Promise<string> {
    const requestUri = query.request_uri;
    if (!requestUri) throw new OAuthError('invalid_request', 'request_uri required (PAR)');
    const session = await this.store.get<AuthRequest>(`par:${requestUri}`);
    if (!session) throw new OAuthError('invalid_request', 'unknown or expired request_uri');
    if (query.client_id && query.client_id !== session.client_id) throw new OAuthError('invalid_request', 'client_id mismatch');

    const interactionId = rand(16);
    await this.store.set(`auth:${interactionId}`, session, 600);
    await this.store.del(`par:${requestUri}`);
    return `${this.feUrl}/authorize?session=${interactionId}`;
  }

  /** issuer-fe fetches this to render the consent screen. */
  async getInteraction(interactionId: string) {
    const session = await this.store.get<AuthRequest>(`auth:${interactionId}`);
    if (!session) throw new OAuthError('invalid_request', 'unknown or expired interaction', 404);
    return {
      demo: true,
      client_id: session.client_id,
      credentials: session.configIds.map((id) => {
        const c = getConfig(id)!;
        return { id, name: c.display.name, format: c.format, fields: c.displayFields };
      }),
    };
  }

  /** issuer-fe posts the user's decision; returns the wallet redirect URL. */
  async decideInteraction(interactionId: string, approve: boolean): Promise<{ redirect: string }> {
    const session = await this.store.getdel<AuthRequest>(`auth:${interactionId}`);
    if (!session) throw new OAuthError('invalid_request', 'unknown or expired interaction', 404);
    const url = new URL(session.redirect_uri);
    if (session.state) url.searchParams.set('state', session.state);
    if (!approve) {
      url.searchParams.set('error', 'access_denied');
      return { redirect: url.toString() };
    }
    const code = rand();
    await this.store.set(
      `authz:${code}`,
      { configIds: session.configIds, client_id: session.client_id, redirect_uri: session.redirect_uri, code_challenge: session.code_challenge, dpop_jkt: session.dpop_jkt },
      60,
    );
    url.searchParams.set('code', code);
    url.searchParams.set('iss', this.issuer);
    return { redirect: url.toString() };
  }

  // ---- Credential Offer (pre-authorized_code, mDL) ----------------------------------------------------
  async createCredentialOffer(configId: string): Promise<{ credential_offer: unknown; credential_offer_uri: string; deep_link: string }> {
    const c = getConfig(configId);
    if (!c || c.flow !== 'pre-authorized_code') throw new OAuthError('invalid_request', 'not a pre-authorized credential');
    const preAuthCode = rand();
    await this.store.set(`pre-auth:${preAuthCode}`, { configIds: [configId] }, 600);
    const offer = {
      credential_issuer: this.issuer,
      credential_configuration_ids: [configId],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': preAuthCode },
      },
    };
    const offerId = rand(16);
    await this.store.set(`offer:${offerId}`, offer, 600);
    const credential_offer_uri = `${this.issuer}/credential-offer/${offerId}`;
    return { credential_offer: offer, credential_offer_uri, deep_link: `haip-vci://?credential_offer_uri=${encodeURIComponent(credential_offer_uri)}` };
  }

  async getCredentialOffer(offerId: string) {
    const offer = await this.store.get(`offer:${offerId}`);
    if (!offer) throw new OAuthError('invalid_request', 'unknown or expired offer', 404);
    return offer;
  }

  // ---- Token endpoint ---------------------------------------------------------------------------------
  async token(body: Record<string, string>, att: AttestationResult, dpopJkt: string) {
    const grant = body.grant_type;
    let configIds: string[];

    if (grant === 'authorization_code') {
      const session = await this.store.getdel<AuthRequest & { code_challenge: string }>(`authz:${body.code}`);
      if (!session) throw new OAuthError('invalid_grant', 'invalid or used authorization code');
      if (body.redirect_uri !== session.redirect_uri) throw new OAuthError('invalid_grant', 'redirect_uri mismatch');
      if (!att.dev && att.sub !== session.client_id) throw new OAuthError('invalid_grant', 'client_id mismatch');
      if (!body.code_verifier || s256(body.code_verifier) !== session.code_challenge) {
        throw new OAuthError('invalid_grant', 'PKCE verification failed');
      }
      if (session.dpop_jkt && session.dpop_jkt !== dpopJkt) throw new OAuthError('invalid_dpop_proof', 'dpop_jkt mismatch');
      configIds = session.configIds;
    } else if (grant === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
      const session = await this.store.getdel<{ configIds: string[] }>(`pre-auth:${body['pre-authorized_code']}`);
      if (!session) throw new OAuthError('invalid_grant', 'invalid or used pre-authorized_code');
      configIds = session.configIds;
    } else {
      throw new OAuthError('unsupported_grant_type', `grant_type ${grant}`);
    }

    const access_token = await this.issuerJwt.sign(
      { cnf: { jkt: dpopJkt }, authorized_configs: configIds },
      { typ: 'at+jwt', sub: att.sub, aud: this.issuer, expSec: 3600 },
    );
    return {
      access_token,
      token_type: 'DPoP',
      expires_in: 3600,
      authorization_details: configIds.map((id) => ({
        type: 'openid_credential',
        credential_configuration_id: id,
        credential_identifiers: [id],
      })),
    };
  }

  // ---- Nonce endpoint ---------------------------------------------------------------------------------
  async nonce(): Promise<{ c_nonce: string }> {
    const c_nonce = await this.issuerJwt.sign({ jti: rand(16) }, { typ: 'c_nonce+jwt', sub: 'c_nonce', aud: this.issuer, expSec: 300 });
    return { c_nonce };
  }

  // ---- Credential endpoint ----------------------------------------------------------------------------
  async credential(body: Record<string, unknown>, accessToken: Record<string, unknown>): Promise<{ credentials: Array<{ credential: string }> }> {
    const authorized = (accessToken.authorized_configs as string[] | undefined) ?? [];
    const configId = (body.credential_configuration_id as string | undefined) ?? (authorized.length === 1 ? authorized[0] : undefined);
    if (!configId || !authorized.includes(configId)) throw new OAuthError('invalid_credential_request', 'credential_configuration_id not authorized');
    const c = getConfig(configId)!;

    const proof = (body.proof as { proof_type?: string; jwt?: string } | undefined) ?? undefined;
    const proofs = body.proofs as { jwt?: string[] } | undefined;
    const proofJwt = proof?.jwt ?? proofs?.jwt?.[0];
    if (!proofJwt) throw new OAuthError('invalid_proof', 'jwt proof required');

    const holderJwk = await this.verifyProof(proofJwt);

    const cred = await this.issueCredential(c, holderJwk);
    return { credentials: [{ credential: cred }] };
  }

  private async verifyProof(proofJwt: string): Promise<JWK> {
    const header = decodeProtectedHeader(proofJwt);
    if (header.typ !== 'openid4vci-proof+jwt') throw new OAuthError('invalid_proof', 'bad proof typ');
    const holderJwk = header.jwk as JWK | undefined;
    if (!holderJwk) throw new OAuthError('invalid_proof', 'proof missing jwk');

    let payload;
    try {
      const verified = await jwtVerify(proofJwt, await importJWK(holderJwk, header.alg ?? 'ES256'), { audience: this.issuer });
      payload = verified.payload;
    } catch {
      throw new OAuthError('invalid_proof', 'proof signature invalid');
    }

    // nonce = the c_nonce we issued; single-use.
    const nonce = payload.nonce as string | undefined;
    if (!nonce) throw new OAuthError('invalid_proof', 'proof nonce required');
    try {
      const np = await this.issuerJwt.verify(nonce, { typ: 'c_nonce+jwt', aud: this.issuer });
      if (!np.jti || !(await this.store.setOnce(`c_nonce:${np.jti}`, 300))) throw new Error('nonce replay');
    } catch {
      throw new OAuthError('invalid_nonce', 'invalid or used c_nonce');
    }

    await this.keyAttestation.verify(header as Record<string, unknown>, holderJwk, nonce);
    return holderJwk;
  }

  private async issueCredential(c: CredentialConfig, holderJwk: JWK): Promise<string> {
    const holderJkt = await calculateJwkThumbprint(holderJwk, 'sha256');
    const status = await this.statusList.recordIssuance(c.id, c.format, holderJkt);
    const now = Math.floor(Date.now() / 1000);

    if (c.format === 'dc+sd-jwt') {
      const payload = {
        iss: this.issuer,
        vct: c.vct,
        ...c.sdJwtClaims,
        iat: now,
        exp: now + 63072000, // +2 years
        cnf: { jwk: holderJwk },
        status: { status_list: { idx: status.idx, uri: status.uri } },
      };
      return this.sdJwt.issue(payload, { _sd: c.sdJwtDisclose ?? [] } as never, c.signer);
    }
    // mso_mdoc — NOTE: the issuance is recorded in the status list (status.idx above) but the reference is NOT
    // embedded in the credential: @lukas.j.han/mdoc 0.5.11 has no MSO `status` element (ISO/IEC 18013-5 2nd
    // edition). So mdoc revocation via status list is deferred; mdoc currently relies on validityInfo (exp).
    return this.mdoc.issue(c.doctype!, c.mdocNamespaces!, holderJwk, c.signer);
  }

  listConfigs() {
    return CREDENTIAL_CONFIGS;
  }
}

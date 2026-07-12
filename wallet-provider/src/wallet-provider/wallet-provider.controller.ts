import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Header,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Post,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import * as jose from 'jose';
import { AdminApiKeyGuard } from './admin-api-key.guard';
import { AttestationService } from '../attestation/attestation.service';
import { KeystoreService } from '../attestation/keystore.service';
import { PlatformVerifierRegistry } from '../platform/platform-verifier';
import { statusListUri } from '../status-list/status-list.codec';
import { StatusListRevision } from '../status-list/status-list-revision';
import { KeyAttestationDto, RegisterInstanceDto, WalletAttestationDto } from './dto';
import { InstanceRepository } from './instance.repository';
import { NonceService } from './nonce.service';

@Controller()
export class WalletProviderController {
  constructor(
    private readonly keystore: KeystoreService,
    private readonly nonce: NonceService,
    private readonly verifiers: PlatformVerifierRegistry,
    private readonly instances: InstanceRepository,
    private readonly attestation: AttestationService,
    private readonly statusRevision: StatusListRevision,
  ) {}

  /** Challenge nonce for registration and attestation PoP. */
  @Get('nonce')
  async getNonce(): Promise<{ nonce: string }> {
    return { nonce: await this.nonce.issue() };
  }

  /** Register a wallet instance after a device-integrity check. */
  @Post('wallet-instances')
  async register(@Body() dto: RegisterInstanceDto): Promise<{ instanceId: string }> {
    if (!(await this.nonce.consume(dto.nonce))) throw new BadRequestException('invalid or expired nonce');
    const verifier = this.verifiers.for(dto.platform ?? 'android');
    const integrity = await verifier.verifyIntegrity(dto.integrityToken, dto.nonce);
    if (!integrity.trusted) throw new UnauthorizedException(`device integrity failed: ${integrity.reason}`);
    const instance = await this.instances.create(dto.instanceKey, integrity.platform);
    return { instanceId: instance.instanceId };
  }

  /** Revoke a wallet instance — it can no longer obtain a WUA (soft revocation). Admin-only. */
  @Post('wallet-instances/:id/revoke')
  @UseGuards(AdminApiKeyGuard)
  async revoke(@Param('id', ParseUUIDPipe) id: string): Promise<{ revoked: boolean }> {
    if (!(await this.instances.revoke(id))) throw new NotFoundException('unknown instance');
    this.statusRevision.bump(); // invalidate the cached status list so the flip is reflected promptly
    return { revoked: true };
  }

  /** Instance status — issuers/relying parties check whether a WUA's instance is still valid. */
  @Get('wallet-instances/:id/status')
  async status(@Param('id', ParseUUIDPipe) id: string): Promise<{ instanceId: string; revoked: boolean; createdAt: number; revokedAt: number | null }> {
    const instance = await this.instances.get(id);
    if (!instance) throw new NotFoundException('unknown instance');
    return { instanceId: instance.instanceId, revoked: instance.revoked, createdAt: instance.createdAt, revokedAt: instance.revokedAt };
  }

  /** Issue a Wallet Unit Attestation, gated on a PoP proving possession of the instance key. */
  @Post('wallet-attestation')
  async walletAttestation(@Body() dto: WalletAttestationDto): Promise<{ wallet_attestation: string }> {
    const instance = await this.instances.get(dto.instanceId);
    if (!instance || instance.revoked) throw new UnauthorizedException('unknown or revoked instance');

    let pop: jose.JWTPayload;
    try {
      const key = await jose.importJWK(instance.publicJwk, 'ES256');
      pop = (await jose.jwtVerify(dto.pop, key, { audience: this.keystore.issuer })).payload;
    } catch {
      throw new UnauthorizedException('invalid instance PoP');
    }
    if (!(await this.nonce.consume(pop.nonce as string | undefined))) throw new BadRequestException('invalid or expired nonce');

    // Reference the Token Status List by the instance's stable index — refreshing a WUA reuses it; only
    // revoking the instance flips the bit. (The instance owns the index, not the individual WUA.)
    const statusRef = { idx: instance.statusIdx, uri: statusListUri(this.keystore.issuer) };
    const wua = await this.attestation.issueWalletAttestation(
      instance.publicJwk,
      dto.clientId ?? instance.instanceId,
      statusRef,
    );
    return { wallet_attestation: wua };
  }

  /** Issue a key attestation for credential proof keys (nonce = issuer c_nonce, passed through). */
  @Post('key-attestation')
  async keyAttestation(@Body() dto: KeyAttestationDto): Promise<{ key_attestation: string }> {
    if (!dto.attestedKeys?.length) throw new BadRequestException('attestedKeys required');
    const verifier = this.verifiers.for(dto.platform ?? 'android');
    const { level } = await verifier.verifyKeyAttestation(dto.keyAttestations, dto.nonce);
    const ka = await this.attestation.issueKeyAttestation(dto.attestedKeys, level, dto.nonce);
    return { key_attestation: ka };
  }

  /** WP signing public key — issuers may verify WUA signatures via JWKS instead of x5c. */
  @Get('.well-known/jwks.json')
  jwks(): { keys: jose.JWK[] } {
    return { keys: [this.keystore.publicJwk] };
  }

  /** WP CA certificate (PEM) — a relying wallet/issuer installs it as a trust anchor. */
  @Get('.well-known/wallet-provider-ca.pem')
  @Header('content-type', 'application/x-pem-file')
  caPem(): string {
    return this.keystore.caPem();
  }
}

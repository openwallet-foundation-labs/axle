import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Header,
  NotFoundException,
  Param,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import * as jose from 'jose';
import { AttestationService } from './attestation.service';
import { KeyAttestationDto, RegisterInstanceDto, WalletAttestationDto } from './dto';
import { InstanceRepository } from './instance.repository';
import { IntegrityService } from './integrity.service';
import { KeystoreService } from './keystore.service';
import { NonceService } from './nonce.service';

@Controller()
export class WalletProviderController {
  constructor(
    private readonly keystore: KeystoreService,
    private readonly nonce: NonceService,
    private readonly integrity: IntegrityService,
    private readonly instances: InstanceRepository,
    private readonly attestation: AttestationService,
  ) {}

  /** Challenge nonce for registration and attestation PoP. */
  @Get('nonce')
  getNonce(): { nonce: string } {
    return { nonce: this.nonce.issue() };
  }

  /** Register a wallet instance after a device-integrity check. */
  @Post('wallet-instances')
  async register(@Body() dto: RegisterInstanceDto): Promise<{ instanceId: string }> {
    if (!this.nonce.consume(dto.nonce)) throw new BadRequestException('invalid or expired nonce');
    const integrity = await this.integrity.verify(dto.integrityToken, dto.nonce);
    if (!integrity.trusted) throw new UnauthorizedException(`device integrity failed: ${integrity.reason}`);
    const instance = await this.instances.create(dto.instanceKey, integrity.platform);
    return { instanceId: instance.instanceId };
  }

  /** Revoke a wallet instance — it can no longer obtain a WUA (soft revocation). */
  @Post('wallet-instances/:id/revoke')
  async revoke(@Param('id') id: string): Promise<{ revoked: boolean }> {
    if (!(await this.instances.revoke(id))) throw new NotFoundException('unknown instance');
    return { revoked: true };
  }

  /** Instance status — issuers/relying parties check whether a WUA's instance is still valid. */
  @Get('wallet-instances/:id/status')
  async status(@Param('id') id: string): Promise<{ instanceId: string; revoked: boolean; createdAt: number; revokedAt: number | null }> {
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
    if (!this.nonce.consume(pop.nonce as string | undefined)) throw new BadRequestException('invalid or expired nonce');

    const wua = await this.attestation.issueWalletAttestation(instance.publicJwk, dto.clientId ?? instance.instanceId);
    return { wallet_attestation: wua };
  }

  /** Issue a key attestation for credential proof keys (nonce = issuer c_nonce, passed through). */
  @Post('key-attestation')
  async keyAttestation(@Body() dto: KeyAttestationDto): Promise<{ key_attestation: string }> {
    if (!dto.attestedKeys?.length) throw new BadRequestException('attestedKeys required');
    const ka = await this.attestation.issueKeyAttestation(dto.attestedKeys, dto.nonce);
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

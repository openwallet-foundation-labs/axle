import { IsArray, IsIn, IsNotEmpty, IsObject, IsOptional, IsString } from 'class-validator';
import type { JWK } from 'jose';
import type { WalletPlatform } from '../platform/platform-verifier';

/** POST /wallet-instances — register a wallet instance after a device-integrity check. */
export class RegisterInstanceDto {
  @IsObject()
  instanceKey!: JWK; // the wallet instance public key (bound into the WUA cnf)

  @IsString()
  @IsNotEmpty()
  integrityToken!: string; // Play Integrity / App Attest token (dev: `dev-integrity:<nonce>`)

  @IsString()
  @IsNotEmpty()
  nonce!: string; // from GET /nonce

  @IsOptional()
  @IsIn(['android', 'ios'])
  platform?: WalletPlatform; // selects the verifier; defaults to 'android'
}

/** POST /wallet-attestation — obtain a WUA; `pop` proves possession of the instance key. */
export class WalletAttestationDto {
  @IsString()
  @IsNotEmpty()
  instanceId!: string;

  @IsOptional()
  @IsString()
  clientId?: string; // WUA subject; defaults to instanceId

  @IsString()
  @IsNotEmpty()
  pop!: string; // JWT signed by the instance key: { aud: WP issuer, nonce, iat }
}

/** POST /key-attestation — attest credential proof keys; `nonce` is the issuer's c_nonce. */
export class KeyAttestationDto {
  @IsArray()
  attestedKeys!: JWK[];

  @IsOptional()
  @IsString()
  nonce?: string;

  @IsOptional()
  @IsArray()
  keyAttestations?: string[]; // base64 android-keystore-x5c chains (one per key) → verified to assert the storage level

  @IsOptional()
  @IsIn(['android', 'ios'])
  platform?: WalletPlatform; // selects the verifier; defaults to 'android'
}

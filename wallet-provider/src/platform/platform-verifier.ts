import { Inject, Injectable } from '@nestjs/common';

export type WalletPlatform = 'android' | 'ios';

/** Result of the registration-time device/app integrity check. */
export interface IntegrityResult {
  trusted: boolean;
  platform: WalletPlatform | 'dev';
  reason?: string;
}

/** Truthful ARF `key_storage` assurance, derived from hardware attestation evidence (not on faith). */
export interface KeyAttestationVerdict {
  level: 'iso_18045_high' | 'iso_18045_moderate';
}

/**
 * Per-platform verification strategy. Everything the Wallet Provider *checks* about a client that varies
 * by OS lives behind this: registration integrity (Android Play Integrity / iOS App Attest) and the
 * credential-key hardware attestation. Issuance (WUA/key-attestation signing) stays platform-agnostic.
 */
export interface PlatformVerifier {
  readonly platform: WalletPlatform;
  verifyIntegrity(integrityToken: string | undefined, challenge: string): Promise<IntegrityResult>;
  verifyKeyAttestation(keyAttestations: string[] | undefined, challenge?: string): Promise<KeyAttestationVerdict>;
}

/**
 * Dev bypass: the reference wallet emits `dev-integrity:<nonce>` when a real Play Integrity / App Attest
 * verdict is unavailable (local dev, demo fallback). Accepted by every platform so those flows work.
 */
export function devIntegrity(
  token: string | undefined,
  challenge: string,
  platform: WalletPlatform,
): IntegrityResult | null {
  return token === `dev-integrity:${challenge}` ? { trusted: true, platform } : null;
}

/** DI token for the list of registered platform verifiers. */
export const PLATFORM_VERIFIERS = Symbol('PLATFORM_VERIFIERS');

/** Dispatches to the verifier registered for a given platform. */
@Injectable()
export class PlatformVerifierRegistry {
  private readonly byPlatform: Map<WalletPlatform, PlatformVerifier>;

  constructor(@Inject(PLATFORM_VERIFIERS) verifiers: PlatformVerifier[]) {
    this.byPlatform = new Map(verifiers.map((v) => [v.platform, v]));
  }

  for(platform: WalletPlatform): PlatformVerifier {
    const verifier = this.byPlatform.get(platform);
    if (!verifier) throw new Error(`unsupported wallet platform: ${platform}`);
    return verifier;
  }
}

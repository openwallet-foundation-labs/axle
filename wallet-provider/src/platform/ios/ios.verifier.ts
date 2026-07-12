import { Injectable, Logger } from '@nestjs/common';
import {
  devIntegrity,
  type IntegrityResult,
  type KeyAttestationVerdict,
  type PlatformVerifier,
} from '../platform-verifier';

/**
 * iOS verification via Apple App Attest / DeviceCheck. Not yet implemented — the reference iOS holder
 * doesn't exist yet (swift/ is a UI-less library). Registered so the platform seam is complete and dev
 * flows work; real App Attest (attestation object at registration + assertions for key possession) slots
 * in here without touching the controller.
 */
@Injectable()
export class IosVerifier implements PlatformVerifier {
  readonly platform = 'ios' as const;
  private readonly logger = new Logger(IosVerifier.name);

  async verifyIntegrity(integrityToken: string | undefined, challenge: string): Promise<IntegrityResult> {
    const dev = devIntegrity(integrityToken, challenge, 'ios');
    if (dev) return dev;
    this.logger.warn('iOS App Attest verification is not implemented — rejecting non-dev integrity token');
    return { trusted: false, platform: 'ios', reason: 'iOS App Attest not implemented' };
  }

  async verifyKeyAttestation(): Promise<KeyAttestationVerdict> {
    // iOS has no X.509 key-attestation chain; App Attest assertions would raise this above moderate.
    return { level: 'iso_18045_moderate' };
  }
}

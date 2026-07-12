import { Module } from '@nestjs/common';
import { AttestationService } from './attestation.service';
import { KeystoreService } from './keystore.service';

/** Platform-agnostic issuance of the WP's own artifacts: WUA + key attestation, signed with the WP chain. */
@Module({
  providers: [KeystoreService, AttestationService],
  exports: [KeystoreService, AttestationService],
})
export class AttestationModule {}

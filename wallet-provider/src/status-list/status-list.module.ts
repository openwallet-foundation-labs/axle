import { Module } from '@nestjs/common';
import { AttestationModule } from '../attestation/attestation.module';
import { WalletProviderModule } from '../wallet-provider/wallet-provider.module';
import { StatusListController } from './status-list.controller';
import { StatusListService } from './status-list.service';

/**
 * IETF Token Status List (draft-ietf-oauth-status-list) publication for wallet-instance WUAs. Depends on
 * the WP keystore (AttestationModule) for signing and the instance registry (WalletProviderModule) for the
 * revocation bits.
 */
@Module({
  imports: [AttestationModule, WalletProviderModule],
  controllers: [StatusListController],
  providers: [StatusListService],
  exports: [StatusListService],
})
export class StatusListModule {}

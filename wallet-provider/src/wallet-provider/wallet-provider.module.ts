import { Module } from '@nestjs/common';
import { AttestationModule } from '../attestation/attestation.module';
import { PlatformModule } from '../platform/platform.module';
import { InstanceRepository } from './instance.repository';
import { NonceService } from './nonce.service';
import { WalletProviderController } from './wallet-provider.controller';

/**
 * ARF Wallet Provider: registers wallet instances and issues WUA + key attestations. The HTTP surface is
 * platform-neutral; per-platform verification comes from `PlatformModule`, issuance from `AttestationModule`.
 */
@Module({
  imports: [AttestationModule, PlatformModule],
  controllers: [WalletProviderController],
  providers: [NonceService, InstanceRepository],
  exports: [InstanceRepository],
})
export class WalletProviderModule {}

import { Global, Module } from '@nestjs/common';
import { TrustedListService } from './trusted-list.service';

@Global()
@Module({
  providers: [TrustedListService],
  exports: [TrustedListService],
})
export class TrustModule {}

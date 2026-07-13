import { Module } from '@nestjs/common';
import { VpController } from './vp.controller';
import { VpService } from './vp.service';
import { RequestBuilderService } from './request-builder.service';
import { VpTokenVerifierService } from './vp-token-verifier.service';

@Module({
  controllers: [VpController],
  providers: [VpService, RequestBuilderService, VpTokenVerifierService],
})
export class VpModule {}

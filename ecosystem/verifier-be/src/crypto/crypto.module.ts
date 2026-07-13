import { Global, Module } from '@nestjs/common';
import { KeystoreService } from './keystore.service';

@Global()
@Module({
  providers: [KeystoreService],
  exports: [KeystoreService],
})
export class CryptoModule {}

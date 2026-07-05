import { Module } from '@nestjs/common';
import { DrizzleModule } from './db/drizzle.module';
import { WalletProviderModule } from './wallet-provider/wallet-provider.module';

@Module({
  imports: [DrizzleModule, WalletProviderModule],
})
export class AppModule {}

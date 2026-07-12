import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { LoggerModule } from 'nestjs-pino';
import { PrometheusModule } from '@willsoto/nestjs-prometheus';
import { validate } from './env.validation';
import { createLoggerConfig } from './logger.config';
import { DrizzleModule } from './db/drizzle.module';
import { HealthModule } from './modules/health/health.module';
import { MetricsModule } from './modules/metrics/metrics.module';
import { WalletProviderModule } from './wallet-provider/wallet-provider.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, validate }),
    LoggerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => createLoggerConfig(config),
    }),
    DrizzleModule,
    PrometheusModule.register({ defaultMetrics: { enabled: true } }),
    MetricsModule,
    HealthModule,
    WalletProviderModule,
  ],
})
export class AppModule {}

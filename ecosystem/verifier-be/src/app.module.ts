import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { LoggerModule } from 'nestjs-pino';
import { PrometheusModule } from '@willsoto/nestjs-prometheus';
import { createLoggerConfig } from './logger.config';
import { validate } from './env.validation';
import { MetricsModule } from './modules/metrics/metrics.module';
import { HealthModule } from './modules/health/health.module';
import { CryptoModule } from './crypto/crypto.module';
import { TrustModule } from './trust/trust.module';
import { SessionModule } from './session/session.module';
import { VpModule } from './vp/vp.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, validate }),
    LoggerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: createLoggerConfig,
    }),
    PrometheusModule.register({ defaultMetrics: { enabled: true } }),
    MetricsModule,
    HealthModule,
    CryptoModule,
    TrustModule,
    SessionModule,
    VpModule,
  ],
})
export class AppModule {}

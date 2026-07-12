import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { Logger } from 'nestjs-pino';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({ trustProxy: true }),
    { bufferLogs: true },
  );
  app.useLogger(app.get(Logger)); // route Nest's logs through pino
  app.enableShutdownHooks();
  app.enableCors();
  app.useGlobalPipes(new ValidationPipe({ whitelist: false, transform: true }));
  app.setGlobalPrefix('wp');

  const port = process.env.PORT ?? 3200;
  await app.listen(port, '0.0.0.0');
  app.get(Logger).log(`EUDI Wallet Provider listening on :${port} (prefix /wp)`, 'Bootstrap');
}
void bootstrap();

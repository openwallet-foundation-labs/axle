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
  app.useLogger(app.get(Logger));
  app.enableShutdownHooks();

  // The verifier-fe (browser) polls the presentation result cross-origin.
  app.enableCors({});

  // The wallet fetches the request object as application/oauth-authz-req+jwt and POSTs the response as
  // application/x-www-form-urlencoded (already parsed by the Fastify adapter). Add a raw-string parser for
  // the signed JWT content type so `GET /request/:id` can serve it verbatim if ever re-posted.
  const fastify = app.getHttpAdapter().getInstance();
  fastify.addContentTypeParser('application/oauth-authz-req+jwt', { parseAs: 'string' }, (_req, body, done) => {
    done(null, body);
  });

  app.useGlobalPipes(new ValidationPipe({ whitelist: false, transform: true }));

  // Everything is served under a single path prefix (default `eudi-verifier`; the dev deployment sets
  // `API_PREFIX=trp` to match the `api.dev.hopae.app/trp` ingress). Health/live/ready + the Prometheus
  // scrape sit under the same prefix (the infra probes hit `/<prefix>/health` etc.), so the prefix owns
  // the whole path — no root-level routes. `VERIFIER_BASE_URL` MUST include this prefix.
  const prefix = process.env.API_PREFIX ?? 'eudi-verifier';
  app.setGlobalPrefix(prefix);

  const port = process.env.PORT ?? 3500;
  await app.listen(port, '0.0.0.0');
  app.get(Logger).log(`EUDI Verifier listening on :${port}`, 'Bootstrap');
}
void bootstrap();

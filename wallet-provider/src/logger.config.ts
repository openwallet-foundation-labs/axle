import { ConfigService } from '@nestjs/config';
import type { Params } from 'nestjs-pino';
import type { IncomingMessage, ServerResponse } from 'node:http';

/**
 * Structured (pino) logging. Pretty single-line logs in dev; JSON in prod for the log pipeline.
 * Health/metrics probes are not request-logged (they'd dominate), auth/cookie headers are redacted,
 * and request/response *bodies are never logged* — they carry instance keys, PoP JWTs and integrity tokens.
 */
export function createLoggerConfig(config: ConfigService): Params {
  const isProd = config.get<string>('STAGE') === 'prod';
  const level = config.get<string>('LOG_LEVEL') ?? (isProd ? 'info' : 'debug');

  const IGNORED = new Set(['/wp/health', '/wp/live', '/wp/ready', '/wp/metrics']);

  return {
    pinoHttp: {
      level,
      transport: isProd ? undefined : { target: 'pino-pretty', options: { singleLine: true } },
      redact: {
        paths: ['req.headers.authorization', 'req.headers.cookie', 'req.headers["x-api-key"]'],
        censor: '[REDACTED]',
      },
      serializers: {
        req: (req: IncomingMessage) => ({ method: req.method, url: req.url }),
        res: (res: ServerResponse) => ({ statusCode: res.statusCode }),
      },
      customLogLevel: (_req, res, err) => (res.statusCode >= 500 || err ? 'error' : 'info'),
      autoLogging: {
        ignore: (req) => {
          const url = (req as IncomingMessage & { originalUrl?: string }).originalUrl ?? req.url ?? '';
          return IGNORED.has(url.split('?')[0]);
        },
      },
    },
  };
}

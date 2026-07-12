import { CanActivate, ExecutionContext, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { timingSafeEqual } from 'node:crypto';

/** Header carrying the admin API key. */
export const ADMIN_API_KEY_HEADER = 'x-api-key';

/**
 * Gates admin-only endpoints (e.g. revoke) behind the `ADMIN_API_KEY` secret, presented in the `x-api-key`
 * header. If `ADMIN_API_KEY` is unset the guard allows through and warns — so local dev works, while a
 * deployed instance that injects the secret is protected. Comparison is constant-time.
 */
@Injectable()
export class AdminApiKeyGuard implements CanActivate {
  private readonly logger = new Logger(AdminApiKeyGuard.name);

  constructor(private readonly config: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const configured = this.config.get<string>('ADMIN_API_KEY');
    if (!configured) {
      this.logger.warn('ADMIN_API_KEY is not set — admin endpoints are UNPROTECTED (dev only)');
      return true;
    }
    const provided = context.switchToHttp().getRequest().headers?.[ADMIN_API_KEY_HEADER];
    if (typeof provided !== 'string' || !safeEqual(provided, configured)) {
      throw new UnauthorizedException('invalid or missing admin API key');
    }
    return true;
  }
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

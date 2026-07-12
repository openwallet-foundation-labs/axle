import { Logger } from '@nestjs/common';
import type { IntegrityResult } from '../platform-verifier';

const logger = new Logger('PlayIntegrity');

/**
 * Loads the Google service account from the `GOOGLE_SERVICE_ACCOUNT_JSON` secret string (not a file path),
 * so the image stays config-less. The value must be valid JSON with `private_key`'s newlines intact — store
 * it single-quoted with compact JSON (`jq -c`). Returns `undefined` to fall back to Application Default
 * Credentials.
 */
function serviceAccountCredentials(): Record<string, unknown> | undefined {
  const saJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  return saJson ? (JSON.parse(saJson) as Record<string, unknown>) : undefined;
}

/**
 * Decodes an Android Play Integrity token via Google and checks the verdicts + nonce. Requires
 * `google-auth-library` (an optional dependency) and a service account (the `GOOGLE_SERVICE_ACCOUNT_JSON`
 * secret, or Application Default Credentials as a fallback).
 * Reference: https://developer.android.com/google/play/integrity/standard#decrypt-verify
 */
export async function verifyPlayIntegrity(
  packageName: string,
  token: string,
  challenge: string,
): Promise<IntegrityResult> {
  try {
    const moduleName = 'google-auth-library'; // computed specifier: optional dep, resolved only at runtime
    const { GoogleAuth } = (await import(moduleName)) as any;
    const credentials = serviceAccountCredentials();
    const auth = new GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/playintegrity'],
      ...(credentials ? { credentials } : {}),
    });
    const accessToken = await (await auth.getClient()).getAccessToken();

    const res = await fetch(`https://playintegrity.googleapis.com/v1/${packageName}:decodeIntegrityToken`, {
      method: 'POST',
      headers: { authorization: `Bearer ${accessToken.token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ integrity_token: token }),
    });
    if (!res.ok) return { trusted: false, platform: 'android', reason: `Play Integrity decode failed: ${res.status}` };

    const verdict = ((await res.json()) as any)?.tokenPayloadExternal;
    if (verdict?.requestDetails?.nonce !== challenge) {
      return { trusted: false, platform: 'android', reason: 'Play Integrity nonce mismatch' };
    }
    const appRecognized = verdict?.appIntegrity?.appRecognitionVerdict === 'PLAY_RECOGNIZED';
    const deviceOk: boolean = (verdict?.deviceIntegrity?.deviceRecognitionVerdict ?? []).includes('MEETS_DEVICE_INTEGRITY');
    if (!appRecognized || !deviceOk) {
      return { trusted: false, platform: 'android', reason: 'Play Integrity verdict failed (app/device)' };
    }
    return { trusted: true, platform: 'android' };
  } catch (e) {
    logger.error(`Play Integrity verification error: ${(e as Error).message}`);
    return { trusted: false, platform: 'android', reason: 'verification error (google-auth-library installed + credentials configured?)' };
  }
}

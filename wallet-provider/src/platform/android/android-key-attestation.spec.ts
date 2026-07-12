import { readFileSync } from 'fs';
import { join } from 'path';
import { verifyAndroidKeyAttestation } from './android-key-attestation';

/**
 * Verifies against a real Android Key Attestation chain captured from a device (Samsung SM-F731N),
 * challenge = "eudi-attestation-challenge". Proves the WP can verify a hardware chain and derive the
 * true storage level — the basis for asserting `iso_18045_high` truthfully.
 */
describe('verifyAndroidKeyAttestation', () => {
  const chain = new Uint8Array(readFileSync(join(__dirname, '..', '..', '..', 'test', 'fixtures', 'key-attestation-chain.der')));
  const challenge = new TextEncoder().encode('eudi-attestation-challenge');

  it('verifies a real device chain: hardware-backed, matching challenge', async () => {
    const verdict = await verifyAndroidKeyAttestation(chain, challenge);
    expect(verdict.verified).toBe(true);
    expect(verdict.challengeMatches).toBe(true);
    expect(['trustedEnvironment', 'strongBox']).toContain(verdict.securityLevel);
  });

  it('rejects a wrong challenge (anti-replay)', async () => {
    const verdict = await verifyAndroidKeyAttestation(chain, new TextEncoder().encode('a-different-nonce'));
    expect(verdict.verified).toBe(true); // chain is still valid
    expect(verdict.challengeMatches).toBe(false); // but the challenge does not match
  });

  it('rejects a chain that does not root in a Google attestation root', async () => {
    // Flip a byte in the last (root) certificate region so the root thumbprint no longer matches.
    const tampered = new Uint8Array(chain);
    tampered[tampered.length - 40] ^= 0xff;
    const verdict = await verifyAndroidKeyAttestation(tampered, challenge);
    expect(verdict.verified).toBe(false);
  });
});

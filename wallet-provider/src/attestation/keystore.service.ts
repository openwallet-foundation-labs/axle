import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Crypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';
import * as jose from 'jose';

const webcrypto = new Crypto();
x509.cryptoProvider.set(webcrypto);

/**
 * Holds the Wallet Provider's signing key and its signer certificate. WUAs / key attestations / status-list
 * tokens carry `x5c = [signer cert]` (convention: the signing leaf only); relying issuers install the WP CA
 * (served at `/ca.pem`) as the trust anchor and chain the signer to it.
 *
 * Production: load the persistent signer key + signer cert + CA cert from env (`WP_SIGNER_PRIVATE_KEY`,
 * `WP_SIGNER_CERT`, `WP_CA_CERT`) so the trust anchor is **stable across restarts and replicas** (generate
 * them once with `tools/gen-keystore.mjs`). Dev: if unset, an ephemeral self-signed CA + signer are made on
 * startup — fine locally, but a fresh key per process, so WUAs won't verify across restarts/replicas.
 */
@Injectable()
export class KeystoreService implements OnModuleInit {
  private readonly logger = new Logger(KeystoreService.name);

  readonly issuer = process.env.WP_ISSUER ?? 'https://wallet-provider.hopae.dev';

  /** jose-usable private signing key. */
  signingKey!: jose.CryptoKey;
  /** base64(DER) chain: `[signer cert]`. The CA is a separately-distributed trust anchor (see `/ca.pem`). */
  x5c!: string[];
  /** signing public key as JWK (for `/jwks`). */
  publicJwk!: jose.JWK;

  private caCertPem!: string;

  async onModuleInit(): Promise<void> {
    const signerKey = pemEnv('WP_SIGNER_PRIVATE_KEY');
    const signerCert = pemEnv('WP_SIGNER_CERT');
    const caCert = pemEnv('WP_CA_CERT');
    if (signerKey && signerCert && caCert) {
      await this.loadFromEnv(signerKey, signerCert, caCert);
      this.logger.log(`WP keystore loaded from env — issuer=${this.issuer}, x5c=[signer]`);
    } else {
      await this.generateEphemeral();
      this.logger.warn(
        'WP keystore generated (ephemeral, per-process) — set WP_SIGNER_PRIVATE_KEY/WP_SIGNER_CERT/WP_CA_CERT to persist the trust anchor across restarts and replicas',
      );
    }
  }

  /** Loads the persistent signer key + certificates from PEM env vars. */
  private async loadFromEnv(signerKeyPem: string, signerCertPem: string, caCertPem: string): Promise<void> {
    this.signingKey = (await jose.importPKCS8(signerKeyPem, 'ES256')) as jose.CryptoKey;
    this.publicJwk = await jose.exportJWK(await jose.importX509(signerCertPem, 'ES256'));
    this.x5c = [pemToBase64Der(signerCertPem)];
    this.caCertPem = caCertPem.trim() + '\n';
  }

  /** Dev fallback: a self-signed CA + signer, freshly generated per process. */
  private async generateEphemeral(): Promise<void> {
    const algorithm: EcKeyGenParams = { name: 'ECDSA', namedCurve: 'P-256' };
    const caKeys = await webcrypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
    const signKeys = await webcrypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
    const validity = { notBefore: new Date('2025-01-01'), notAfter: new Date('2035-01-01') };
    const sigAlg: EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' };

    const caCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: '01',
      name: 'CN=EUDI Wallet Provider CA, O=Hopae, C=KR',
      keys: caKeys,
      signingAlgorithm: sigAlg,
      extensions: [
        new x509.BasicConstraintsExtension(true, 1, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      ],
      ...validity,
    });

    const signerCert = await x509.X509CertificateGenerator.create({
      serialNumber: '02',
      subject: 'CN=EUDI Wallet Provider Signer, O=Hopae, C=KR',
      issuer: caCert.subject,
      publicKey: signKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: sigAlg,
      extensions: [
        new x509.BasicConstraintsExtension(false),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      ],
      ...validity,
    });

    const privJwk = (await webcrypto.subtle.exportKey('jwk', signKeys.privateKey)) as jose.JWK;
    this.signingKey = (await jose.importJWK(privJwk, 'ES256')) as jose.CryptoKey;
    this.publicJwk = (await webcrypto.subtle.exportKey('jwk', signKeys.publicKey)) as jose.JWK;
    this.x5c = [Buffer.from(signerCert.rawData).toString('base64')];
    this.caCertPem = caCert.toString('pem');
  }

  /** PEM of the WP CA cert — a relying wallet/issuer installs this as a trust anchor. */
  caPem(): string {
    return this.caCertPem;
  }
}

/** Reads a PEM env var, tolerating single-line `\n`-escaped values (real newlines are unaffected). */
function pemEnv(name: string): string | undefined {
  const value = process.env[name];
  return value ? value.replace(/\\n/g, '\n') : undefined;
}

/** Strips PEM armor + whitespace to the base64(DER) form used in an `x5c` entry. */
function pemToBase64Der(pem: string): string {
  return pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

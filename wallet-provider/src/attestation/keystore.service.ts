import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { Crypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';
import * as jose from 'jose';

const webcrypto = new Crypto();
x509.cryptoProvider.set(webcrypto);

/**
 * Holds the Wallet Provider's signing key and its X.509 chain (signer <- WP CA).
 * WUAs / key attestations carry `x5c` = [signer, CA]; relying issuers trust the WP CA root.
 * Dev: a self-signed CA + signer are generated on startup. Production: load from KMS/PKI.
 */
@Injectable()
export class KeystoreService implements OnModuleInit {
  private readonly logger = new Logger(KeystoreService.name);

  readonly issuer = process.env.WP_ISSUER ?? 'https://wallet-provider.hopae.dev';

  /** jose-usable private signing key. */
  signingKey!: jose.CryptoKey;
  /** base64(DER) chain: [signer cert, CA cert]. */
  x5c!: string[];
  /** signing public key as JWK (for /jwks). */
  publicJwk!: jose.JWK;

  private caCert!: x509.X509Certificate;

  async onModuleInit(): Promise<void> {
    const algorithm: EcKeyGenParams = { name: 'ECDSA', namedCurve: 'P-256' };
    const caKeys = await webcrypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
    const signKeys = await webcrypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
    const validity = { notBefore: new Date('2025-01-01'), notAfter: new Date('2035-01-01') };
    const sigAlg: EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' };

    this.caCert = await x509.X509CertificateGenerator.createSelfSigned({
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
      issuer: this.caCert.subject,
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

    this.x5c = [
      Buffer.from(signerCert.rawData).toString('base64'),
      Buffer.from(this.caCert.rawData).toString('base64'),
    ];
    this.logger.log(`WP keystore ready — issuer=${this.issuer}, chain=[signer, CA]`);
  }

  /** PEM of the WP CA cert — a relying wallet/issuer installs this as a trust anchor. */
  caPem(): string {
    return this.caCert.toString('pem');
  }
}

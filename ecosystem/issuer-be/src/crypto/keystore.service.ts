import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Crypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';
import { importPKCS8, exportJWK, calculateJwkThumbprint, type JWK } from 'jose';

export type SignerType = 'pid' | 'mdl' | 'access';

export interface Signer {
  /** Private key as a JWK (with `d`) — consumed by @sd-jwt (ES256 signer) and @lukas.j.han/mdoc (CoseKey). */
  privateJwk: JWK;
  /** Public key as a JWK (no `d`). */
  publicJwk: JWK;
  /** Leaf DSC in PEM. */
  certPem: string;
  /** DER bytes of the leaf DSC (for the mdoc COSE x5chain). */
  certDer: Uint8Array;
  /** x5c array (base64 DER, no PEM armor) — the SD-JWT VC JOSE `x5c` header (trust anchor excluded, HAIP §6.1.1). */
  x5c: string[];
  /** Issuing CA (trust anchor) PEM — informational; NOT put in x5c. */
  caCertPem?: string;
  /** RFC 7638 JWK thumbprint of the signing key (used as `kid`). */
  kid: string;
}

interface RawKeystore {
  privateKeyPem: string;
  certPem: string;
  caCertPem?: string;
}

const webcrypto = new Crypto();
x509.cryptoProvider.set(webcrypto);

/**
 * Loads the Issuer's Document Signer (DSC) keys from env — `ISSUER_PID_SIGNER` / `ISSUER_MDL_SIGNER`, each a
 * JSON `{ privateKeyPem, certPem, caCertPem }` minted by `ecosystem/trusted-list/tools/gen-signer.mjs`. When a
 * signer is unset, an ephemeral self-signed dev key is generated at boot (works locally but does NOT chain to
 * the published Trusted List, so real wallets/verifiers will reject it).
 */
@Injectable()
export class KeystoreService implements OnModuleInit {
  private readonly logger = new Logger(KeystoreService.name);
  private signers = new Map<SignerType, Signer>();

  constructor(private readonly config: ConfigService) {}

  async onModuleInit() {
    this.signers.set('pid', await this.load('pid', 'ISSUER_PID_SIGNER', 'PID Document Signer'));
    this.signers.set('mdl', await this.load('mdl', 'ISSUER_MDL_SIGNER', 'mDL Document Signer'));
    // The Provider's ACCESS certificate that signs the (signed) Issuer Metadata JWS — distinct from the
    // credential Document Signers (ETSI TS 119 472-3 ISS-MDATA-4.2.1-02). Unset ⇒ metadata falls back to the
    // PID DSC (see getSigner). We do NOT synthesize an ephemeral self-signed one for it.
    const accessRaw = this.config.get<string>('ISSUER_ACCESS_CERT');
    if (accessRaw) {
      const ks = JSON.parse(accessRaw) as RawKeystore;
      this.signers.set('access', await this.fromPem(ks.privateKeyPem, ks.certPem, ks.caCertPem));
      this.logger.log(`access signer loaded from ISSUER_ACCESS_CERT: ${new x509.X509Certificate(ks.certPem).subject}`);
    } else {
      this.logger.warn('ISSUER_ACCESS_CERT unset — signed metadata falls back to the PID Document Signer');
    }
  }

  getSigner(type: SignerType): Signer {
    const s = this.signers.get(type);
    if (s) return s;
    // Metadata signing falls back to the PID DSC when no dedicated access cert is configured.
    if (type === 'access') return this.getSigner('pid');
    throw new Error(`signer not initialized: ${type}`);
  }

  private async load(type: SignerType, envKey: string, dev: string): Promise<Signer> {
    const raw = this.config.get<string>(envKey);
    if (raw) {
      const ks = JSON.parse(raw) as RawKeystore;
      const signer = await this.fromPem(ks.privateKeyPem, ks.certPem, ks.caCertPem);
      this.logger.log(`${type} signer loaded from ${envKey}: ${new x509.X509Certificate(ks.certPem).subject}`);
      return signer;
    }
    const signer = await this.ephemeral(dev);
    this.logger.warn(`${envKey} unset — using an EPHEMERAL self-signed ${type} signer (dev only, not trust-listed)`);
    return signer;
  }

  private async fromPem(privateKeyPem: string, certPem: string, caCertPem?: string): Promise<Signer> {
    const key = await importPKCS8(privateKeyPem, 'ES256', { extractable: true });
    const privateJwk = await exportJWK(key);
    const { d: _d, ...publicJwk } = privateJwk;
    const cert = new x509.X509Certificate(certPem);
    return {
      privateJwk,
      publicJwk,
      certPem,
      certDer: new Uint8Array(cert.rawData),
      x5c: [pemToBase64(certPem)],
      caCertPem,
      kid: await calculateJwkThumbprint(publicJwk, 'sha256'),
    };
  }

  private async ephemeral(cn: string): Promise<Signer> {
    const keys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: '01',
      name: `CN=DEV ${cn}, O=Hopae S.A. (dev), C=LU`,
      keys,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      notBefore: new Date(Date.now() - 86400_000),
      notAfter: new Date(Date.now() + 365 * 86400_000),
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
      ],
    });
    const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64');
    const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${pkcs8.match(/.{1,64}/g)!.join('\n')}\n-----END PRIVATE KEY-----\n`;
    return this.fromPem(privateKeyPem, cert.toString('pem'));
  }
}

function pemToBase64(pem: string): string {
  return pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

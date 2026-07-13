import type { MdocContext } from '@lukas.j.han/mdoc';
import { CoseKey } from '@lukas.j.han/mdoc';
import { Crypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';

const webcrypto = new Crypto();
x509.cryptoProvider.set(webcrypto);

const EC_P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ECDSA_SHA256 = { name: 'ECDSA', hash: 'SHA-256' } as const;

const notForVerification = (name: string) => () => {
  throw new Error(`mdocContext.${name} is not implemented (verification context: device-signature only, no MAC)`);
};

/**
 * A verification-capable COSE/crypto/X.509 context for `@lukas.j.han/mdoc` `DeviceResponse.verify`. Backs
 * COSE_Sign1 verification (issuer MSO + device signature) with WebCrypto ECDSA P-256, and X.509 chain
 * validation + public-key extraction with `@peculiar/x509`. `deviceMac` (MAC0 / ECDH key agreement) is not
 * wired — the wallet SDK defaults to device-signature auth over OpenID4VP, which needs none of it.
 */
export const mdocVerifyContext: MdocContext = {
  crypto: {
    digest: async ({ digestAlgorithm, bytes }) => {
      const out = await webcrypto.subtle.digest(digestAlgorithm, new Uint8Array(bytes));
      return new Uint8Array(out);
    },
    random: (length: number) => webcrypto.getRandomValues(new Uint8Array(length)),
    calculateEphemeralMacKey: notForVerification('crypto.calculateEphemeralMacKey'),
  },
  cose: {
    sign1: {
      sign: notForVerification('cose.sign1.sign'),
      verify: async ({ key, sign1 }) => {
        const cryptoKey = await webcrypto.subtle.importKey('jwk', key.jwk as JsonWebKey, EC_P256, false, ['verify']);
        return webcrypto.subtle.verify(
          ECDSA_SHA256,
          cryptoKey,
          new Uint8Array(sign1.signature as Uint8Array),
          new Uint8Array(sign1.toBeSigned),
        );
      },
    },
    mac0: {
      sign: notForVerification('cose.mac0.sign'),
      verify: notForVerification('cose.mac0.verify'),
    },
  },
  x509: {
    getIssuerNameField: ({ certificate, field }) => {
      const cert = new x509.X509Certificate(new Uint8Array(certificate));
      return cert.issuerName.getField(field);
    },
    getPublicKey: async ({ certificate }) => {
      const cert = new x509.X509Certificate(new Uint8Array(certificate));
      const cryptoKey = await cert.publicKey.export(webcrypto);
      const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey);
      return CoseKey.fromJwk(jwk as Record<string, unknown>);
    },
    verifyCertificateChain: async ({ trustedCertificates, x5chain, now }) => {
      const date = now ?? new Date();
      const chain = x5chain.map((d) => new x509.X509Certificate(new Uint8Array(d)));
      const trusted = trustedCertificates.map((d) => new x509.X509Certificate(new Uint8Array(d)));
      if (chain.length === 0) throw new Error('mdoc x5chain is empty');

      // Intra-chain: each cert is signed by the next (leaf → … → top).
      for (let i = 0; i < chain.length - 1; i++) {
        if (!(await chain[i].verify({ publicKey: chain[i + 1].publicKey, date }))) {
          throw new Error('mdoc x5chain: a certificate is not signed by the next in the chain');
        }
      }
      // Top of chain must be, or be signed by, a trusted anchor.
      const top = chain[chain.length - 1];
      for (const t of trusted) {
        // `equal()` narrows `t` to `never` in the false branch (type predicate); cast back for `.publicKey`.
        if (top.equal(t)) return;
        if (await top.verify({ publicKey: (t as x509.X509Certificate).publicKey, date })) return;
      }
      throw new Error('mdoc x5chain does not chain to a trusted issuer certificate');
    },
    getCertificateData: async ({ certificate }) => {
      const cert = new x509.X509Certificate(new Uint8Array(certificate));
      const thumb = await cert.getThumbprint('SHA-256');
      return {
        issuerName: cert.issuer,
        subjectName: cert.subject,
        serialNumber: cert.serialNumber,
        thumbprint: Buffer.from(thumb).toString('hex'),
        notBefore: cert.notBefore,
        notAfter: cert.notAfter,
        pem: cert.toString('pem'),
      };
    },
  },
};

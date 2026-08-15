// Builds an ETSI TS 119 602 "List of Trusted Entities" (LoTE) object from a per-list config + the shared
// scheme info + the embedded certificates. Scheme-explicit JSON shaped from the §6 component names (Table A.1
// maps these to the 119 612 TSL fields); reconcile exact key names against the ETSI forge JSON schema before
// production interop. Distribution points are derived from scheme.siteUrl + the list slug.
import 'reflect-metadata';
import { Crypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

x509.cryptoProvider.set(new Crypto());

/**
 * The certificate's Subject Key Identifier, or undefined when it cannot be read.
 *
 * `getExtension()` materialises every extension while searching, so one extension the library cannot type
 * takes the whole certificate down. That is not hypothetical for third-party anchors: the EU Age Verification
 * reference CA (`CN=Age Verification Issuer CA 01`) carries a malformed issuerAltName — openssl renders it as
 * raw bytes too. `x509Ski` is optional (§6.6.3) and the certificate is published in full alongside it, so
 * omitting the field is strictly better than refusing to list the anchor.
 */
function subjectKeyIdentifier(cert) {
  try {
    return cert.getExtension(x509.SubjectKeyIdentifierExtension)?.keyId;
  } catch (e) {
    console.warn(`  ! SKI unreadable for "${cert.subjectName.toString()}" (${e.message}) — omitting x509Ski`);
    return undefined;
  }
}

/** Parses a PEM cert into the ServiceDigitalIdentity fields (§6.6.3): the cert, its subject DN, and SKI. */
function digitalIdentity(pem) {
  const cert = new x509.X509Certificate(pem);
  const ski = subjectKeyIdentifier(cert);
  return {
    x509Certificate: Buffer.from(cert.rawData).toString('base64'),
    x509SubjectName: cert.subjectName.toString(),
    ...(ski ? { x509Ski: ski } : {}),
  };
}

export function buildLote(root, list, scheme, at = new Date()) {
  const nextUpdate = new Date(at);
  nextUpdate.setUTCMonth(nextUpdate.getUTCMonth() + (scheme.nextUpdateMonths ?? 6)); // <= 6 months

  const base = scheme.siteUrl.replace(/\/$/, '');
  const selfUri = `${base}/tl/${list.slug}.jws`;

  return {
    listAndSchemeInformation: {
      loteVersionIdentifier: list.loteVersionIdentifier,
      loteSequenceNumber: list.loteSequenceNumber,
      loteType: list.loteType,
      schemeOperatorName: scheme.schemeOperatorName,
      schemeName: list.schemeName,
      schemeInformationUri: [`${base}/`],
      statusDeterminationApproach: scheme.statusDeterminationApproach,
      schemeTypeCommunityRules: scheme.schemeTypeCommunityRules,
      schemeTerritory: scheme.schemeTerritory,
      pointersToOtherLoTE: [selfUri],
      listIssueDateTime: at.toISOString(),
      nextUpdate: nextUpdate.toISOString(),
      distributionPoints: [selfUri],
    },
    trustedEntitiesList: list.entities
      .filter((e) => e.teName)
      .map((e) => ({
        trustedEntityInformation: {
          teName: e.teName,
          teTradeName: e.teTradeName,
          teAddress: e.teAddress,
          teInformationUri: e.teInformationUri,
        },
        trustedEntityServices: e.services.map((s) => ({
          serviceTypeIdentifier: s.serviceTypeIdentifier,
          serviceName: s.serviceName,
          serviceDigitalIdentity: digitalIdentity(readFileSync(join(root, s.certFile), 'utf8')),
          // Absence of ServiceCurrentStatus ⇒ the listed service is certified/current (Annex E Table E.3).
        })),
      })),
  };
}

// Builds an ETSI TS 119 602 "List of Trusted Entities" (LoTE) object from config + embedded certificates.
// Scheme-explicit JSON shaped from the §6 component names (Table A.1 maps these to the 119 612 TSL fields);
// reconcile exact key names against the ETSI forge JSON schema (Annex A) before production interop.
import 'reflect-metadata';
import { Crypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

x509.cryptoProvider.set(new Crypto());

/** Parses a PEM cert into the ServiceDigitalIdentity fields (§6.6.3): the cert, its subject DN, and SKI. */
function digitalIdentity(pem) {
  const cert = new x509.X509Certificate(pem);
  const ski = cert.getExtension(x509.SubjectKeyIdentifierExtension);
  return {
    x509Certificate: Buffer.from(cert.rawData).toString('base64'),
    x509SubjectName: cert.subjectName.toString(),
    ...(ski ? { x509Ski: ski.keyId } : {}),
  };
}

export function buildLote(root, at = new Date()) {
  const scheme = JSON.parse(readFileSync(join(root, 'config/scheme.json'), 'utf8'));
  const entities = JSON.parse(readFileSync(join(root, 'config/entities/wallet-providers.json'), 'utf8'));

  const nextUpdate = new Date(at);
  nextUpdate.setUTCMonth(nextUpdate.getUTCMonth() + (scheme.nextUpdateMonths ?? 6)); // Annex E: <= 6 months

  return {
    listAndSchemeInformation: {
      loteVersionIdentifier: scheme.loteVersionIdentifier,
      loteSequenceNumber: scheme.loteSequenceNumber,
      loteType: scheme.loteType,
      schemeOperatorName: scheme.schemeOperatorName,
      schemeName: scheme.schemeName,
      schemeInformationUri: scheme.schemeInformationUri,
      statusDeterminationApproach: scheme.statusDeterminationApproach,
      schemeTypeCommunityRules: scheme.schemeTypeCommunityRules,
      schemeTerritory: scheme.schemeTerritory,
      pointersToOtherLoTE: [scheme.selfPointerUri],
      listIssueDateTime: at.toISOString(),
      nextUpdate: nextUpdate.toISOString(),
      distributionPoints: scheme.distributionPoints,
    },
    trustedEntitiesList: entities
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
          // Annex E Table E.3: absence of ServiceCurrentStatus ⇒ the listed wallet solution is certified.
        })),
      })),
  };
}

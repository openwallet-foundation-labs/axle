import type { SignerType } from '../crypto/keystore.service';

// Hardcoded demo subject — a Luxembourg citizen (matches the C=LU issuer identity). The same person is used
// across PID (SD-JWT VC + mdoc); the mDL adds driving data. All claims are fixed (sandbox demo, no real IdP).
const PERSON = {
  given_name: 'Charel',
  family_name: 'Weber',
  birth_date: '1990-05-14',
  birth_place: 'Luxembourg',
  nationality: 'LU',
  resident_address: '12, Rue de la Gare',
  resident_postal_code: 'L-1611',
  resident_city: 'Luxembourg',
  resident_country: 'LU',
  document_number: 'LU123456789',
};

export type Flow = 'authorization_code' | 'pre-authorized_code';
export type CredFormat = 'dc+sd-jwt' | 'mso_mdoc';

export interface DisplayField {
  label: string;
  value: string;
}

export interface MdocNamespaceClaims {
  namespace: string;
  claims: Record<string, unknown>;
}

export interface CredentialConfig {
  /** credential_configuration_id (the key in credential_configurations_supported). */
  id: string;
  format: CredFormat;
  scope: string;
  signer: SignerType;
  flow: Flow;
  display: { name: string; locale: string; background_color: string; text_color: string };
  /** SD-JWT VC */
  vct?: string;
  sdJwtClaims?: Record<string, unknown>;
  sdJwtDisclose?: string[];
  /** ISO mdoc */
  doctype?: string;
  mdocNamespaces?: MdocNamespaceClaims[];
  /** Fields shown on the issuance consent screen. */
  displayFields: DisplayField[];
  /**
   * Whether a valid Key Attestation (the WUA) is MANDATORY in the credential-request jwt proof. ETSI TS 119
   * 472-3 CRED-REQ-4.6.1.2-03 makes the `key_attestation` parameter mandatory for PID/EAA, and the Provider
   * must verify it chains to the Wallet Provider Trusted List (CRED-REQ-PROC-4.6.2.1-01). Omitted ⇒ true
   * (secure default): the config advertises `key_attestations_required` and rejects a proof without a valid
   * attestation. Set false to also accept a bare jwt proof (PoP only, no WSCD binding) — for low-assurance
   * demo credentials only; NEVER for PID or an eIDAS LoA-High EAA.
   */
  keyAttestationRequired?: boolean;
}

const PID_ISSUING_AUTHORITY = "Centre des technologies de l'information de l'État (CTIE)";
const MDL_ISSUING_AUTHORITY = 'Société Nationale de Circulation Automobile (SNCA)';

export const CREDENTIAL_CONFIGS: CredentialConfig[] = [
  // 1) PID as SD-JWT VC — authorization_code flow.
  {
    id: 'eu.europa.ec.eudi.pid.sd_jwt_vc',
    keyAttestationRequired: true, // PID — WSCD-bound, LoA High (ETSI TS 119 472-3)
    format: 'dc+sd-jwt',
    scope: 'eu.europa.ec.eudi.pid.sd_jwt_vc',
    signer: 'pid',
    flow: 'authorization_code',
    display: { name: 'Personal ID (PID)', locale: 'en', background_color: '#12395b', text_color: '#ffffff' },
    vct: 'urn:eudi:pid:1',
    sdJwtClaims: {
      given_name: PERSON.given_name,
      family_name: PERSON.family_name,
      birthdate: PERSON.birth_date,
      place_of_birth: PERSON.birth_place,
      nationalities: [PERSON.nationality],
      resident_address: `${PERSON.resident_address}, ${PERSON.resident_postal_code} ${PERSON.resident_city}`,
      resident_country: PERSON.resident_country,
      age_over_18: true,
      issuing_country: 'LU',
      issuing_authority: PID_ISSUING_AUTHORITY,
    },
    sdJwtDisclose: [
      'given_name',
      'family_name',
      'birthdate',
      'place_of_birth',
      'nationalities',
      'resident_address',
      'resident_country',
      'age_over_18',
      'issuing_country',
      'issuing_authority',
    ],
    displayFields: [
      { label: 'Given name', value: PERSON.given_name },
      { label: 'Family name', value: PERSON.family_name },
      { label: 'Date of birth', value: PERSON.birth_date },
      { label: 'Place of birth', value: PERSON.birth_place },
      { label: 'Nationality', value: PERSON.nationality },
      { label: 'Address', value: `${PERSON.resident_address}, ${PERSON.resident_postal_code} ${PERSON.resident_city}` },
      { label: 'Issuing country', value: 'LU' },
      { label: 'Issuing authority', value: PID_ISSUING_AUTHORITY },
    ],
  },

  // 2) PID as mdoc — authorization_code flow.
  {
    id: 'eu.europa.ec.eudi.pid.mdoc',
    keyAttestationRequired: true, // PID — WSCD-bound, LoA High (ETSI TS 119 472-3)
    format: 'mso_mdoc',
    scope: 'eu.europa.ec.eudi.pid.mdoc',
    signer: 'pid',
    flow: 'authorization_code',
    display: { name: 'Personal ID (PID) · mdoc', locale: 'en', background_color: '#12395b', text_color: '#ffffff' },
    doctype: 'eu.europa.ec.eudi.pid.1',
    mdocNamespaces: [
      {
        namespace: 'eu.europa.ec.eudi.pid.1',
        claims: {
          given_name: PERSON.given_name,
          family_name: PERSON.family_name,
          birth_date: PERSON.birth_date,
          nationality: PERSON.nationality,
          resident_address: PERSON.resident_address,
          resident_city: PERSON.resident_city,
          resident_postal_code: PERSON.resident_postal_code,
          resident_country: PERSON.resident_country,
          age_over_18: true,
          issuing_country: 'LU',
          issuing_authority: PID_ISSUING_AUTHORITY,
          expiry_date: '2035-05-14',
          issuance_date: '2026-07-12',
        },
      },
    ],
    displayFields: [
      { label: 'Given name', value: PERSON.given_name },
      { label: 'Family name', value: PERSON.family_name },
      { label: 'Date of birth', value: PERSON.birth_date },
      { label: 'Nationality', value: PERSON.nationality },
      { label: 'Address', value: `${PERSON.resident_address}, ${PERSON.resident_postal_code} ${PERSON.resident_city}` },
      { label: 'Issuing country', value: 'LU' },
      { label: 'Issuing authority', value: PID_ISSUING_AUTHORITY },
    ],
  },

  // 3) mDL as mdoc — pre-authorized_code flow.
  {
    id: 'org.iso.18013.5.1.mDL',
    // mDL is an EAA, not PID: ISO/IEC 18013-5 requires device-key binding (proven by the jwt proof's PoP) but
    // not a WUA. We treat this sandbox mDL as lower-assurance and accept a bare jwt proof. Flip to true to
    // enforce the WUA (strict ETSI TS 119 472-3 for a device-bound EAA).
    keyAttestationRequired: false,
    format: 'mso_mdoc',
    scope: 'org.iso.18013.5.1.mDL',
    signer: 'mdl',
    flow: 'pre-authorized_code',
    display: { name: 'Mobile Driving Licence (mDL)', locale: 'en', background_color: '#0b6b3a', text_color: '#ffffff' },
    doctype: 'org.iso.18013.5.1.mDL',
    mdocNamespaces: [
      {
        namespace: 'org.iso.18013.5.1',
        claims: {
          given_name: PERSON.given_name,
          family_name: PERSON.family_name,
          birth_date: PERSON.birth_date,
          issue_date: '2024-03-01',
          expiry_date: '2034-03-01',
          issuing_country: 'LU',
          issuing_authority: MDL_ISSUING_AUTHORITY,
          document_number: PERSON.document_number,
          un_distinguishing_sign: 'L',
          nationality: PERSON.nationality,
          resident_address: PERSON.resident_address,
          resident_city: PERSON.resident_city,
          resident_country: PERSON.resident_country,
          driving_privileges: [
            { vehicle_category_code: 'B', issue_date: '2010-06-01', expiry_date: '2034-03-01' },
          ],
        },
      },
    ],
    displayFields: [
      { label: 'Given name', value: PERSON.given_name },
      { label: 'Family name', value: PERSON.family_name },
      { label: 'Date of birth', value: PERSON.birth_date },
      { label: 'Document number', value: PERSON.document_number },
      { label: 'Categories', value: 'B' },
      { label: 'Issue date', value: '2024-03-01' },
      { label: 'Expiry date', value: '2034-03-01' },
      { label: 'Issuing authority', value: MDL_ISSUING_AUTHORITY },
    ],
  },
];

export function getConfig(id: string): CredentialConfig | undefined {
  return CREDENTIAL_CONFIGS.find((c) => c.id === id);
}

export function getConfigByScope(scope: string): CredentialConfig | undefined {
  return CREDENTIAL_CONFIGS.find((c) => c.scope === scope);
}

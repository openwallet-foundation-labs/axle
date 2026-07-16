import type { SignerType } from '../crypto/keystore.service';
import { PORTRAIT_JPEG } from './portrait';

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
  /**
   * SD-JWT VC selective-disclosure frame (`@sd-jwt` `DisclosureFrame`): the top-level `_sd` lists the claim
   * names to make selectively disclosable; a nested object (e.g. `address`) carries its own `_sd` so each of
   * its members is individually disclosable — per the PID Rulebook §4.1.1 hierarchical claim names.
   */
  sdJwtDisclose?: Record<string, unknown>;
  /** ISO mdoc */
  doctype?: string;
  mdocNamespaces?: MdocNamespaceClaims[];
  /** Fields shown on the issuance consent screen. */
  displayFields: DisplayField[];
  /**
   * Whether a valid Key Attestation is MANDATORY in the credential-request jwt proof. ETSI TS 119
   * 472-3 CRED-REQ-4.6.1.2-03 makes the `key_attestation` parameter mandatory for PID/EAA, and the Provider
   * must verify it chains to the Wallet Provider Trusted List (CRED-REQ-PROC-4.6.2.1-01). Omitted ⇒ true
   * (secure default): the config advertises `key_attestations_required` and rejects a proof without a valid
   * attestation. Set false to also accept a bare jwt proof (PoP only, no WSCD binding) — for low-assurance
   * demo credentials only; NEVER for PID or an eIDAS LoA-High EAA.
   */
  keyAttestationRequired?: boolean;
  /**
   * MSO ValidityInfo lifetime in days (mso_mdoc only). Omitted ⇒ the sandbox default (validUntil 2035-12-31).
   * When set, the timestamps are truncated to UTC midnight — the AV Profile (Annex A §3.4.1) / ISO 18013-5
   * reduced-precision recommendation so attestations issued in the same batch stay unlinkable by timestamp.
   */
  validityDays?: number;
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
      // PID Rulebook §4.1.1: birth_place → `place_of_birth`, a JSON object (≥1 of country/region/locality),
      // not a bare string.
      place_of_birth: { locality: PERSON.birth_place },
      // §4.1.1: nationality → `nationalities`, an array of ISO 3166-1 alpha-2 codes.
      nationalities: [PERSON.nationality],
      // §4.1.1: resident_* map to the OIDC `address` object (address.formatted / .street_address /
      // .postal_code / .locality / .country) — flat resident_* claims are the mdoc encoding (§3.1.2), not SD-JWT VC.
      address: {
        formatted: `${PERSON.resident_address}, ${PERSON.resident_postal_code} ${PERSON.resident_city}`,
        street_address: PERSON.resident_address,
        postal_code: PERSON.resident_postal_code,
        locality: PERSON.resident_city,
        country: PERSON.resident_country,
      },
      issuing_country: 'LU',
      issuing_authority: PID_ISSUING_AUTHORITY,
    },
    sdJwtDisclose: {
      _sd: [
        'given_name',
        'family_name',
        'birthdate',
        'place_of_birth',
        'nationalities',
        'issuing_country',
        'issuing_authority',
      ],
      // The `address` object is present, but each member is individually selectively-disclosable so a
      // Relying Party can, e.g., request only address.locality without the full address (§4.1.1).
      address: { _sd: ['formatted', 'street_address', 'postal_code', 'locality', 'country'] },
    },
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
          // PID Rulebook §3.1.4: birth_place → `place_of_birth` element, a map (≥1 of country/region/locality).
          place_of_birth: { locality: PERSON.birth_place },
          // §3.1.2/§3.1.3: the `nationality` element is encoded as the `nationalities` type — an ARRAY of
          // ISO 3166-1 alpha-2 codes, not a single string.
          nationality: [PERSON.nationality],
          resident_address: PERSON.resident_address,
          resident_city: PERSON.resident_city,
          resident_postal_code: PERSON.resident_postal_code,
          resident_country: PERSON.resident_country,
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
    // not a key attestation. We treat this sandbox mDL as lower-assurance and accept a bare jwt proof. Flip to
    // true to enforce a key attestation (strict ETSI TS 119 472-3 for a device-bound EAA).
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

  // 4) Proof of Age attestation — EU Age Verification Profile (av-doc-technical-specification, Annex A).
  {
    id: 'proof_of_age',
    // The AV Profile keeps device binding out of scope: unlinkability comes from batch issuance + single use,
    // not from a WSCD-bound key — accept a bare jwt proof (PoP only).
    keyAttestationRequired: false,
    format: 'mso_mdoc',
    // AV Profile §A.5: both the credential_configuration_id and the scope are the literal `proof_of_age`.
    scope: 'proof_of_age',
    // Signed with the sandbox attestation DS so it chains to the published Trusted List. A production AV
    // Attestation Provider uses a dedicated DS under the Commission's AV trusted list (ETSI TS 119 612).
    signer: 'mdl',
    flow: 'pre-authorized_code',
    display: { name: 'Proof of Age (18+)', locale: 'en', background_color: '#4a1140', text_color: '#ffffff' },
    // §A.4: DocType and namespace are the same string, and `age_over_18` is the ONLY mandatory attribute —
    // the attestation SHALL NOT carry any other attribute (no name, no date of birth: unlinkable by content).
    doctype: 'eu.europa.ec.av.1',
    mdocNamespaces: [{ namespace: 'eu.europa.ec.av.1', claims: { age_over_18: true } }],
    // §3.4.3: short-lived (3 months max), designed for single use, no revocation.
    validityDays: 90,
    displayFields: [{ label: 'Age over 18', value: 'Yes' }],
  },

  // 5) Photo ID as mdoc — ISO/IEC TS 23220-4:2026 Annex C profile.
  {
    // The published TS prints the DocType/namespace with lowercase `photoid` (C.2.1 [DT_dual]); some
    // pre-release ecosystems used `photoID` — keep the TS spelling.
    id: 'org.iso.23220.photoid.1',
    keyAttestationRequired: true, // a government photo identity document — WSCD-bound like the PID
    format: 'mso_mdoc',
    scope: 'org.iso.23220.photoid.1',
    signer: 'mdl',
    flow: 'authorization_code',
    display: { name: 'Photo ID', locale: 'en', background_color: '#0c3c4e', text_color: '#ffffff' },
    doctype: 'org.iso.23220.photoid.1',
    mdocNamespaces: [
      {
        // Generic ISO/IEC TS 23220-2 elements (Table C.1): every Mandatory member, the Recommended age_*
        // set, and a residence/document subset of the Optionals. The third profile namespace
        // (`org.iso.23220.datagroups.1`, ICAO 9303 LDS blobs) is omitted — it requires byte-identical eMRTD
        // data groups the sandbox subject does not have.
        namespace: 'org.iso.23220.1',
        claims: {
          family_name: PERSON.family_name,
          given_name: PERSON.given_name,
          birth_date: PERSON.birth_date,
          portrait: PORTRAIT_JPEG,
          issue_date: '2026-07-01',
          expiry_date: '2031-07-01',
          issuing_authority: PID_ISSUING_AUTHORITY,
          issuing_country: 'LU',
          age_over_18: true,
          age_in_years: 36,
          age_birth_year: 1990,
          nationality: PERSON.nationality,
          document_number: PERSON.document_number,
          resident_address: PERSON.resident_address,
          resident_city: PERSON.resident_city,
          resident_postal_code: PERSON.resident_postal_code,
          resident_country: PERSON.resident_country,
        },
      },
      {
        // PhotoID-specific elements (Table C.2) — an optional subset; exercises the second namespace.
        namespace: 'org.iso.23220.photoid.1',
        claims: {
          person_id: '1990051412345',
          birth_country: PERSON.nationality,
          birth_city: PERSON.birth_place,
        },
      },
    ],
    displayFields: [
      { label: 'Given name', value: PERSON.given_name },
      { label: 'Family name', value: PERSON.family_name },
      { label: 'Date of birth', value: PERSON.birth_date },
      { label: 'Portrait', value: 'Facial image (JPEG)' },
      { label: 'Document number', value: PERSON.document_number },
      { label: 'Issue date', value: '2026-07-01' },
      { label: 'Expiry date', value: '2031-07-01' },
      { label: 'Issuing authority', value: PID_ISSUING_AUTHORITY },
    ],
  },
];

export function getConfig(id: string): CredentialConfig | undefined {
  return CREDENTIAL_CONFIGS.find((c) => c.id === id);
}

export function getConfigByScope(scope: string): CredentialConfig | undefined {
  return CREDENTIAL_CONFIGS.find((c) => c.scope === scope);
}

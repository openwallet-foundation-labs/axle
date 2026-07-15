/**
 * The credential kinds this verifier can request, and the DCQL query (OpenID4VP §6) for each. The frontend
 * (or API caller) selects one or more by key; the request builder assembles a single `dcql_query` with one
 * credential entry per selection. Query ids double as the key under which verified claims are returned.
 */
export type RequestableKey = 'pid_sd_jwt' | 'pid_mdoc' | 'mdl';

export interface RequestableCredential {
  key: RequestableKey;
  /** DCQL query id (unique within a request). */
  queryId: string;
  format: 'dc+sd-jwt' | 'mso_mdoc';
  label: string;
  /** SD-JWT VC type (dc+sd-jwt) or mdoc docType (mso_mdoc). */
  type: string;
  /** mdoc namespace (mso_mdoc only). */
  namespace?: string;
  /** Requested claim leaf names (within the namespace, for mdoc). */
  claimNames: string[];
}

const PID_VCT = 'urn:eudi:pid:1';
const PID_DOCTYPE = 'eu.europa.ec.eudi.pid.1';
const PID_NAMESPACE = 'eu.europa.ec.eudi.pid.1';
const MDL_DOCTYPE = 'org.iso.18013.5.1.mDL';
const MDL_NAMESPACE = 'org.iso.18013.5.1';

// The default claim set — an identity request (given name, family name, date of birth). Age-verification
// attributes were removed from the PID Rulebook (v1.1, following CIR 2024/2977), so we request `birthdate`
// (SD-JWT VC, §4.1.1) / `birth_date` (mdoc, §3.1.2) instead of the former `age_over_18`.
export const REQUESTABLE: Record<RequestableKey, RequestableCredential> = {
  pid_sd_jwt: {
    key: 'pid_sd_jwt',
    queryId: 'pid_sd_jwt',
    format: 'dc+sd-jwt',
    label: 'Personal ID (SD-JWT VC)',
    type: PID_VCT,
    claimNames: ['given_name', 'family_name', 'birthdate'],
  },
  pid_mdoc: {
    key: 'pid_mdoc',
    queryId: 'pid_mdoc',
    format: 'mso_mdoc',
    label: 'Personal ID (mdoc)',
    type: PID_DOCTYPE,
    namespace: PID_NAMESPACE,
    claimNames: ['given_name', 'family_name', 'birth_date'],
  },
  mdl: {
    key: 'mdl',
    queryId: 'mdl',
    format: 'mso_mdoc',
    label: 'Mobile Driving Licence (mDL)',
    type: MDL_DOCTYPE,
    namespace: MDL_NAMESPACE,
    claimNames: ['given_name', 'family_name', 'birth_date', 'driving_privileges'],
  },
};

/** Builds the OpenID4VP `dcql_query` object requesting each selected credential. */
export function buildDcqlQuery(keys: RequestableKey[]): { credentials: unknown[] } {
  return {
    credentials: keys.map((key) => {
      const c = REQUESTABLE[key];
      if (c.format === 'dc+sd-jwt') {
        return {
          id: c.queryId,
          format: 'dc+sd-jwt',
          meta: { vct_values: [c.type] },
          claims: c.claimNames.map((name) => ({ path: [name] })),
        };
      }
      return {
        id: c.queryId,
        format: 'mso_mdoc',
        meta: { doctype_value: c.type },
        claims: c.claimNames.map((name) => ({ path: [c.namespace, name] })),
      };
    }),
  };
}

export function parseRequestedKeys(input: unknown): RequestableKey[] {
  const all = Object.keys(REQUESTABLE) as RequestableKey[];
  if (input == null) return ['pid_sd_jwt'];
  const arr = Array.isArray(input) ? input : [input];
  const keys = arr.filter((k): k is RequestableKey => all.includes(k as RequestableKey));
  return keys.length > 0 ? keys : ['pid_sd_jwt'];
}

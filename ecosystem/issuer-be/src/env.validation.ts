import { plainToInstance } from 'class-transformer';
import { IsJSON, IsNotEmpty, IsOptional, IsString, validateSync } from 'class-validator';

class EnvironmentVariables {
  @IsString()
  @IsNotEmpty()
  STAGE: string;

  @IsString()
  @IsNotEmpty()
  PORT: string;

  @IsString()
  @IsNotEmpty()
  DATABASE_URL: string;

  /**
   * The Credential Issuer identifier — the public base URL. It is the `credential_issuer` in the issuer
   * metadata, the `iss` of the access tokens / c_nonces, and the base every endpoint (.well-known, /par,
   * /authorize, /token, /nonce, /credential, /status-lists) is built from. No trailing slash.
   */
  @IsString()
  @IsNotEmpty()
  ISSUER_BASE_URL: string;

  /** issuer-fe base URL — where /authorize redirects the browser for the issuance consent screen. */
  @IsOptional()
  @IsString()
  ISSUER_FE_URL?: string;

  /**
   * PID Document Signer keystore as a JSON *string*: { privateKeyPem, certPem, caCertPem }. The leaf DSC
   * (chains to the PID Issuer CA) that signs PID credentials (SD-JWT VC x5c[0] / mdoc x5chain[0]).
   * Unset ⇒ an ephemeral self-signed dev key (won't chain to the published Trusted List).
   */
  @IsOptional()
  @IsJSON()
  ISSUER_PID_SIGNER?: string;

  /** mDL Document Signer keystore (JSON: { privateKeyPem, certPem, caCertPem }); leaf chains to the Attestation CA. */
  @IsOptional()
  @IsJSON()
  ISSUER_MDL_SIGNER?: string;

  /**
   * The Provider's registrar_dataset for signed-metadata `issuer_info` (ETSI TS 119 472-3 ISS-MDATA-REG_CERT-4.2.3),
   * as a JSON *string* {identifier, srvDescription, registryURI, providesAttestations?}. `providesAttestations` is
   * auto-derived from the credential configs when omitted. Unset ⇒ a sandbox default dataset.
   */
  @IsOptional()
  @IsJSON()
  ISSUER_REGISTRAR_DATASET?: string;

  /**
   * Optional registrar-issued Provider registration certificate (compact JWS) added to `issuer_info` as a
   * `registration_cert` element (ISS-MDATA-REG_CERT-4.2.3-04..06). Unset ⇒ only the registrar_dataset is sent.
   */
  @IsOptional()
  @IsString()
  ISSUER_REGISTRATION_CERT?: string;

  /**
   * URL of the JAdES-signed Wallet Providers Trusted List used to verify Wallet Attestations (WUAs): the
   * WP CA is extracted from it and wallet attestation x5c chains are checked against it. Default = the
   * Hopae sandbox list.
   */
  @IsOptional()
  @IsString()
  TRUSTED_LIST_URL?: string;

  /**
   * Pinned Scheme Operator signing certificate (PEM) for the Wallet Providers Trusted List JAdES signature.
   * Unset ⇒ the published `scheme-operator.pem` is fetched and pinned on first use (better than trusting the
   * list's own embedded x5c[0]). Set to the real SO cert for out-of-band pinning.
   */
  @IsOptional()
  @IsString()
  ISSUER_SCHEME_OPERATOR_CERT?: string;

  /** Redis URL for shared session/nonce/code state (required for multi-replica). Unset ⇒ in-memory (single-replica dev). */
  @IsOptional()
  @IsString()
  REDIS_URL?: string;

  /** pino log level override (default: debug in non-prod, info in prod). */
  @IsOptional()
  @IsString()
  LOG_LEVEL?: string;

  /** Set to `true` to accept wallets without a valid Wallet/Key Attestation or WUA chain. OFF by default; never in prod. */
  @IsOptional()
  @IsString()
  DEV_ATTESTATION_BYPASS?: string;

  /** Admin API key for admin-only endpoints (revoke). Unset ⇒ those endpoints are unprotected (dev only). */
  @IsOptional()
  @IsString()
  ADMIN_API_KEY?: string;
}

export function validate(config: Record<string, unknown>) {
  const validated = plainToInstance(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });
  const errors = validateSync(validated, { skipMissingProperties: false });
  if (errors.length > 0) {
    throw new Error(
      `Environment validation failed:\n${errors.map((e) => `  - ${Object.values(e.constraints ?? {}).join(', ')}`).join('\n')}`,
    );
  }
  return validated;
}

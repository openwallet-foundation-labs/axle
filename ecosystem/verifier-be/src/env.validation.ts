import { plainToInstance } from 'class-transformer';
import { IsJSON, IsNotEmpty, IsOptional, IsString, validateSync } from 'class-validator';

class EnvironmentVariables {
  @IsString()
  @IsNotEmpty()
  STAGE: string;

  @IsString()
  @IsNotEmpty()
  PORT: string;

  /**
   * The Verifier's public base URL — the base every OpenID4VP endpoint is built from (`/presentations`,
   * `/request/:id`, `/response/:id`) and the `response_uri` / `request_uri` handed to the wallet. It is also
   * the audience the wallet's key-binding JWT is checked against. No trailing slash.
   */
  @IsString()
  @IsNotEmpty()
  VERIFIER_BASE_URL: string;

  /** verifier-fe base URL — where the browser polls the presentation result. */
  @IsOptional()
  @IsString()
  VERIFIER_FE_URL?: string;

  /**
   * The Wallet-Relying Party Access Certificate (WRPAC) keystore as a JSON *string*:
   * { privateKeyPem, certPem, caCertPem }. The reader access cert (chains to the Registrar CA) whose key
   * signs the OpenID4VP request object; `client_id` = `x509_hash:base64url(SHA-256(certDer))` (HAIP).
   * Unset ⇒ an ephemeral self-signed dev key (won't chain to the Registrar CA, so real wallets reject it).
   */
  @IsOptional()
  @IsJSON()
  VERIFIER_WRPAC?: string;

  /**
   * The Wallet-Relying Party Registration Certificate (WRPRC) — a registrar-issued `rc-wrp+jwt` compact JWS,
   * carried by value in the request's `verifier_info` `registration_cert` element (ETSI TS 119 472-2 §6.3).
   * Unset ⇒ no `registration_cert` element is sent (the wallet then skips WRPRC handling).
   */
  @IsOptional()
  @IsString()
  VERIFIER_WRPRC?: string;

  /**
   * The RP Registrar dataset for the `verifier_info` `registrar_dataset` element, as a JSON *string*
   * (identifier, srvDescription, registryURI, intendedUseIdentifier, purpose, policyURI, credential).
   * Unset ⇒ a minimal dataset is derived from the WRPAC/config.
   */
  @IsOptional()
  @IsJSON()
  VERIFIER_REGISTRAR_DATASET?: string;

  /**
   * Base URL of the JAdES-signed Trusted Lists (ETSI TS 119 602) used to verify presented credentials: the
   * PID Issuer CA (`/pid-issuers.jades.json`) and Attestation CA (`/attestation-issuers.jades.json`) are
   * extracted from it and the credential's x5c chains are checked against them. Default = the Hopae sandbox.
   */
  @IsOptional()
  @IsString()
  TRUSTED_LIST_BASE_URL?: string;

  /** pino log level override (default: debug in non-prod, info in prod). */
  @IsOptional()
  @IsString()
  LOG_LEVEL?: string;
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

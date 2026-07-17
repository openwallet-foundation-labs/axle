// gen-mdoc-fixtures.ts — issues every mso_mdoc CREDENTIAL_CONFIG through the REAL issuer code path
// (MdocService + the sandbox Document Signers from ecosystem/trusted-list/secrets) and prints a JSON
// fixture array. Feed it to the wallet SDKs' fixture-driven interop tests, e.g. the swift verifier:
//
//   cd ecosystem/issuer-be
//   npx ts-node -T --skipProject --compilerOptions '{"module":"commonjs","moduleResolution":"node","experimentalDecorators":true,"esModuleInterop":true,"target":"ES2022"}' \
//     tools/gen-mdoc-fixtures.ts > /tmp/mdoc-fixtures.json
//   cd ../../swift
//   EUDI_MDOC_FIXTURES=/tmp/mdoc-fixtures.json swift test --filter LiveIssuerFixtureTests \
//     -Xlinker -L/usr/lib/gcc/x86_64-linux-gnu/11   # linker flag: Linux only
//
// Output element: { id, doctype, signer, issuerSignedB64 (standard base64 CBOR IssuerSigned), caDerB64 }.
import { readFileSync } from 'fs';
import { join } from 'path';
import { exportJWK, generateKeyPair, importPKCS8 } from 'jose';
import { CREDENTIAL_CONFIGS } from '../src/vci/credential-configs';
import { MdocService } from '../src/credentials/mdoc.service';

const SECRETS = join(__dirname, '../../trusted-list/secrets');

function pemBody(pem: string): string {
  return pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

async function loadSigner(file: string) {
  const ks = JSON.parse(readFileSync(join(SECRETS, file), 'utf8'));
  const privateJwk = await exportJWK(await importPKCS8(ks.privateKeyPem, 'ES256', { extractable: true }));
  return {
    privateJwk,
    certDer: new Uint8Array(Buffer.from(pemBody(ks.certPem), 'base64')),
    caDerB64: pemBody(ks.caCertPem),
  };
}

async function main() {
  const signers: Record<string, Awaited<ReturnType<typeof loadSigner>>> = {
    pid: await loadSigner('pid-signer.json'),
    mdl: await loadSigner('mdl-signer.json'),
  };
  const keystore = { getSigner: (t: string) => signers[t] };
  const svc = new MdocService(keystore as never);

  const { publicKey } = await generateKeyPair('ES256', { extractable: true });
  const deviceJwk = await exportJWK(publicKey);

  const out: unknown[] = [];
  for (const c of CREDENTIAL_CONFIGS) {
    if (c.format !== 'mso_mdoc') continue;
    const issuerSigned = await svc.issue(
      c.doctype!, c.mdocNamespaces!, deviceJwk as never, c.signer,
      { idx: 0, uri: 'https://tiss.api.hopae.com/status-lists/1' },
      c.validityDays,
    );
    out.push({
      id: c.id,
      doctype: c.doctype,
      signer: c.signer,
      issuerSignedB64: Buffer.from(issuerSigned, 'base64url').toString('base64'),
      caDerB64: signers[c.signer].caDerB64,
    });
    process.stderr.write(`issued ${c.id} (${c.doctype}) validityDays=${c.validityDays ?? 'default'}\n`);
  }
  process.stdout.write(JSON.stringify(out, null, 2) + '\n');
}

main().catch((e) => { console.error(e); process.exit(1); });

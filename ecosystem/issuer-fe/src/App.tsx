import { useEffect, useState, type ReactNode } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { BadgeCheck, Check, Copy, Loader2, QrCode, ShieldAlert, Smartphone, X } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';

const BE = import.meta.env.VITE_ISSUER_BE_URL ?? 'http://localhost:3400';

const FORMAT_LABEL: Record<string, string> = {
  'dc+sd-jwt': 'SD-JWT VC',
  mso_mdoc: 'ISO mdoc',
};

const DESCRIPTIONS: Record<string, string> = {
  'eu.europa.ec.eudi.pid.sd_jwt_vc':
    'Person Identification Data as an IETF SD-JWT VC — selective disclosure, cryptographically holder-bound.',
  'eu.europa.ec.eudi.pid.mdoc': 'Person Identification Data as an ISO/IEC 18013-5 mdoc.',
  'org.iso.18013.5.1.mDL': 'Mobile Driving Licence (ISO/IEC 18013-5 mdoc).',
};

// A stylised ring — evokes an EU-official identity document without reproducing the actual EU emblem.
function Emblem() {
  return (
    <svg viewBox="0 0 48 48" className="h-9 w-9 shrink-0" aria-hidden="true">
      <circle cx="24" cy="24" r="22" fill="#00246b" stroke="#ffcc00" strokeWidth="1.5" />
      <rect x="14" y="17" width="20" height="14" rx="2" fill="none" stroke="#ffcc00" strokeWidth="1.6" />
      <circle cx="19.5" cy="22.5" r="2.4" fill="#ffcc00" />
      <line x1="24" y1="21" x2="30" y2="21" stroke="#ffcc00" strokeWidth="1.4" strokeLinecap="round" />
      <line x1="24" y1="24" x2="30" y2="24" stroke="#ffcc00" strokeWidth="1.4" strokeLinecap="round" />
      <line x1="16.5" y1="27.5" x2="31.5" y2="27.5" stroke="#ffcc00" strokeWidth="1.2" strokeLinecap="round" />
    </svg>
  );
}

function SiteHeader() {
  return (
    <header className="sticky top-0 z-40 w-full border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80">
      <div className="h-1 w-full bg-primary" />
      <div className="mx-auto flex h-16 w-full max-w-2xl items-center gap-3 px-4">
        <Emblem />
        <div className="min-w-0 leading-tight">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">EUDI Wallet</div>
          <div className="text-base font-semibold tracking-tight">Credential Issuer</div>
        </div>
        <div className="ml-auto hidden shrink-0 text-right text-[11px] leading-tight text-muted-foreground sm:block">
          Hopae EUDI Sandbox
          <br />
          Luxembourg
        </div>
      </div>
    </header>
  );
}

function Hero({ eyebrow, title, children }: { eyebrow: string; title: string; children: ReactNode }) {
  return (
    <section className="border-b border-border bg-muted/30">
      <div className="mx-auto w-full max-w-2xl px-4 py-10 sm:py-12">
        <Badge variant="secondary">{eyebrow}</Badge>
        <h1 className="mt-4 text-2xl font-semibold tracking-tight sm:text-3xl">{title}</h1>
        <p className="mt-3 max-w-xl text-sm leading-relaxed text-muted-foreground">{children}</p>
      </div>
    </section>
  );
}

export default function App() {
  const session = new URLSearchParams(window.location.search).get('session');
  return (
    <div className="flex min-h-screen flex-col overflow-x-hidden bg-background text-foreground">
      <div className="bg-amber-400 text-amber-950">
        <div className="mx-auto max-w-2xl px-4 py-1.5 text-center text-xs font-semibold tracking-wide">
          DEMO FLOW · Sandbox — no real authentication, no real personal data
        </div>
      </div>

      <SiteHeader />

      <main className="flex-1">{session ? <ConsentView session={session} /> : <LandingView />}</main>

      <footer className="border-t border-border bg-muted/30">
        <div className="mx-auto w-full max-w-2xl px-4 py-6 text-center text-[11px] leading-relaxed text-muted-foreground">
          OpenID4VCI 1.0 · HAIP · ETSI SD-JWT VC / ISO 18013-5 mdoc — Hopae EUDI Sandbox (not a production service)
        </div>
      </footer>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------------------
// Landing: list the offered credentials, hand out a credential offer (QR + deep link) for the wallet.
// ---------------------------------------------------------------------------------------------------------
interface OfferConfig {
  id: string;
  name: string;
  format: string;
  description: string;
}

// Issuance options the operator picks; they are baked into the credential offer (the wallet SDK reads them).
type FlowChoice = 'authorization_code' | 'pre-authorized_code';
interface Options {
  flow: FlowChoice;
  deferred: boolean;
  encrypted: boolean;
  batchSize: 1 | 3;
}
// PID's natural flow is authorization_code (with consent); mDL is pre-authorized. Either can be overridden.
const defaultOptions = (id: string): Options => ({
  flow: id.includes('pid') ? 'authorization_code' : 'pre-authorized_code',
  deferred: false,
  encrypted: false,
  batchSize: 1,
});

interface Offer {
  name: string;
  deepLink: string;
  uri: string;
  options: Options;
}

/** A compact segmented control for a small set of mutually-exclusive choices. */
function Segmented<T extends string | number>({
  value,
  onChange,
  opts,
}: {
  value: T;
  onChange: (v: T) => void;
  opts: { v: T; label: string }[];
}) {
  return (
    <div className="inline-flex rounded-md border border-border p-0.5">
      {opts.map((o) => (
        <button
          key={String(o.v)}
          type="button"
          onClick={() => onChange(o.v)}
          className={cn(
            'rounded px-2.5 py-1 text-xs font-medium transition-colors',
            value === o.v ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground',
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/** An on/off pill toggle. */
function Toggle({ on, onChange, label }: { on: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!on)}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors',
        on ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:text-foreground',
      )}
    >
      <span className={cn('h-2 w-2 rounded-full', on ? 'bg-primary' : 'bg-muted-foreground/40')} />
      {label}
    </button>
  );
}

function OptionField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">{label}</span>
      {children}
    </div>
  );
}

function LandingView() {
  const [configs, setConfigs] = useState<OfferConfig[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [offer, setOffer] = useState<Offer | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [options, setOptions] = useState<Record<string, Options>>({});
  const optFor = (id: string) => options[id] ?? defaultOptions(id);
  const setOpt = (id: string, patch: Partial<Options>) =>
    setOptions((o) => ({ ...o, [id]: { ...optFor(id), ...patch } }));

  useEffect(() => {
    fetch(`${BE}/.well-known/openid-credential-issuer/eudi-issuer`)
      .then((r) => {
        if (!r.ok) throw new Error('metadata');
        return r.json();
      })
      .then((m) => {
        const cfgs = m.credential_configurations_supported as Record<string, { format: string; display?: { name: string }[] }>;
        setConfigs(
          Object.entries(cfgs).map(([id, c]) => ({
            id,
            name: c.display?.[0]?.name ?? id,
            format: c.format,
            description: DESCRIPTIONS[id] ?? '',
          })),
        );
      })
      .catch(() => setErr('Could not reach the issuer. Please try again later.'));
  }, []);

  async function getOffer(c: OfferConfig) {
    setBusy(c.id);
    const o = optFor(c.id);
    try {
      const r = await fetch(`${BE}/eudi-issuer/credential-offer/create`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          credential_configuration_id: c.id,
          flow: o.flow,
          deferred: o.deferred,
          encrypted: o.encrypted,
          batch_size: o.batchSize,
        }),
      });
      const { deep_link, credential_offer_uri } = await r.json();
      setOffer({ name: c.name, deepLink: deep_link, uri: credential_offer_uri, options: o });
    } catch {
      setErr('Could not create the credential offer.');
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <Hero eyebrow="EU Digital Identity Wallet" title="Available credentials">
        Pick a credential, then scan the QR code with your EUDI wallet (or open it on this device) to add it to
        your wallet.
      </Hero>

      <div className="mx-auto w-full max-w-2xl px-4 py-8">
        {err ? (
          <ErrorBox msg={err} />
        ) : !configs ? (
          <Centered>
            <Loader2 className="h-6 w-6 animate-spin" />
            <span>Loading credentials…</span>
          </Centered>
        ) : (
          <div className="space-y-3">
            {configs.map((c) => (
              <Card key={c.id}>
                <CardHeader>
                  <div className="flex flex-wrap items-center gap-2">
                    <CardTitle className="text-base">{c.name}</CardTitle>
                    <Badge variant="secondary">{FORMAT_LABEL[c.format] ?? c.format}</Badge>
                  </div>
                  {c.description && <CardDescription>{c.description}</CardDescription>}
                </CardHeader>
                <CardContent className="space-y-4">
                  {(() => {
                    const o = optFor(c.id);
                    return (
                      <div className="grid gap-3 rounded-lg border border-border bg-muted/20 p-3 sm:grid-cols-2">
                        <OptionField label="Flow">
                          <Segmented
                            value={o.flow}
                            onChange={(v) => setOpt(c.id, { flow: v })}
                            opts={[
                              { v: 'authorization_code', label: 'Auth code' },
                              { v: 'pre-authorized_code', label: 'Pre-auth' },
                            ]}
                          />
                        </OptionField>
                        <OptionField label="Batch size">
                          <Segmented
                            value={o.batchSize}
                            onChange={(v) => setOpt(c.id, { batchSize: v })}
                            opts={[
                              { v: 1, label: '1' },
                              { v: 3, label: '3' },
                            ]}
                          />
                        </OptionField>
                        <OptionField label="Response">
                          <Toggle on={o.encrypted} onChange={(v) => setOpt(c.id, { encrypted: v })} label="Encrypted (JWE)" />
                        </OptionField>
                        <OptionField label="Issuance">
                          <Toggle on={o.deferred} onChange={(v) => setOpt(c.id, { deferred: v })} label="Deferred" />
                        </OptionField>
                      </div>
                    );
                  })()}
                  <Button onClick={() => getOffer(c)} disabled={busy === c.id} className="w-full sm:w-auto">
                    {busy === c.id ? <Loader2 className="animate-spin" /> : <QrCode />}
                    Get credential
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      {offer && <OfferModal offer={offer} onClose={() => setOffer(null)} />}
    </>
  );
}

function OfferModal({ offer, onClose }: { offer: Offer; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <Card className="w-full max-w-sm" onClick={(e) => e.stopPropagation()}>
        <CardHeader className="items-center text-center">
          <CardTitle className="text-lg">{offer.name}</CardTitle>
          <CardDescription>Scan with your EUDI wallet</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col items-center gap-4">
          <div className="rounded-xl border bg-white p-3">
            <QRCodeSVG value={offer.deepLink} size={216} level="M" />
          </div>
          <div className="flex w-full flex-wrap justify-center gap-1.5">
            <Badge variant="secondary">{offer.options.flow === 'authorization_code' ? 'Auth code' : 'Pre-auth'}</Badge>
            <Badge variant="secondary">Batch {offer.options.batchSize}</Badge>
            {offer.options.encrypted && <Badge variant="secondary">Encrypted</Badge>}
            {offer.options.deferred && <Badge variant="secondary">Deferred</Badge>}
          </div>
          <Button asChild className="w-full">
            <a href={offer.deepLink}>
              <Smartphone />
              Open in wallet
            </a>
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              navigator.clipboard?.writeText(offer.deepLink);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }}
          >
            {copied ? <Check className="text-success" /> : <Copy />}
            {copied ? 'Copied' : 'Copy offer link'}
          </Button>
          <button onClick={onClose} className="text-xs text-muted-foreground transition-colors hover:text-foreground">
            Close
          </button>
        </CardContent>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------------------
// Consent: shown when the authorization-code flow redirects here with ?session=… — review + issue the PID.
// ---------------------------------------------------------------------------------------------------------
interface Field {
  label: string;
  value: string;
}
interface Credential {
  id: string;
  name: string;
  format: string;
  fields: Field[];
}
interface Interaction {
  demo: boolean;
  client_id: string;
  credentials: Credential[];
}
type CState =
  | { s: 'loading' }
  | { s: 'error'; msg: string }
  | { s: 'ready'; data: Interaction }
  | { s: 'submitting'; data: Interaction }
  | { s: 'done' };

function ConsentView({ session }: { session: string }) {
  const [state, setState] = useState<CState>({ s: 'loading' });

  useEffect(() => {
    fetch(`${BE}/eudi-issuer/interaction/${session}`)
      .then((r) => {
        if (!r.ok) throw new Error('This issuance session is invalid or has expired.');
        return r.json();
      })
      .then((data: Interaction) => setState({ s: 'ready', data }))
      .catch((e) => setState({ s: 'error', msg: e.message }));
  }, [session]);

  async function decide(approve: boolean, data: Interaction) {
    setState({ s: 'submitting', data });
    try {
      const r = await fetch(`${BE}/eudi-issuer/interaction/${session}/decide`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ approve }),
      });
      const { redirect } = await r.json();
      setState({ s: 'done' });
      window.location.href = redirect;
    } catch {
      setState({ s: 'error', msg: 'Could not complete the request. Please try again from your wallet.' });
    }
  }

  if (state.s === 'loading')
    return (
      <Centered>
        <Loader2 className="h-6 w-6 animate-spin" />
        <span>Loading your issuance request…</span>
      </Centered>
    );
  if (state.s === 'done')
    return (
      <Centered>
        <Loader2 className="h-6 w-6 animate-spin" />
        <span>Returning to your wallet…</span>
      </Centered>
    );
  if (state.s === 'error')
    return (
      <div className="mx-auto w-full max-w-2xl px-4 py-8">
        <ErrorBox msg={state.msg} />
      </div>
    );

  const data = state.data;
  const busy = state.s === 'submitting';
  return (
    <>
      <Hero eyebrow="Issuance consent" title="Review your credential">
        Your wallet requested the following {data.credentials.length === 1 ? 'credential' : 'credentials'}. Review
        the details, then issue {data.credentials.length === 1 ? 'it' : 'them'} to your wallet.
      </Hero>

      <div className="mx-auto w-full max-w-2xl px-4 py-8">
        <div className="space-y-4">
          {data.credentials.map((c) => (
            <Card key={c.id} className="overflow-hidden">
              <div className="flex items-center justify-between gap-2 border-b border-border bg-muted/50 px-6 py-3">
                <div className="font-semibold tracking-tight">{c.name}</div>
                <Badge variant="secondary">{FORMAT_LABEL[c.format] ?? c.format}</Badge>
              </div>
              <dl className="divide-y divide-border">
                {c.fields.map((f) => (
                  <div key={f.label} className="flex gap-4 px-6 py-2.5 text-sm">
                    <dt className="w-40 shrink-0 text-muted-foreground">{f.label}</dt>
                    <dd className="font-medium">{f.value}</dd>
                  </div>
                ))}
              </dl>
            </Card>
          ))}
        </div>

        <p className="mt-4 text-xs text-muted-foreground">
          Issued by the Centre des technologies de l'information de l'État (CTIE), Luxembourg — sandbox. Client:{' '}
          <span className="font-mono">{data.client_id}</span>
        </p>

        <div className="mt-6 flex flex-col gap-3 sm:flex-row-reverse">
          <Button size="lg" onClick={() => decide(true, data)} disabled={busy}>
            {busy ? <Loader2 className="animate-spin" /> : <BadgeCheck />}
            {busy ? 'Issuing…' : 'Issue to wallet'}
          </Button>
          <Button size="lg" variant="outline" onClick={() => decide(false, data)} disabled={busy}>
            <X />
            Cancel
          </Button>
        </div>
      </div>
    </>
  );
}

function Centered({ children }: { children: ReactNode }) {
  return <div className="flex flex-col items-center gap-3 py-20 text-center text-sm text-muted-foreground">{children}</div>;
}

function ErrorBox({ msg }: { msg: string }) {
  return (
    <Card className="border-destructive/40 bg-destructive/5">
      <CardContent className="flex items-start gap-3 py-6">
        <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-destructive" />
        <div>
          <p className="font-semibold text-destructive">Unable to continue</p>
          <p className="mt-1 text-sm text-destructive/90">{msg}</p>
        </div>
      </CardContent>
    </Card>
  );
}

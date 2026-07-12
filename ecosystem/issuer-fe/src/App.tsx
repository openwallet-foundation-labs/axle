import { useEffect, useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';

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
    <svg viewBox="0 0 48 48" className="h-9 w-9" aria-hidden="true">
      <circle cx="24" cy="24" r="22" fill="#00246b" stroke="#ffcc00" strokeWidth="1.5" />
      <rect x="14" y="17" width="20" height="14" rx="2" fill="none" stroke="#ffcc00" strokeWidth="1.6" />
      <circle cx="19.5" cy="22.5" r="2.4" fill="#ffcc00" />
      <line x1="24" y1="21" x2="30" y2="21" stroke="#ffcc00" strokeWidth="1.4" strokeLinecap="round" />
      <line x1="24" y1="24" x2="30" y2="24" stroke="#ffcc00" strokeWidth="1.4" strokeLinecap="round" />
      <line x1="16.5" y1="27.5" x2="31.5" y2="27.5" stroke="#ffcc00" strokeWidth="1.2" strokeLinecap="round" />
    </svg>
  );
}

export default function App() {
  const session = new URLSearchParams(window.location.search).get('session');
  return (
    <div className="min-h-screen overflow-x-hidden bg-slate-100 font-sans text-slate-900">
      <div className="bg-amber-400 text-amber-950">
        <div className="mx-auto max-w-2xl px-4 py-1.5 text-center text-xs font-semibold tracking-wide">
          DEMO FLOW · Sandbox — no real authentication, no real personal data
        </div>
      </div>
      <header className="bg-eu-blue text-white">
        <div className="mx-auto flex max-w-2xl items-center gap-3 px-4 py-4">
          <Emblem />
          <div className="min-w-0 leading-tight">
            <div className="text-[13px] font-semibold uppercase tracking-wider text-eu-gold">EUDI Wallet</div>
            <div className="text-lg font-semibold">Credential Issuer</div>
          </div>
          <div className="ml-auto hidden shrink-0 text-right text-[11px] text-white/70 sm:block">
            Hopae EUDI Sandbox
            <br />
            Luxembourg
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-2xl px-4 py-8">{session ? <ConsentView session={session} /> : <LandingView />}</main>
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
interface Offer {
  name: string;
  deepLink: string;
  uri: string;
}

function LandingView() {
  const [configs, setConfigs] = useState<OfferConfig[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [offer, setOffer] = useState<Offer | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

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
    try {
      const r = await fetch(`${BE}/eudi-issuer/credential-offer/create`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ credential_configuration_id: c.id }),
      });
      const { deep_link, credential_offer_uri } = await r.json();
      setOffer({ name: c.name, deepLink: deep_link, uri: credential_offer_uri });
    } catch {
      setErr('Could not create the credential offer.');
    } finally {
      setBusy(null);
    }
  }

  if (err) return <ErrorBox msg={err} />;
  if (!configs) return <Centered>Loading credentials…</Centered>;

  return (
    <div>
      <h1 className="text-xl font-semibold tracking-tight">Available credentials</h1>
      <p className="mt-1 text-sm text-slate-600">
        Pick a credential, then scan the QR code with your EUDI wallet (or open it on this device) to add it to
        your wallet.
      </p>

      <div className="mt-6 space-y-3">
        {configs.map((c) => (
          <section
            key={c.id}
            className="flex flex-col gap-3 rounded-xl border border-slate-200 bg-white p-5 shadow-sm sm:flex-row sm:items-center sm:gap-4"
          >
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="font-semibold text-eu-deep">{c.name}</h2>
                <span className="rounded-full bg-eu-blue/10 px-2.5 py-0.5 text-xs font-medium text-eu-blue">
                  {FORMAT_LABEL[c.format] ?? c.format}
                </span>
              </div>
              <p className="mt-1 text-sm text-slate-600">{c.description}</p>
            </div>
            <button
              onClick={() => getOffer(c)}
              disabled={busy === c.id}
              className="w-full shrink-0 rounded-lg bg-eu-blue px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-eu-deep disabled:opacity-60 sm:w-auto"
            >
              {busy === c.id ? '…' : 'Get credential'}
            </button>
          </section>
        ))}
      </div>

      {offer && <OfferModal offer={offer} onClose={() => setOffer(null)} />}

      <footer className="mt-10 border-t border-slate-200 pt-4 text-center text-[11px] text-slate-400">
        OpenID4VCI 1.0 · HAIP · ETSI SD-JWT VC / ISO 18013-5 mdoc — Hopae EUDI Sandbox (not a production service)
      </footer>
    </div>
  );
}

function OfferModal({ offer, onClose }: { offer: Offer; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <div className="w-full max-w-sm rounded-2xl bg-white p-6 text-center shadow-xl" onClick={(e) => e.stopPropagation()}>
        <h3 className="text-lg font-semibold">{offer.name}</h3>
        <p className="mt-1 text-sm text-slate-600">Scan with your EUDI wallet</p>
        <div className="mx-auto mt-4 w-fit rounded-xl border border-slate-200 bg-white p-3">
          <QRCodeSVG value={offer.deepLink} size={216} level="M" />
        </div>
        <a
          href={offer.deepLink}
          className="mt-4 block rounded-lg bg-eu-blue px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-eu-deep"
        >
          Open in wallet
        </a>
        <button
          onClick={() => {
            navigator.clipboard?.writeText(offer.deepLink);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
          className="mt-2 text-xs font-medium text-eu-blue hover:underline"
        >
          {copied ? 'Copied ✓' : 'Copy offer link'}
        </button>
        <button onClick={onClose} className="mt-4 block w-full text-xs text-slate-400 hover:text-slate-600">
          Close
        </button>
      </div>
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

  if (state.s === 'loading') return <Centered>Loading your issuance request…</Centered>;
  if (state.s === 'done') return <Centered>Returning to your wallet…</Centered>;
  if (state.s === 'error') return <ErrorBox msg={state.msg} />;

  const data = state.data;
  const busy = state.s === 'submitting';
  return (
    <div>
      <h1 className="text-xl font-semibold tracking-tight">Review your credential</h1>
      <p className="mt-1 text-sm text-slate-600">
        Your wallet requested the following {data.credentials.length === 1 ? 'credential' : 'credentials'}. Review
        the details, then issue {data.credentials.length === 1 ? 'it' : 'them'} to your wallet.
      </p>

      <div className="mt-6 space-y-4">
        {data.credentials.map((c) => (
          <section key={c.id} className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
            <div className="flex items-center justify-between border-b border-slate-100 bg-slate-50 px-5 py-3">
              <h2 className="font-semibold text-eu-deep">{c.name}</h2>
              <span className="rounded-full bg-eu-blue/10 px-2.5 py-0.5 text-xs font-medium text-eu-blue">
                {FORMAT_LABEL[c.format] ?? c.format}
              </span>
            </div>
            <dl className="divide-y divide-slate-100">
              {c.fields.map((f) => (
                <div key={f.label} className="flex gap-4 px-5 py-2.5 text-sm">
                  <dt className="w-40 shrink-0 text-slate-500">{f.label}</dt>
                  <dd className="font-medium text-slate-900">{f.value}</dd>
                </div>
              ))}
            </dl>
          </section>
        ))}
      </div>

      <p className="mt-4 text-xs text-slate-500">
        Issued by the Centre des technologies de l'information de l'État (CTIE), Luxembourg — sandbox. Client:{' '}
        <span className="font-mono">{data.client_id}</span>
      </p>

      <div className="mt-6 flex flex-col gap-3 sm:flex-row-reverse">
        <button
          onClick={() => decide(true, data)}
          disabled={busy}
          className="inline-flex items-center justify-center rounded-lg bg-eu-blue px-6 py-3 font-semibold text-white shadow-sm transition hover:bg-eu-deep disabled:opacity-60"
        >
          {busy ? 'Issuing…' : 'Issue to wallet'}
        </button>
        <button
          onClick={() => decide(false, data)}
          disabled={busy}
          className="inline-flex items-center justify-center rounded-lg border border-slate-300 bg-white px-6 py-3 font-semibold text-slate-700 transition hover:bg-slate-50 disabled:opacity-60"
        >
          Cancel
        </button>
      </div>

      <footer className="mt-10 border-t border-slate-200 pt-4 text-center text-[11px] text-slate-400">
        OpenID4VCI 1.0 · HAIP · ETSI SD-JWT VC / ISO 18013-5 mdoc — Hopae EUDI Sandbox (not a production service)
      </footer>
    </div>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return <div className="py-20 text-center text-slate-500">{children}</div>;
}
function ErrorBox({ msg }: { msg: string }) {
  return (
    <div className="rounded-xl border border-red-200 bg-red-50 p-6 text-red-800">
      <p className="font-semibold">Unable to continue</p>
      <p className="mt-1 text-sm">{msg}</p>
    </div>
  );
}

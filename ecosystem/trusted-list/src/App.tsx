import { useEffect, useState } from 'react';
import { Check, ChevronRight, Copy, Download, ShieldCheck, FileSignature, CalendarClock } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';

// Canonical production origin the curl commands point at (the site itself may be served from a preview URL).
// Set VITE_SITE_URL at build time (e.g. Vercel env); falls back to the sandbox's production domain.
const SITE = import.meta.env.VITE_SITE_URL ?? 'https://trusted-list.vercel.app';

interface Format {
  key: string;
  label: string;
  hint: string;
  file: string;
}
interface Service {
  name: string;
  type: string;
}
interface Entity {
  name: string;
  services: Service[];
}

/**
 * How an anchor got onto the list, derived from its `serviceTypeIdentifier`. A list mixes CAs the scheme
 * operates and is answerable for with anchors it merely observed and republished — the reader has to be able
 * to tell those apart at a glance, so the portal groups by this rather than listing everything in one run.
 */
const PROVENANCE = [
  {
    id: 'scheme',
    short: 'Scheme',
    label: 'Operated by the scheme',
    note: 'Certificate authorities this sandbox runs and is answerable for.',
    match: (t: string) => t.startsWith('http://uri.etsi.org/19602/SvcType/'),
  },
  {
    id: 'production',
    short: 'Production',
    label: 'Mirrored — production issuers',
    note: 'Live issuing authority roots observed from their public sources. Republished, not certified by the scheme.',
    match: (t: string) => t.includes('/mirrored-iaca'),
  },
  {
    id: 'reference',
    short: 'Reference',
    label: 'Mirrored — EU reference implementation',
    note: 'The EU reference wallet stack’s PID and Age Verification issuer CAs.',
    match: (t: string) => t.includes('/mirrored-reference'),
  },
  {
    id: 'test',
    short: 'Test',
    label: 'Test & conformance roots',
    note: 'Interop and conformance harnesses. Present because this ecosystem is itself a demo.',
    match: (t: string) => t.includes('/sandbox-only'),
  },
] as const;
const OTHER = { id: 'other', short: 'Other', label: 'Other', note: '', match: () => true } as const;

const provenanceOf = (type: string) => PROVENANCE.find((p) => p.match(type)) ?? OTHER;

/** Splits "mDL IACA — California DMV IACA Root · valid to 2033-01-07" into its kind and the rest. */
function splitKind(serviceName: string): [kind: string | null, rest: string] {
  const at = serviceName.indexOf(' — ');
  return at === -1 ? [null, serviceName] : [serviceName.slice(0, at), serviceName.slice(at + 3)];
}

/** Entities split by provenance, each entity carrying only the services of that group. */
function groupByProvenance(entities: Entity[]) {
  return [...PROVENANCE, OTHER]
    .map((group) => ({
      ...group,
      entities: entities
        .map((e) => ({ name: e.name, services: e.services.filter((s) => provenanceOf(s.type).id === group.id) }))
        .filter((e) => e.services.length > 0),
    }))
    .filter((g) => g.entities.length > 0);
}
interface TrustList {
  slug: string;
  title: string;
  standard: string;
  description: string;
  sequenceNumber: number;
  issued: string;
  nextUpdate: string;
  entities: Entity[];
  formats: Format[];
}
interface SchemeOperator {
  file: string;
  subject: string;
  fingerprintSha256: string;
  validTo: string;
}
interface Manifest {
  generatedAt: string;
  schemeOperator?: SchemeOperator;
  lists: TrustList[];
}

/** The entities on a list — collapsed to a one-line census, grouped by provenance when opened. */
function EntityDirectory({ entities }: { entities: Entity[] }) {
  const groups = groupByProvenance(entities);
  const count = (list: Entity[]) => list.reduce((n, e) => n + e.services.length, 0);
  const anchors = count(entities);

  return (
    <details
      // A short list is worth reading outright; a 25-entity roll-call has to earn its space.
      open={entities.length <= 3}
      className="group mt-2 rounded-lg border bg-muted/20"
    >
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-xs hover:bg-muted/40">
        <ChevronRight className="size-3.5 shrink-0 text-muted-foreground transition-transform group-open:rotate-90" />
        <span className="font-medium text-foreground">
          {entities.length} {entities.length === 1 ? 'entity' : 'entities'} · {anchors}{' '}
          {anchors === 1 ? 'anchor' : 'anchors'}
        </span>
        <span className="ml-auto flex flex-wrap justify-end gap-1">
          {groups.map((g) => (
            <Badge key={g.id} variant="outline" className="text-[10px] font-normal">
              {g.short} {count(g.entities)}
            </Badge>
          ))}
        </span>
      </summary>

      <div className="space-y-5 border-t px-3 py-3">
        {groups.map((g) => (
          <section key={g.id}>
            <h4 className="text-[11px] font-semibold uppercase tracking-wide text-foreground">{g.label}</h4>
            {g.note && <p className="mt-0.5 text-[11px] leading-relaxed text-muted-foreground">{g.note}</p>}
            <ul className="mt-2 space-y-2">
              {g.entities.map((e) => (
                <li key={e.name} className="text-xs">
                  <span className="font-medium text-foreground">{e.name}</span>
                  <ul className="mt-1 space-y-1 border-l border-border pl-3">
                    {e.services.map((s) => {
                      // serviceName is written to stand alone inside the signed list ("mDL IACA — <CN> …").
                      // Here the group heading already says what kind it is, so the prefix is dimmed and the
                      // certificate itself gets the emphasis.
                      const [kind, rest] = splitKind(s.name);
                      return (
                        <li key={s.name} className="leading-relaxed">
                          {kind && <span className="text-muted-foreground/70">{kind} — </span>}
                          <span className="text-muted-foreground">{rest}</span>
                        </li>
                      );
                    })}
                  </ul>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </details>
  );
}

function CopyButton({ text, className }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="ghost"
      size="icon"
      className={cn('h-7 w-7 shrink-0 text-slate-300 hover:bg-slate-700 hover:text-white', className)}
      aria-label="Copy curl command"
      onClick={() => {
        navigator.clipboard?.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
    >
      {copied ? <Check className="text-green-400" /> : <Copy />}
    </Button>
  );
}

function SiteHeader({ anchorFile }: { anchorFile?: string }) {
  return (
    <header className="sticky top-0 z-40 w-full border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80">
      <div className="h-1 w-full bg-primary" />
      <div className="mx-auto flex h-16 w-full max-w-4xl items-center justify-between gap-4 px-6">
        <a href="#top" className="flex items-center gap-2.5">
          <span className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-sm">
            <ShieldCheck className="size-5" />
          </span>
          <span className="flex flex-col leading-tight">
            <span className="text-sm font-semibold tracking-tight sm:text-base">Trust Services</span>
            <span className="text-[11px] text-muted-foreground">Hopae EUDI Sandbox</span>
          </span>
        </a>

        {anchorFile && (
          <Button asChild variant="outline" size="sm">
            <a href={`/tl/${anchorFile}`} download={anchorFile}>
              <Download />
              <span className="hidden sm:inline">Trust anchor</span>
            </a>
          </Button>
        )}
      </div>
    </header>
  );
}

export default function App() {
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch('/tl/lists.json', { cache: 'no-store' })
      .then((r) => {
        if (!r.ok) throw new Error(`${r.status} loading lists.json`);
        return r.json();
      })
      .then(setManifest)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <SiteHeader anchorFile={manifest?.schemeOperator?.file} />

      <main className="flex-1">
        {/* Hero */}
        <section id="top" className="border-b border-border bg-muted/30">
          <div className="mx-auto w-full max-w-4xl px-6 py-14 sm:py-16">
            <Badge variant="secondary">EU Digital Identity Wallet</Badge>
            <h1 className="mt-4 text-3xl font-semibold tracking-tight sm:text-4xl">Trusted Lists</h1>
            <p className="mt-4 max-w-2xl text-base leading-relaxed text-muted-foreground sm:text-lg">
              JAdES-signed Trusted Lists (ETSI TS 119 602) for the Hopae EUDI sandbox. Download the signed
              list for a service type, or fetch it with curl.
            </p>
            <div className="mt-6 flex flex-wrap gap-2">
              <Badge variant="outline" className="font-mono text-[11px]">
                ETSI TS 119 602
              </Badge>
              <Badge variant="outline" className="font-mono text-[11px]">
                JAdES · ETSI TS 119 182-1
              </Badge>
              {manifest && (
                <Badge variant="outline" className="text-[11px]">
                  {manifest.lists.length} {manifest.lists.length === 1 ? 'list' : 'lists'}
                </Badge>
              )}
            </div>
          </div>
        </section>

        {/* Content */}
        <div className="mx-auto w-full max-w-4xl px-6 py-10">
          {error && (
            <div className="rounded-lg border border-destructive/40 bg-destructive/5 px-4 py-3 text-sm text-destructive">
              Could not load the lists: {error}
            </div>
          )}
          {!manifest && !error && <p className="text-sm text-muted-foreground">Loading…</p>}

          {manifest?.schemeOperator && (
            <Card id="scheme-operator" className="mb-6 border-dashed">
              <CardHeader>
                <div className="flex items-center justify-between gap-3">
                  <CardTitle className="text-base">Scheme Operator — trust anchor</CardTitle>
                  <Badge variant="secondary" className="shrink-0">
                    <FileSignature className="mr-1 h-3.5 w-3.5" /> JAdES signer
                  </Badge>
                </div>
                <CardDescription className="flex flex-col gap-1 pt-1">
                  <span>
                    Every list below is JAdES-signed by this certificate. Download and pin it (verify the
                    fingerprint), then you can trust the lists.
                  </span>
                  <span className="pt-1 font-mono text-[11px] text-foreground">
                    {manifest.schemeOperator.subject}
                  </span>
                  <span className="font-mono text-[11px]">
                    SHA-256 {manifest.schemeOperator.fingerprintSha256}
                  </span>
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Button asChild size="sm" variant="outline">
                  <a href={`/tl/${manifest.schemeOperator.file}`} download={manifest.schemeOperator.file}>
                    <Download />
                    Download certificate (PEM)
                  </a>
                </Button>
              </CardContent>
            </Card>
          )}

          <div className="space-y-4">
            {manifest?.lists.map((list) => (
              <Card key={list.slug}>
                <CardHeader>
                  <div className="flex items-start justify-between gap-3">
                    <CardTitle className="text-xl">{list.title}</CardTitle>
                    <Badge variant="outline" className="shrink-0 gap-1 text-[11px] font-normal">
                      <CalendarClock className="h-3.5 w-3.5" />
                      Issued {list.issued.slice(0, 10)}
                    </Badge>
                  </div>
                  <CardDescription className="flex flex-col gap-1.5 pt-1">
                    <span className="font-mono text-xs">{list.standard}</span>
                    <span>{list.description}</span>
                    <EntityDirectory entities={list.entities} />
                  </CardDescription>
                </CardHeader>

                <CardContent className="space-y-3">
                  {list.formats.map((f) => {
                    const curl = `curl -O ${SITE}/tl/${f.file}`;
                    return (
                      <div key={f.key} className="rounded-lg border bg-muted/30 p-3">
                        <div className="flex items-center justify-between gap-3">
                          <div>
                            <div className="text-sm font-medium">{f.label}</div>
                            <div className="text-xs text-muted-foreground">{f.hint}</div>
                          </div>
                          <Button asChild size="sm" variant="outline" className="shrink-0">
                            <a href={`/tl/${f.file}`} download={f.file}>
                              <Download />
                              Download
                            </a>
                          </Button>
                        </div>
                        <div className="relative mt-3">
                          <pre className="whitespace-pre-wrap break-all rounded-md bg-slate-900 py-2 pl-3 pr-10 font-mono text-xs leading-relaxed text-slate-50">
                            {curl}
                          </pre>
                          <CopyButton text={curl} className="absolute right-1 top-1" />
                        </div>
                      </div>
                    );
                  })}
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </main>

      <footer className="border-t border-border bg-muted/30">
        <div className="mx-auto w-full max-w-4xl px-6 py-8 text-xs leading-relaxed text-muted-foreground">
          <p>
            The Scheme Operator signing key is held offline; each list is re-issued at least every 6 months
            (Annex E nextUpdate).
          </p>
          <p className="mt-1 font-mono">
            ETSI TS 119 602 · ETSI TS 119 182-1 (JAdES) · sandbox — not a production trust list.
          </p>
        </div>
      </footer>
    </div>
  );
}

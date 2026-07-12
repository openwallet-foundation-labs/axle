import { useEffect, useState } from 'react';
import { Check, Copy, Download } from 'lucide-react';

import { Button } from '@/components/ui/button';
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
interface Entity {
  name: string;
  services: string[];
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
    <div className="min-h-screen bg-background">
      <div className="mx-auto max-w-3xl px-6 py-16">
        <header className="mb-10">
          <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">Hopae EUDI Sandbox</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight">Trust Services</h1>
          <p className="mt-3 max-w-xl text-sm leading-relaxed text-muted-foreground">
            JAdES-signed Trusted Lists (ETSI TS 119 602) for the Hopae EUDI sandbox. Download the signed list
            for a service type, or fetch it with curl.
          </p>
        </header>

        {error && <p className="text-sm text-red-600">Could not load the lists: {error}</p>}
        {!manifest && !error && <p className="text-sm text-muted-foreground">Loading…</p>}

        {manifest?.schemeOperator && (
          <Card className="mb-4 border-dashed">
            <CardHeader>
              <CardTitle className="text-base">Scheme Operator — trust anchor</CardTitle>
              <CardDescription className="flex flex-col gap-1 pt-1">
                <span>Every list below is JAdES-signed by this certificate. Download and pin it (verify the fingerprint), then you can trust the lists.</span>
                <span className="pt-1 font-mono text-[11px] text-foreground">{manifest.schemeOperator.subject}</span>
                <span className="font-mono text-[11px]">SHA-256 {manifest.schemeOperator.fingerprintSha256}</span>
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
                <CardTitle className="text-xl">{list.title}</CardTitle>
                <CardDescription className="flex flex-col gap-1.5 pt-1">
                  <span className="font-mono text-xs">{list.standard}</span>
                  <span>{list.description}</span>
                  {list.entities.map((e) => (
                    <span key={e.name} className="text-xs">
                      <span className="font-medium text-foreground">{e.name}</span>
                      <span className="text-muted-foreground"> — {e.services.join(' · ')}</span>
                    </span>
                  ))}
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
                        <pre className="whitespace-pre-wrap break-all rounded-md bg-slate-900 py-2 pl-3 pr-10 font-mono text-xs leading-relaxed text-slate-50">{curl}</pre>
                        <CopyButton text={curl} className="absolute right-1 top-1" />
                      </div>
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          ))}
        </div>

        <footer className="mt-12 border-t pt-6 text-xs leading-relaxed text-muted-foreground">
          <p>
            The Scheme Operator signing key is held offline; each list is re-issued at least every 6 months
            (Annex E nextUpdate).
          </p>
          <p className="mt-1 font-mono">
            ETSI TS 119 602 · ETSI TS 119 182-1 (JAdES) · sandbox — not a production trust list.
          </p>
        </footer>
      </div>
    </div>
  );
}

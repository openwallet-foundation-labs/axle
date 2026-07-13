import { useCallback, useEffect, useRef, useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import {
  BadgeCheck,
  CheckCircle2,
  Fingerprint,
  IdCard,
  Loader2,
  QrCode,
  Smartphone,
  XCircle,
  Building2,
  ArrowLeft,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

const BE = (import.meta.env.VITE_VERIFIER_BE_URL as string | undefined) ?? 'https://dev.api.hopae.com/trp';

type CredKey = 'pid_sd_jwt' | 'pid_mdoc' | 'mdl';
type RpMode = 'plain' | 'intermediary';

const CREDENTIALS: { key: CredKey; label: string; type: string; icon: typeof IdCard }[] = [
  { key: 'pid_sd_jwt', label: 'PID · SD-JWT VC', type: 'urn:eudi:pid:1', icon: IdCard },
  { key: 'pid_mdoc', label: 'PID · mdoc', type: 'eu.europa.ec.eudi.pid.1', icon: Fingerprint },
  { key: 'mdl', label: 'mDL · mdoc', type: 'org.iso.18013.5.1.mDL', icon: IdCard },
];

interface CreatedQr {
  transaction_id: string;
  mode: 'qr';
  client_id: string;
  request_uri: string;
  qr: string;
  requested: { key: string; label: string }[];
}
interface CreatedDcApi {
  transaction_id: string;
  mode: 'dc_api';
  requested: { key: string; label: string }[];
  dc_api_request: { protocol: string; request: unknown };
}
interface VerifiedCred {
  queryId: string;
  format: string;
  type: string;
  claims: Record<string, unknown>;
}
interface ResultBody {
  transaction_id: string;
  status: 'pending' | 'verified' | 'failed';
  credentials?: VerifiedCred[];
  error?: string;
}

type Phase =
  | { name: 'config' }
  | { name: 'qr'; created: CreatedQr }
  | { name: 'dcapi'; note: string }
  | { name: 'result'; result: ResultBody };

export default function App() {
  const [selected, setSelected] = useState<Set<CredKey>>(new Set(['pid_sd_jwt']));
  const [rp, setRp] = useState<RpMode>('plain');
  const [phase, setPhase] = useState<Phase>({ name: 'config' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);

  const stopPolling = () => {
    if (pollRef.current) {
      window.clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };
  useEffect(() => () => stopPolling(), []);

  const toggle = (k: CredKey) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      if (next.size === 0) next.add(k); // keep at least one
      return next;
    });

  const reset = () => {
    stopPolling();
    setError(null);
    setPhase({ name: 'config' });
  };

  const create = useCallback(
    async (mode: 'qr' | 'dc_api') => {
      const body = {
        credentials: [...selected],
        mode,
        rp,
        ...(mode === 'dc_api' ? { origins: [window.location.origin] } : {}),
      };
      const res = await fetch(`${BE}/presentations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`request failed: HTTP ${res.status}`);
      return res.json();
    },
    [selected, rp],
  );

  const poll = (id: string) => {
    stopPolling();
    pollRef.current = window.setInterval(async () => {
      try {
        const r: ResultBody = await (await fetch(`${BE}/presentations/${id}`)).json();
        if (r.status !== 'pending') {
          stopPolling();
          setPhase({ name: 'result', result: r });
        }
      } catch {
        /* keep polling */
      }
    }, 2000);
  };

  const startQr = async () => {
    setBusy(true);
    setError(null);
    try {
      const created: CreatedQr = await create('qr');
      setPhase({ name: 'qr', created });
      poll(created.transaction_id);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const startDcApi = async () => {
    setBusy(true);
    setError(null);
    try {
      const created: CreatedDcApi = await create('dc_api');
      // Digital Credentials API (experimental; shape varies by browser).
      const anyNav = navigator as unknown as {
        credentials: { get: (o: unknown) => Promise<{ data?: unknown } | null> };
      };
      const supported = 'credentials' in navigator && typeof anyNav.credentials.get === 'function';
      if (!supported) throw new Error('이 브라우저는 Digital Credentials API를 지원하지 않습니다. QR 방식을 사용하세요.');
      setPhase({ name: 'dcapi', note: '지갑에서 자격증명을 선택하세요…' });

      const resp = await anyNav.credentials.get({
        digital: { requests: [{ protocol: 'openid4vp', data: (created.dc_api_request as { request: unknown }).request }] },
      } as unknown);
      if (!resp) throw new Error('지갑이 응답을 반환하지 않았습니다.');

      // The wallet's OpenID4VP response (Authorization Response) — a JSON object or string carrying vp_token.
      const raw = (resp as { data?: unknown }).data;
      const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
      const vp_token = (data as { vp_token?: unknown })?.vp_token ?? data;

      await fetch(`${BE}/presentations/${created.transaction_id}/dc-api-response`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vp_token, origin: window.location.origin }),
      });
      const r: ResultBody = await (await fetch(`${BE}/presentations/${created.transaction_id}`)).json();
      setPhase({ name: 'result', result: r });
    } catch (e) {
      setError((e as Error).message);
      setPhase({ name: 'config' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen w-full">
      <div className="mx-auto flex min-h-screen max-w-2xl flex-col px-4 py-10">
        <header className="mb-8 flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-primary text-primary-foreground">
            <BadgeCheck className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight">EUDI Verifier</h1>
            <p className="text-sm text-muted-foreground">OpenID4VP relying party — Hopae Sandbox</p>
          </div>
        </header>

        {phase.name === 'config' && (
          <ConfigView
            selected={selected}
            toggle={toggle}
            rp={rp}
            setRp={setRp}
            busy={busy}
            error={error}
            onQr={startQr}
            onDcApi={startDcApi}
          />
        )}
        {phase.name === 'qr' && <QrView created={phase.created} onBack={reset} />}
        {phase.name === 'dcapi' && <WaitingView note={phase.note} />}
        {phase.name === 'result' && <ResultView result={phase.result} onBack={reset} />}

        <footer className="mt-auto pt-10 text-center text-xs text-muted-foreground">
          Requests are signed with a registrar-issued WRPAC; the WRPRC travels in <code>verifier_info</code>.
        </footer>
      </div>
    </div>
  );
}

function ConfigView(props: {
  selected: Set<CredKey>;
  toggle: (k: CredKey) => void;
  rp: RpMode;
  setRp: (r: RpMode) => void;
  busy: boolean;
  error: string | null;
  onQr: () => void;
  onDcApi: () => void;
}) {
  const { selected, toggle, rp, setRp, busy, error, onQr, onDcApi } = props;
  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>요청할 자격증명</CardTitle>
          <CardDescription>지갑에 제시를 요청할 크리덴셜을 선택하세요 (복수 선택 가능).</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-3">
          {CREDENTIALS.map((c) => {
            const on = selected.has(c.key);
            const Icon = c.icon;
            return (
              <button
                key={c.key}
                onClick={() => toggle(c.key)}
                className={cn(
                  'flex flex-col items-start gap-2 rounded-lg border p-3 text-left transition-colors',
                  on ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'hover:bg-accent',
                )}
              >
                <div className="flex w-full items-center justify-between">
                  <Icon className="h-5 w-5" />
                  {on && <CheckCircle2 className="h-4 w-4 text-primary" />}
                </div>
                <div className="text-sm font-medium">{c.label}</div>
                <div className="break-all text-[11px] text-muted-foreground">{c.type}</div>
              </button>
            );
          })}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Relying Party</CardTitle>
          <CardDescription>요청에 실을 등록 인증서(WRPRC)를 선택하세요.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          {(
            [
              { key: 'plain', label: '일반 RP', desc: '직접 등록된 relying party' },
              { key: 'intermediary', label: 'Intermediary 경유', desc: '중개자를 통해 등록된 RP (intermediary 필드 포함)' },
            ] as const
          ).map((o) => (
            <button
              key={o.key}
              onClick={() => setRp(o.key)}
              className={cn(
                'flex items-start gap-3 rounded-lg border p-3 text-left transition-colors',
                rp === o.key ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'hover:bg-accent',
              )}
            >
              <Building2 className="mt-0.5 h-5 w-5 shrink-0" />
              <div>
                <div className="text-sm font-medium">{o.label}</div>
                <div className="text-xs text-muted-foreground">{o.desc}</div>
              </div>
            </button>
          ))}
        </CardContent>
      </Card>

      {error && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/5 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2">
        <Button size="lg" onClick={onQr} disabled={busy}>
          {busy ? <Loader2 className="h-5 w-5 animate-spin" /> : <QrCode className="h-5 w-5" />}
          QR로 요청 (교차 기기)
        </Button>
        <Button size="lg" variant="secondary" onClick={onDcApi} disabled={busy}>
          <Smartphone className="h-5 w-5" />
          DC API로 요청 (동일 기기)
        </Button>
      </div>
    </div>
  );
}

function QrView({ created, onBack }: { created: CreatedQr; onBack: () => void }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>지갑으로 스캔</CardTitle>
        <CardDescription>
          {created.requested.map((r) => r.label).join(', ')} — QR을 지갑으로 스캔하거나, 같은 기기라면 버튼으로 여세요.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col items-center gap-5">
        <div className="rounded-xl border bg-white p-4">
          <QRCodeSVG value={created.qr} size={232} level="M" />
        </div>
        <a href={created.qr} className="w-full">
          <Button size="lg" className="w-full">
            <Smartphone className="h-5 w-5" />
            지갑 앱으로 열기
          </Button>
        </a>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          지갑의 응답을 기다리는 중…
        </div>
        <code className="w-full break-all rounded bg-muted px-3 py-2 text-[11px] text-muted-foreground">
          {created.client_id}
        </code>
        <Button variant="ghost" size="sm" onClick={onBack}>
          <ArrowLeft className="h-4 w-4" /> 취소
        </Button>
      </CardContent>
    </Card>
  );
}

function WaitingView({ note }: { note: string }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-4 py-14">
        <Loader2 className="h-10 w-10 animate-spin text-primary" />
        <div className="text-sm text-muted-foreground">{note}</div>
      </CardContent>
    </Card>
  );
}

function ResultView({ result, onBack }: { result: ResultBody; onBack: () => void }) {
  const ok = result.status === 'verified';
  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardContent className="flex flex-col items-center gap-3 py-10 text-center">
          {ok ? (
            <CheckCircle2 className="h-14 w-14 text-success" />
          ) : (
            <XCircle className="h-14 w-14 text-destructive" />
          )}
          <div className="text-lg font-semibold">{ok ? '검증 완료' : '검증 실패'}</div>
          {!ok && result.error && <div className="max-w-md text-sm text-muted-foreground">{result.error}</div>}
        </CardContent>
      </Card>

      {ok &&
        (result.credentials ?? []).map((c) => (
          <Card key={c.queryId}>
            <CardHeader className="flex-row items-center justify-between space-y-0">
              <div>
                <CardTitle className="text-base">{c.type}</CardTitle>
                <CardDescription>{c.format}</CardDescription>
              </div>
              <Badge variant="success">
                <BadgeCheck className="mr-1 h-3.5 w-3.5" /> verified
              </Badge>
            </CardHeader>
            <CardContent>
              <dl className="divide-y">
                {Object.entries(c.claims).map(([k, v]) => (
                  <div key={k} className="flex items-start justify-between gap-4 py-2">
                    <dt className="text-sm text-muted-foreground">{k}</dt>
                    <dd className="max-w-[60%] break-words text-right text-sm font-medium">{renderClaim(v)}</dd>
                  </div>
                ))}
              </dl>
            </CardContent>
          </Card>
        ))}

      <Button variant="outline" onClick={onBack}>
        <ArrowLeft className="h-4 w-4" /> 새 검증 시작
      </Button>
    </div>
  );
}

function renderClaim(v: unknown): string {
  if (v === true) return '✓ true';
  if (v === false) return '✗ false';
  if (Array.isArray(v) || (v !== null && typeof v === 'object')) return JSON.stringify(v);
  return String(v);
}

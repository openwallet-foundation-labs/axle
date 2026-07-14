# EUDI Verifier — frontend (Relying Party UI)

The Relying Party UI for OpenID4VP. Lets a user build a presentation request (choose **PID** or **mDL**,
**QR** vs the browser **Digital Credentials API**, **direct** vs **intermediary** RP), then either renders the
QR / `openid4vp://` deep link or invokes `navigator.credentials.get`. It polls the verifier backend for the
verified result and displays the disclosed claims and trust status.

Vite 5 + React 18 + TypeScript + Tailwind + shadcn/ui + `qrcode.react`.

## Config

`VITE_VERIFIER_BE_URL` — the verifier backend base URL (OpenID4VP endpoints under this path). The FE calls
`${VITE_VERIFIER_BE_URL}/presentations`, `/presentations/exchange`, `/presentations/:id`, and
`/presentations/:id/dc-api-response`. Defaults to `https://dev.api.hopae.com/trp` (the deployed `trp` verifier).

## Run

```bash
pnpm install
pnpm dev        # http://localhost:5176
pnpm build      # tsc -b && vite build → dist/ (deploy on Vercel; vercel.json rewrites all routes to index.html)
```

Live demo: https://eudi-verifier.vercel.app/ (this frontend, pointed at the dev verifier backend).
Pairs with the verifier backend — see [`../verifier-be/README.md`](../verifier-be/README.md).

# oddsportal-proxy

Minimal authenticated forward proxy (HTTP + CONNECT) that only allows
`oddsportal.com`. Deploy in Singapore so browsing OddsPortal exits via a
Singapore IP, which shows the most bookmakers (US IPs see very few).

## Env vars

- `PROXY_USER` / `PROXY_PASS` — proxy credentials (required)
- `PORT` — listen port (Render sets this)

## Health check

`GET /health` → `200 ok` (no auth required)

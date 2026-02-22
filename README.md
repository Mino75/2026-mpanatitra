# mpanatitra-proxy 🔁

Mpanatitra or Carrier in Malagasy is A minimal HTTP forward proxy built on Express. It sits between a client (browser or service) and an internal service, handling authentication, CORS, and request forwarding.

---

## What it does 📋

- Receives incoming HTTP requests (typically behind reverse proxy)
- Validates an API key before forwarding the request
- Optionally checks the source domain of the caller
- Handles CORS headers and OPTIONS preflight requests (for browser `fetch()` calls)
- Forwards requests to an internal service (`TARGET_BASE_URL`), injecting Basic Auth on the way out

---

## Environment variables ⚙️

### Required

| Variable | Description |
|---|---|
| `TARGET_BASE_URL` | Internal URL of the target service, e.g. `http://myservice:8080` |
| `BASIC_AUTH_USER` | Basic Auth username injected toward upstream |
| `BASIC_AUTH_PASS` | Basic Auth password injected toward upstream |
| `AUTHORIZED_API_KEYS` | Comma-separated list of allowed API keys |

### Optional

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Server listening port |
| `TRUST_PROXY` | `true` | Trust proxy headers (e.g. `X-Forwarded-For`) |
| `ENFORCE_SITE_ALLOWLIST` | `false` | Enable source domain verification |
| `AUTHORIZED_SITES` | — | Allowed domains when allowlist is enabled, e.g. `example.com,*.mysite.com` |
| `SOURCE_DOMAIN_HEADER` | `x-source-domain` | Header used to read the source domain |
| `API_KEY_HEADER` | `x-api-key` | Header used to read the API key |
| `ALLOW_API_KEY_IN_QUERY` | `false` | Accept the API key as a query param (`?api_key=...`) |
| `API_KEY_QUERY_PARAM` | `api_key` | Query param name if the above is enabled |
| `MAX_BODY_BYTES` | `10485760` (10 MB) | Maximum accepted request body size |
| `UPSTREAM_TIMEOUT_MS` | `15000` | Upstream request timeout in ms |
| `SERVER_TIMEOUT_MS` | `16000` | Global server timeout in ms |
| `UPSTREAM_MAX_SOCKETS` | `100` | Max keep-alive sockets toward upstream |
| `FORWARD_CLIENT_IP` | `true` | Forward client IP via `X-Forwarded-For` |
| `CORS_ENABLED` | `true` | Enable CORS headers |
| `CORS_ALLOW_ORIGINS` | `*` | Allowed CORS origins (CSV or `*`) |
| `CORS_ALLOW_CREDENTIALS` | `false` | Allow CORS credentials |
| `CORS_MAX_AGE_SECONDS` | `600` | Preflight cache duration in seconds |
| `LOG_STARTUP` | `true` | Log config on startup |
| `LOG_REQUESTS` | `false` | Log each incoming request and upstream errors |

---

## Getting started 🚀

### With Docker

```bash
docker build -t mpanatitra-proxy .

docker run -p 3000:3000 \
  -e TARGET_BASE_URL=http://myservice:8080 \
  -e BASIC_AUTH_USER=user \
  -e BASIC_AUTH_PASS=secret \
  -e AUTHORIZED_API_KEYS=key1,key2 \
  mpanatitra-proxy
```

### Locally (Node.js ≥ 20)

```bash
npm install

TARGET_BASE_URL=http://localhost:9000 \
BASIC_AUTH_USER=user \
BASIC_AUTH_PASS=secret \
AUTHORIZED_API_KEYS=myapikey \
node server.js
```

---

## Endpoints 🛤️

| Route | Description |
|---|---|
| `GET /healthz` | Health check — returns `ok` with a 200, no authentication required |
| `* *` | All other routes are proxied to the upstream |

---

## Security 🔒

- API keys are compared using **timing-safe equality** to prevent timing attacks.
- Upstream Basic Auth is injected server-side — the caller never sees it.
- Sensitive inbound headers (including the incoming `Authorization`) are stripped before forwarding.
- Source domain verification (`ENFORCE_SITE_ALLOWLIST`) is **not a strong security boundary**: `Origin` and `Referer` headers can be spoofed by clients. Use it as an additional layer, not as a replacement for API key auth.

---

## Dependencies 📦

- [`express`](https://expressjs.com/) — the only npm dependency. Everything else uses Node.js built-ins (`http`, `crypto`, `url`).

---

## License 📄

MIT — see [LICENSE](./LICENSE).

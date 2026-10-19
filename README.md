# VEDA — Subscription Converter MVP

A small, runnable MVP for a VEDA-branded subscription converter with a dark black + lime-green interface.

## What works in this MVP

- Paste subscription content or provide an HTTPS subscription URL.
- Safely fetch a public subscription URL (basic SSRF protections, redirects revalidated, response size capped).
- Decode Base64 subscription content when possible.
- Output the subscription as `Original`, `Base64`, or a normalized `Links` list.
- Generate a VEDA endpoint URL for a source subscription (URL builder only; it does not create a permanent public proxy endpoint).
- Copy output to clipboard.
- Responsive single-page interface.

## Important scope limits

This first MVP does **not** claim full Xray JSON, Sing-box JSON, or Clash/Mihomo YAML conversion. Those require format-specific parsers and test fixtures. The current `Links` output extracts common URI schemes (`vless`, `vmess`, `trojan`, `ss`, `ssr`, `hy2`, `hysteria2`, `tuic`, `anytls`) from decoded text.

The VEDA URL builder creates a URL to the app's `/api/convert` endpoint with a source URL parameter. It is a prototype URL, not a persistent subscription proxy URL. Do not deploy this publicly as-is without further security review, abuse controls, logging/privacy review, and infrastructure-level egress restrictions.

## Run locally

Python 3.10+ recommended.

```bash
python -m venv .venv
# Windows:
.venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000

## API

- `GET /api/health` — health check.
- `POST /api/convert` — accepts JSON:
  - `content`: raw subscription text (optional)
  - `url`: HTTPS URL to fetch (optional)
  - `format`: `original`, `base64`, or `links`
  - `user_agent`: optional user-agent for upstream request
  - `os`: optional label retained for future extension
  - `hwid`: optional label retained for future extension

Example:

```bash
curl -X POST http://127.0.0.1:8000/api/convert \
  -H "Content-Type: application/json" \
  -d '{"content":"vless://example@vpn.example:443?security=tls#Demo","format":"links"}'
```

## Security notes

- Only HTTP(S) source URLs are accepted; HTTPS is recommended.
- Private, loopback, link-local, multicast, reserved, and unspecified IP addresses are blocked.
- Redirects are followed manually and revalidated.
- DNS resolution is checked before requests, but production deployment should additionally enforce outbound network restrictions at the infrastructure level to mitigate DNS rebinding and related SSRF risks.
- Responses have timeouts and a size cap.
- Do not log source URLs or subscription contents: they may contain credentials.

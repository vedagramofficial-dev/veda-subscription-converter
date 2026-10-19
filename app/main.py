from __future__ import annotations

import base64
import ipaddress
import socket
from typing import Literal
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

app = FastAPI(title="VEDA Subscription Converter", version="0.1.0")

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_CONTENT_CHARS = 2 * 1024 * 1024
ALLOWED_SCHEMES = {
    "vless", "vmess", "trojan", "ss", "ssr",
    "hy2", "hysteria2", "tuic", "anytls"
}


class ConvertRequest(BaseModel):
    content: str | None = Field(default=None, max_length=MAX_CONTENT_CHARS)
    url: str | None = Field(default=None, max_length=2048)
    format: Literal["original", "base64", "links"] = "original"
    user_agent: str = Field(default="VEDA-Subscription-Converter/0.1", max_length=256)
    os: str | None = Field(default=None, max_length=64)
    hwid: str | None = Field(default=None, max_length=256)

    @field_validator("url")
    @classmethod
    def validate_url_shape(cls, value):
        if value is None or value.strip() == "":
            return None
        parsed = urlparse(value.strip())
        if parsed.scheme not in ("https", "http") or not parsed.hostname:
            raise ValueError("URL must be a valid HTTP or HTTPS URL.")
        if parsed.username or parsed.password:
            raise ValueError("URLs containing embedded credentials are not accepted.")
        return value.strip()


def _public_ip(host: str) -> bool:
    """Resolve host and reject any non-public result."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            return False
    return True


def _validate_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise HTTPException(status_code=400, detail="Only HTTP(S) URLs are supported.")
    host = parsed.hostname.lower()
    if host in ("localhost",) or host.endswith(".localhost") or host.endswith(".local"):
        raise HTTPException(status_code=400, detail="Local hostnames are not allowed.")
    if not _public_ip(host):
        raise HTTPException(status_code=400, detail="The source host must resolve only to public IP addresses.")


async def _fetch_public_text(start_url: str, user_agent: str) -> str:
    current_url = start_url
    headers = {"User-Agent": user_agent, "Accept": "text/plain, */*"}
    timeout = httpx.Timeout(8.0, connect=4.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        for redirect_count in range(4):
            _validate_public_url(current_url)
            try:
                async with client.stream("GET", current_url, headers=headers) as response:
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location")
                        if not location:
                            raise HTTPException(status_code=502, detail="Upstream redirect had no Location header.")
                        if redirect_count >= 3:
                            raise HTTPException(status_code=502, detail="Too many upstream redirects.")
                        current_url = str(response.url.join(location))
                        continue
                    if response.status_code >= 400:
                        raise HTTPException(status_code=502, detail=f"Upstream returned HTTP {response.status_code}.")
                    content_length = response.headers.get("content-length")
                    if content_length and content_length.isdigit() and int(content_length) > MAX_RESPONSE_BYTES:
                        raise HTTPException(status_code=413, detail="Upstream response is too large.")
                    chunks = []
                    total = 0
                    async for chunk in response.aiter_bytes():
                        total += len(chunk)
                        if total > MAX_RESPONSE_BYTES:
                            raise HTTPException(status_code=413, detail="Upstream response is too large.")
                        chunks.append(chunk)
                    raw = b"".join(chunks)
                    return raw.decode(response.encoding or "utf-8", errors="replace")
            except HTTPException:
                raise
            except httpx.TimeoutException:
                raise HTTPException(status_code=504, detail="Upstream request timed out.")
            except httpx.HTTPError:
                raise HTTPException(status_code=502, detail="Could not fetch the source subscription.")
    raise HTTPException(status_code=502, detail="Could not fetch the source subscription.")


def _decode_subscription(text: str) -> str:
    cleaned = text.strip()
    if not cleaned:
        return ""
    # If it already resembles URI links or JSON/YAML, keep it as-is.
    if "://" in cleaned or cleaned.startswith(("{", "[", "proxies:", "mixed-port:")):
        return cleaned
    compact = "".join(cleaned.split())
    try:
        padded = compact + ("=" * (-len(compact) % 4))
        decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="strict").strip()
        if decoded and ("://" in decoded or decoded.startswith(("{", "[", "proxies:", "mixed-port:"))):
            return decoded
    except (ValueError, UnicodeDecodeError):
        pass
    return cleaned


def _extract_links(text: str) -> list[str]:
    results = []
    seen = set()
    for line in text.splitlines():
        candidate = line.strip().strip('"').strip("'")
        if "://" not in candidate:
            continue
        scheme = candidate.split("://", 1)[0].lower()
        if scheme in ALLOWED_SCHEMES and candidate not in seen:
            results.append(candidate)
            seen.add(candidate)
    return results


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "veda-subscription-converter", "version": "0.1.0"}


@app.post("/api/convert")
async def convert(req: ConvertRequest):
    if bool(req.content and req.url):
        raise HTTPException(status_code=400, detail="Provide either content or URL, not both.")
    if not req.content and not req.url:
        raise HTTPException(status_code=400, detail="Paste subscription content or provide a source URL.")

    source_text = req.content
    if req.url:
        source_text = await _fetch_public_text(req.url, req.user_agent)

    normalized = _decode_subscription(source_text or "")
    if req.format == "original":
        output = normalized
    elif req.format == "base64":
        output = base64.b64encode(normalized.encode("utf-8")).decode("ascii")
    else:
        links = _extract_links(normalized)
        output = "\n".join(links)
        if not output:
            raise HTTPException(status_code=422, detail="No supported proxy URI links were found in the content.")

    return {
        "format": req.format,
        "output": output,
        "items": len(_extract_links(normalized)),
        "source": "url" if req.url else "content",
        "note": "VEDA MVP supports Original, Base64, and extracting common proxy URI links."
    }


@app.get("/")
async def index():
    return FileResponse("app/static/index.html")


app.mount("/static", StaticFiles(directory="app/static"), name="static")

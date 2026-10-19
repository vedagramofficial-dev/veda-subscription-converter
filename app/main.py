from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import socket
from urllib.parse import urlparse

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

app = FastAPI(title="VEDA Subscription Converter", version="0.2.0")

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_CONTENT_CHARS = 2 * 1024 * 1024

ALLOWED_SCHEMES = {
    "vless", "vmess", "trojan", "ss", "ssr",
    "hy2", "hysteria2", "tuic", "anytls"
}

UA_PRESETS = {
    "default": "VEDA-Subscription-Converter/0.2",
    "happ": "happ",
    "v2": "v2",
    "incy": "incy",
    "web": "Mozilla/5.0",
}

OUTPUT_FORMATS = {
    "passthrough", "url", "b64", "jsonX", "jsonS", "yaml",
    "original", "base64", "links"
}


class ConvertRequest(BaseModel):
    content: str | None = Field(default=None, max_length=MAX_CONTENT_CHARS)
    url: str | None = Field(default=None, max_length=2048)
    format: str = "passthrough"
    user_agent: str = Field(default="VEDA-Subscription-Converter/0.2", max_length=256)
    os: str | None = Field(default=None, max_length=64)
    hwid: str | None = Field(default=None, max_length=256)

    @field_validator("url")
    @classmethod
    def validate_url_shape(cls, value):
        if not value or not value.strip():
            return None
        parsed = urlparse(value.strip())
        if parsed.scheme not in ("https", "http") or not parsed.hostname:
            raise ValueError("URL must be HTTP or HTTPS.")
        if parsed.username or parsed.password:
            raise ValueError("Embedded URL credentials are not accepted.")
        return value.strip()

    @field_validator("format")
    @classmethod
    def validate_format(cls, value):
        if value not in OUTPUT_FORMATS:
            raise ValueError("Unsupported output format.")
        return value


def _public_ip(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return bool(infos) and all(
            ipaddress.ip_address(info[4][0].split("%")[0]).is_global
            for info in infos
        )
    except (socket.gaierror, OSError, ValueError):
        return False


def _validate_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(400, "Only HTTP(S) URLs are supported.")

    host = parsed.hostname.lower()
    if host == "localhost" or host.endswith((".localhost", ".local")):
        raise HTTPException(400, "Local hostnames are not allowed.")
    if not _public_ip(host):
        raise HTTPException(400, "Source host must resolve to public IP addresses.")


async def _fetch_public_text(url: str, user_agent: str) -> str:
    current_url = url
    headers = {"User-Agent": user_agent, "Accept": "text/plain, */*"}
    timeout = httpx.Timeout(8.0, connect=4.0)

    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, trust_env=False
    ) as client:
        for redirect_count in range(4):
            _validate_public_url(current_url)
            try:
                async with client.stream("GET", current_url, headers=headers) as r:
                    if r.status_code in (301, 302, 303, 307, 308):
                        location = r.headers.get("location")
                        if not location or redirect_count >= 3:
                            raise HTTPException(502, "Too many or invalid redirects.")
                        current_url = str(r.url.join(location))
                        continue

                    if r.status_code >= 400:
                        raise HTTPException(502, f"Upstream HTTP {r.status_code}.")

                    length = r.headers.get("content-length")
                    if length and length.isdigit() and int(length) > MAX_RESPONSE_BYTES:
                        raise HTTPException(413, "Upstream response is too large.")

                    chunks, total = [], 0
                    async for chunk in r.aiter_bytes():
                        total += len(chunk)
                        if total > MAX_RESPONSE_BYTES:
                            raise HTTPException(413, "Upstream response is too large.")
                        chunks.append(chunk)

                    return b"".join(chunks).decode(
                        r.encoding or "utf-8", errors="replace"
                    )
            except HTTPException:
                raise
            except httpx.TimeoutException:
                raise HTTPException(504, "Upstream request timed out.")
            except httpx.HTTPError:
                raise HTTPException(502, "Could not fetch the source subscription.")

    raise HTTPException(502, "Could not fetch the source subscription.")


def _decode_subscription(text: str) -> str:
    cleaned = text.strip()
    if not cleaned:
        return ""
    if "://" in cleaned or cleaned.startswith(("{", "[", "proxies:", "mixed-port:")):
        return cleaned

    compact = "".join(cleaned.split())
    try:
        decoded = base64.b64decode(
            compact + "=" * (-len(compact) % 4), validate=True
        ).decode("utf-8").strip()
        if decoded and (
            "://" in decoded or decoded.startswith(("{", "[", "proxies:", "mixed-port:"))
        ):
            return decoded
    except (ValueError, UnicodeDecodeError, binascii.Error):
        pass
    return cleaned


def _extract_links(text: str) -> list[str]:
    result, seen = [], set()
    for line in text.splitlines():
        candidate = line.strip().strip('"').strip("'")
        if "://" not in candidate:
            continue
        scheme = candidate.split("://", 1)[0].lower()
        if scheme in ALLOWED_SCHEMES and candidate not in seen:
            result.append(candidate)
            seen.add(candidate)
    return result


def _convert_output(text: str, fmt: str) -> str:
    normalized = _decode_subscription(text)

    if fmt in ("passthrough", "original"):
        return text
    if fmt in ("b64", "base64"):
        return base64.b64encode(normalized.encode()).decode("ascii")
    if fmt in ("url", "links"):
        links = _extract_links(normalized)
        if not links:
            raise HTTPException(422, "No supported proxy URI links found.")
        return "\n".join(links)

    try:
        data = json.loads(normalized) if normalized.lstrip().startswith(("{", "[")) else None
    except json.JSONDecodeError:
        data = None

    if fmt == "jsonX":
        if not isinstance(data, dict) or not isinstance(data.get("outbounds"), list):
            raise HTTPException(
                422, "jsonX requires an existing Xray JSON configuration."
            )
        return json.dumps(data, ensure_ascii=False, indent=2)

    if fmt == "jsonS":
        if not isinstance(data, dict) or not isinstance(data.get("outbounds"), list):
            raise HTTPException(
                422, "jsonS requires an existing Sing-box JSON configuration."
            )
        return json.dumps(data, ensure_ascii=False, indent=2)

    if fmt == "yaml":
        try:
            parsed = yaml.safe_load(normalized)
        except yaml.YAMLError:
            raise HTTPException(422, "Input is not valid YAML.")
        if not isinstance(parsed, dict) or not (
            "proxies" in parsed or "proxy-providers" in parsed
        ):
            raise HTTPException(
                422, "yaml requires a Clash/Mihomo-compatible YAML configuration."
            )
        return yaml.safe_dump(parsed, allow_unicode=True, sort_keys=False)

    raise HTTPException(400, "Unsupported format.")


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "veda-subscription-converter", "version": "0.2.0"}


@app.post("/api/convert")
async def convert(req: ConvertRequest):
    if bool(req.content) == bool(req.url):
        raise HTTPException(400, "Provide either content or URL, not both.")

    source = req.content
    if req.url:
        source = await _fetch_public_text(req.url, req.user_agent)

    output = _convert_output(source or "", req.format)
    return {
        "format": req.format,
        "output": output,
        "items": len(_extract_links(_decode_subscription(source or ""))),
        "source": "url" if req.url else "content"
    }


@app.get("/sub", response_class=PlainTextResponse)
async def subscription_link(
    url: str = Query(..., min_length=8, max_length=2048),
    ua: str = Query(default="default"),
    format: str = Query(default="passthrough"),
    os: str | None = Query(default=None, max_length=64),
    hwid: str | None = Query(default=None, max_length=256),
):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(400, "Нужна корректная HTTP или HTTPS ссылка.")
    if parsed.username or parsed.password:
        raise HTTPException(400, "Ссылки со встроенными паролями не поддерживаются.")
    if ua not in UA_PRESETS:
        raise HTTPException(400, "Неизвестный шаблон UA.")
    if ua == "web" and not os:
        raise HTTPException(400, "Для шаблона web необходимо указать os.")
    if os and os.lower() not in {"android", "ios", "windows", "macos", "linux"}:
        raise HTTPException(400, "Неизвестное значение OS.")
    if format not in OUTPUT_FORMATS:
        raise HTTPException(400, "Неизвестный формат ответа.")

    # Note: UA presets are placeholders until exact provider values are confirmed.
    content = await _fetch_public_text(url, UA_PRESETS[ua])
    output = _convert_output(content, format)

    return PlainTextResponse(
        output,
        headers={"Cache-Control": "no-store"}
    )


@app.get("/")
async def index():
    return FileResponse("app/static/index.html")


app.mount("/static", StaticFiles(directory="app/static"), name="static")

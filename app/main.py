from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import socket
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

app = FastAPI(title="VEDA Subscription Converter", version="0.2.1")

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

# Statistics are stored beside this file. For persistent production statistics,
# use a database or persistent volume if the hosting platform has ephemeral disks.
STATS_FILE = Path(__file__).with_name("stats.json")
STATS_LOCK = Lock()


def _read_stats() -> dict:
    try:
        data = json.loads(STATS_FILE.read_text(encoding="utf-8"))
        return {
            "visitors": max(0, int(data.get("visitors", 0))),
            "conversions": max(0, int(data.get("conversions", 0))),
        }
    except (OSError, ValueError, TypeError, AttributeError):
        return {"visitors": 0, "conversions": 0}


def _write_stats(data: dict) -> None:
    temp_file = STATS_FILE.with_suffix(".tmp")
    temp_file.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temp_file.replace(STATS_FILE)


def _increment_stat(key: str) -> dict:
    with STATS_LOCK:
        stats = _read_stats()
        stats[key] += 1
        _write_stats(stats)
        return stats


class ConvertRequest(BaseModel):
    content: str | None = Field(default=None, max_length=MAX_CONTENT_CHARS)
    url: str | None = Field(default=None, max_length=2048)
    format: str = "passthrough"
    user_agent: str = Field(
        default="VEDA-Subscription-Converter/0.2",
        max_length=256
    )
    os: str | None = Field(default=None, max_length=64)
    hwid: str | None = Field(default=None, max_length=256)

    @field_validator("url")
    @classmethod
    def validate_url_shape(cls, value):
        if value is None or not value.strip():
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
        raise HTTPException(
            status_code=400,
            detail="Only HTTP(S) URLs are supported."
        )
    host = parsed.hostname.lower()
    if host == "localhost" or host.endswith((".localhost", ".local")):
        raise HTTPException(
            status_code=400,
            detail="Local hostnames are not allowed."
        )
    if not _public_ip(host):
        raise HTTPException(
            status_code=400,
            detail="Source host must resolve to public IP addresses."
        )


async def _fetch_public_text(url: str, user_agent: str) -> str:
    current_url = url
    headers = {"User-Agent": user_agent, "Accept": "text/plain, */*"}
    timeout = httpx.Timeout(8.0, connect=4.0)

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False
    ) as client:
        for redirect_count in range(4):
            _validate_public_url(current_url)
            try:
                async with client.stream("GET", current_url, headers=headers) as response:
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location")
                        if not location or redirect_count >= 3:
                            raise HTTPException(
                                status_code=502,
                                detail="Too many or invalid redirects."
                            )
                        current_url = str(response.url.join(location))
                        continue

                    if response.status_code >= 400:
                        raise HTTPException(
                            status_code=502,
                            detail=f"Upstream HTTP {response.status_code}."
                        )

                    length = response.headers.get("content-length")
                    if length and length.isdigit() and int(length) > MAX_RESPONSE_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail="Upstream response is too large."
                        )

                    chunks = []
                    total = 0
                    async for chunk in response.aiter_bytes():
                        total += len(chunk)
                        if total > MAX_RESPONSE_BYTES:
                            raise HTTPException(
                                status_code=413,
                                detail="Upstream response is too large."
                            )
                        chunks.append(chunk)

                    return b"".join(chunks).decode(
                        response.encoding or "utf-8",
                        errors="replace"
                    )
            except HTTPException:
                raise
            except httpx.TimeoutException:
                raise HTTPException(
                    status_code=504,
                    detail="Upstream request timed out."
                )
            except httpx.HTTPError:
                raise HTTPException(
                    status_code=502,
                    detail="Could not fetch the source subscription."
                )

    raise HTTPException(
        status_code=502,
        detail="Could not fetch the source subscription."
    )


def _decode_subscription(text: str) -> str:
    cleaned = text.strip()
    if not cleaned:
        return ""
    if "://" in cleaned or cleaned.startswith(("{", "[", "proxies:", "mixed-port:")):
        return cleaned

    compact = "".join(cleaned.split())
    try:
        padded = compact + "=" * (-len(compact) % 4)
        decoded = base64.b64decode(padded, validate=True).decode("utf-8").strip()
        if decoded and (
            "://" in decoded
            or decoded.startswith(("{", "[", "proxies:", "mixed-port:"))
        ):
            return decoded
    except (ValueError, UnicodeDecodeError, binascii.Error):
        pass
    return cleaned


def _extract_links(text: str) -> list[str]:
    result = []
    seen = set()
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
        return base64.b64encode(normalized.encode("utf-8")).decode("ascii")
    if fmt in ("url", "links"):
        links = _extract_links(normalized)
        if not links:
            raise HTTPException(
                status_code=422,
                detail="No supported proxy URI links found."
            )
        return "\n".join(links)

    try:
        data = (
            json.loads(normalized)
            if normalized.lstrip().startswith(("{", "["))
            else None
        )
    except json.JSONDecodeError:
        data = None

    if fmt in ("jsonX", "jsonS"):
        if not isinstance(data, dict) or not isinstance(data.get("outbounds"), list):
            label = "Xray" if fmt == "jsonX" else "Sing-box"
            raise HTTPException(
                status_code=422,
                detail=f"{fmt} requires an existing {label} JSON configuration."
            )
        return json.dumps(data, ensure_ascii=False, indent=2)

    if fmt == "yaml":
        try:
            parsed = yaml.safe_load(normalized)
        except yaml.YAMLError:
            raise HTTPException(status_code=422, detail="Input is not valid YAML.")
        if not isinstance(parsed, dict) or not (
            "proxies" in parsed or "proxy-providers" in parsed
        ):
            raise HTTPException(
                status_code=422,
                detail="yaml requires a Clash/Mihomo-compatible YAML configuration."
            )
        return yaml.safe_dump(parsed, allow_unicode=True, sort_keys=False)

    raise HTTPException(status_code=400, detail="Unsupported format.")


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "veda-subscription-converter",
        "version": "0.2.1"
    }


@app.get("/api/stats")
async def get_stats():
    with STATS_LOCK:
        return _read_stats()


@app.post("/api/stats/visit")
async def count_visit():
    return _increment_stat("visitors")


@app.post("/api/stats/conversion")
async def count_conversion():
    return _increment_stat("conversions")


@app.post("/api/convert")
async def convert(req: ConvertRequest):
    if bool(req.content) == bool(req.url):
        raise HTTPException(
            status_code=400,
            detail="Provide either content or URL, not both."
        )

    source = req.content
    if req.url:
        source = await _fetch_public_text(req.url, req.user_agent)

    output = _convert_output(source or "", req.format)
    result = {
        "format": req.format,
        "output": output,
        "items": len(_extract_links(_decode_subscription(source or ""))),
        "source": "url" if req.url else "content"
    }
    _increment_stat("conversions")
    return result


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
        raise HTTPException(status_code=400, detail="Нужна корректная HTTP или HTTPS ссылка.")
    if parsed.username or parsed.password:
        raise HTTPException(
            status_code=400,
            detail="Ссылки со встроенными паролями не поддерживаются."
        )
    if ua not in UA_PRESETS:
        raise HTTPException(status_code=400, detail="Неизвестный шаблон UA.")
    if ua == "web" and not os:
        raise HTTPException(
            status_code=400,
            detail="Для шаблона web необходимо указать os."
        )
    if os and os.lower() not in {"android", "ios", "windows", "macos", "linux"}:
        raise HTTPException(status_code=400, detail="Неизвестное значение OS.")
    if format not in OUTPUT_FORMATS:
        raise HTTPException(status_code=400, detail="Неизвестный формат ответа.")

    content = await _fetch_public_text(url, UA_PRESETS[ua])
    output = _convert_output(content, format)
    _increment_stat("conversions")
    return PlainTextResponse(output, headers={"Cache-Control": "no-store"})


STATIC_DIR = Path(__file__).parent / "static"


@app.get("/")
async def index():
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=500, detail="app/static/index.html was not found.")
    return FileResponse(index_file)


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

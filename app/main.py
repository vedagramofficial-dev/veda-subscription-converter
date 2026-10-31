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

APP_VERSION = "2.0.0"
app = FastAPI(
    title="VEDA Subscription Converter",
    version=APP_VERSION,
    description="VEDA subscription link checker and format helper",
)

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_CONTENT_CHARS = 2 * 1024 * 1024
ALLOWED_SCHEMES = {
    "vless", "vmess", "trojan", "ss", "ssr",
    "hy2", "hysteria2", "tuic", "anytls",
}
UA_PRESETS = {
    "default": "VEDA-Subscription-Converter/2.0",
    "happ": "happ",
    "v2": "v2",
    "incy": "incy",
    "web": "Mozilla/5.0",
}
ALLOWED_OS = {"android", "ios", "windows", "macos", "linux"}
OUTPUT_FORMATS = {"original", "links", "base64", "yaml"}

STATS_FILE = Path(__file__).with_name("stats.json")
STATS_LOCK = Lock()


class ConvertRequest(BaseModel):
    content: str | None = Field(default=None, max_length=MAX_CONTENT_CHARS)
    url: str | None = Field(default=None, max_length=2048)
    format: str = "original"
    user_agent: str = Field(default=UA_PRESETS["default"], max_length=256)
    os: str | None = Field(default=None, max_length=32)

    @field_validator("url")
    @classmethod
    def validate_url_shape(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("URL must be HTTP or HTTPS.")
        if parsed.username or parsed.password:
            raise ValueError("Embedded URL credentials are not accepted.")
        return value

    @field_validator("format")
    @classmethod
    def validate_format(cls, value: str) -> str:
        if value not in OUTPUT_FORMATS:
            raise ValueError("Unsupported output format.")
        return value


def _read_stats() -> dict:
    try:
        raw = json.loads(STATS_FILE.read_text(encoding="utf-8"))
        return {
            "visitors": max(0, int(raw.get("visitors", 0))),
            "conversions": max(0, int(raw.get("conversions", 0))),
        }
    except (OSError, ValueError, TypeError, AttributeError):
        return {"visitors": 0, "conversions": 0}


def _write_stats(stats: dict) -> None:
    STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATS_FILE.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(stats, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary.replace(STATS_FILE)


def _increment_stat(key: str) -> dict:
    with STATS_LOCK:
        stats = _read_stats()
        stats[key] += 1
        _write_stats(stats)
        return stats


def _is_public_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        return ip.is_global
    except ValueError:
        return False


def _validate_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(400, "Only HTTP(S) source URLs are supported.")

    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith((".localhost", ".local")):
        raise HTTPException(400, "Local hostnames are not allowed.")

    try:
        records = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except (socket.gaierror, OSError, ValueError):
        raise HTTPException(400, "Source hostname could not be resolved.")

    addresses = {record[4][0] for record in records}
    if not addresses or not all(
        _is_public_address(address) for address in addresses
    ):
        raise HTTPException(
            400,
            "Source host must resolve only to public IP addresses.",
        )


async def _fetch_public_text(url: str, user_agent: str) -> str:
    current_url = url
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/plain, */*",
    }
    timeout = httpx.Timeout(10.0, connect=5.0)

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        for redirect_number in range(4):
            _validate_public_url(current_url)

            try:
                async with client.stream(
                    "GET",
                    current_url,
                    headers=headers,
                ) as response:

                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location")

                        if not location or redirect_number == 3:
                            raise HTTPException(
                                502,
                                "Too many or invalid redirects.",
                            )

                        current_url = str(response.url.join(location))
                        continue

                    if response.status_code >= 400:
                        raise HTTPException(
                            502,
                            f"Source server returned HTTP {response.status_code}.",
                        )

                    content_length = response.headers.get("content-length")

                    if content_length and content_length.isdigit():
                        if int(content_length) > MAX_RESPONSE_BYTES:
                            raise HTTPException(
                                413,
                                "Source response is too large.",
                            )

                    chunks: list[bytes] = []
                    total = 0

                    async for chunk in response.aiter_bytes():
                        total += len(chunk)

                        if total > MAX_RESPONSE_BYTES:
                            raise HTTPException(
                                413,
                                "Source response is too large.",
                            )

                        chunks.append(chunk)

                    try:
                        return b"".join(chunks).decode(
                            response.encoding or "utf-8",
                            errors="replace",
                        )
                    except LookupError:
                        return b"".join(chunks).decode(
                            "utf-8",
                            errors="replace",
                        )

            except HTTPException:
                raise
            except httpx.TimeoutException:
                raise HTTPException(504, "Source server timed out.")
            except httpx.HTTPError:
                raise HTTPException(
                    502,
                    "Could not download the source subscription.",
                )

    raise HTTPException(
        502,
        "Could not download the source subscription.",
    )


def _decode_subscription(text: str) -> str:
    cleaned = text.strip()

    if not cleaned:
        return ""

    if "://" in cleaned or cleaned.startswith(
        ("{", "[", "proxies:", "mixed-port:")
    ):
        return cleaned

    compact = "".join(cleaned.split())

    try:
        padded = compact + "=" * (-len(compact) % 4)

        decoded = base64.b64decode(
            padded,
            validate=True,
        ).decode("utf-8").strip()

        if decoded and (
            "://" in decoded
            or decoded.startswith(
                ("{", "[", "proxies:", "mixed-port:")
            )
        ):
            return decoded

    except (ValueError, UnicodeDecodeError, binascii.Error):
        pass

    return cleaned


def _extract_links(text: str) -> list[str]:
    links: list[str] = []
    seen: set[str] = set()

    for line in text.splitlines():
        candidate = line.strip().strip('"').strip("'")

        if "://" not in candidate:
            continue

        scheme = candidate.split("://", 1)[0].lower()

        if scheme in ALLOWED_SCHEMES and candidate not in seen:
            seen.add(candidate)
            links.append(candidate)

    return links


def _convert_output(text: str, output_format: str) -> str:
    normalized = _decode_subscription(text)

    if not normalized:
        raise HTTPException(
            422,
            "The source subscription is empty.",
        )

    if output_format == "original":
        return text

    if output_format == "base64":
        return base64.b64encode(
            normalized.encode("utf-8")
        ).decode("ascii")

    if output_format == "links":
        links = _extract_links(normalized)

        if not links:
            raise HTTPException(
                422,
                "No supported proxy links were found in the subscription.",
            )

        return "\n".join(links)

    if output_format == "yaml":
        try:
            parsed = yaml.safe_load(normalized)
        except yaml.YAMLError:
            raise HTTPException(
                422,
                "The source is not valid YAML.",
            )

        if not isinstance(parsed, dict) or not (
            "proxies" in parsed or "proxy-providers" in parsed
        ):
            raise HTTPException(
                422,
                "YAML output is only available for an existing "
                "Clash/Mihomo configuration. "
                "This tool does not convert VLESS links into Clash YAML.",
            )

        return yaml.safe_dump(
            parsed,
            allow_unicode=True,
            sort_keys=False,
        )

    raise HTTPException(400, "Unsupported output format.")


def _resolve_user_agent(ua: str, os_name: str | None) -> str:
    if ua not in UA_PRESETS:
        raise HTTPException(400, "Unknown client preset.")

    if ua == "web":
        if not os_name:
            raise HTTPException(
                400,
                "Choose an operating system for the Web preset.",
            )

        if os_name.lower() not in ALLOWED_OS:
            raise HTTPException(400, "Unknown operating system.")

    return UA_PRESETS[ua]


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "veda-subscription-converter",
        "version": APP_VERSION,
    }


@app.get("/api/stats")
async def get_stats():
    with STATS_LOCK:
        return _read_stats()


@app.post("/api/stats/visit")
async def count_visit():
    return _increment_stat("visitors")


@app.post("/api/check")
async def check_subscription(req: ConvertRequest):
    if bool(req.content) == bool(req.url):
        raise HTTPException(
            400,
            "Provide exactly one source: URL or content.",
        )

    if req.url:
        source = await _fetch_public_text(
            req.url,
            req.user_agent,
        )
        source_type = "url"
    else:
        source = req.content or ""
        source_type = "content"

    output = _convert_output(source, req.format)
    normalized = _decode_subscription(source)

    return {
        "ok": True,
        "format": req.format,
        "output": output,
        "items": len(_extract_links(normalized)),
        "source": source_type,
        "message": "Subscription downloaded and checked successfully.",
    }


@app.post("/api/convert")
async def convert(req: ConvertRequest):
    result = await check_subscription(req)
    _increment_stat("conversions")
    return result


@app.get("/sub", response_class=PlainTextResponse)
async def subscription_link(
    url: str = Query(..., min_length=8, max_length=2048),
    ua: str = Query(default="default"),
    format: str = Query(default="original"),
    os: str | None = Query(default=None, max_length=32),
):
    user_agent = _resolve_user_agent(ua, os)

    if format not in OUTPUT_FORMATS:
        raise HTTPException(400, "Unknown output format.")

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(
            400,
            "A valid HTTP or HTTPS subscription URL is required.",
        )

    if parsed.username or parsed.password:
        raise HTTPException(
            400,
            "URLs containing embedded credentials are not supported.",
        )

    content = await _fetch_public_text(url, user_agent)
    output = _convert_output(content, format)

    _increment_stat("conversions")

    return PlainTextResponse(
        output,
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


STATIC_DIR = Path(__file__).parent / "static"


@app.get("/")
async def index():
    index_file = STATIC_DIR / "index.html"

    if not index_file.exists():
        raise HTTPException(
            500,
            "app/static/index.html was not found.",
        )

    return FileResponse(index_file)


if STATIC_DIR.exists():
    app.mount(
        "/static",
        StaticFiles(directory=STATIC_DIR),
        name="static",
    )

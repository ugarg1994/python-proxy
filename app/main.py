import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urljoin

import httpx
from fastapi import FastAPI, HTTPException, Request
from starlette.background import BackgroundTask
from fastapi.responses import JSONResponse, Response, StreamingResponse

from app.security_copilot import (
    build_security_copilot_manifest,
    build_security_copilot_openapi,
    resolve_public_base_url,
)


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}


app = FastAPI(title="Python Proxy Forwarder", version="0.1.0")


@dataclass(frozen=True)
class Settings:
    upstream_base_url: str | None
    ctix_access_id: str | None
    ctix_secret_key: str | None
    ctix_signature_ttl: int
    proxy_timeout: float


def _clean_base_url(raw_value: str | None) -> str | None:
    if not raw_value:
        return None
    return raw_value.rstrip("/") + "/"


def get_settings() -> Settings:
    return Settings(
        upstream_base_url=_clean_base_url(os.getenv("UPSTREAM_BASE_URL")),
        ctix_access_id=os.getenv("CTIX_ACCESS_ID"),
        ctix_secret_key=os.getenv("CTIX_SECRET_KEY"),
        ctix_signature_ttl=int(os.getenv("CTIX_SIGNATURE_TTL", "25")),
        proxy_timeout=float(os.getenv("PROXY_TIMEOUT", "60")),
    )


def _filter_request_headers(headers: Iterable[tuple[str, str]]) -> dict[str, str]:
    return {
        key: value
        for key, value in headers
        if key.lower() not in HOP_BY_HOP_HEADERS
    }


def _filter_response_headers(headers: httpx.Headers) -> dict[str, str]:
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }


def _build_ctix_signature(access_id: str, secret_key: str, expires: int) -> str:
    message = f"{access_id}\n{expires}".encode("utf-8")
    digest = hmac.new(secret_key.encode("utf-8"), message, hashlib.sha1).digest()
    return base64.b64encode(digest).decode("utf-8")


def _require_upstream_base_url(settings: Settings) -> str:
    if not settings.upstream_base_url:
        raise HTTPException(status_code=500, detail="UPSTREAM_BASE_URL is not configured")
    return settings.upstream_base_url


def _get_query_params(
    original_query: str,
    settings: Settings,
) -> httpx.QueryParams:
    params = httpx.QueryParams(original_query)
    if settings.ctix_access_id and settings.ctix_secret_key:
        expires = int(time.time()) + settings.ctix_signature_ttl
        signature = _build_ctix_signature(
            settings.ctix_access_id, settings.ctix_secret_key, expires
        )
        params = params.set("AccessID", settings.ctix_access_id)
        params = params.set("Signature", signature)
        params = params.set("Expires", str(expires))
    return params


async def _send_upstream(
    *,
    method: str,
    upstream_url: str,
    headers: dict[str, str],
    query_params: httpx.QueryParams,
    content: bytes | str | None,
    timeout_seconds: float,
) -> httpx.Response:
    timeout = httpx.Timeout(timeout_seconds)
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            return await client.send(
                client.build_request(
                    method=method,
                    url=upstream_url,
                    headers=headers,
                    params=query_params,
                    content=content,
                ),
                stream=True,
            )
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="Upstream request timed out") from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {exc}") from exc


@app.get("/health")
async def healthcheck() -> JSONResponse:
    settings = get_settings()
    return JSONResponse(
        {
            "status": "ok",
            "upstream_base_url": settings.upstream_base_url,
            "ctix_signing_enabled": bool(
                settings.ctix_access_id and settings.ctix_secret_key
            ),
            "proxy_mode": "method-preserving path-forwarder",
        }
    )


@app.get("/security-copilot/openapi.json")
async def security_copilot_openapi(request: Request) -> JSONResponse:
    public_base_url = resolve_public_base_url(str(request.base_url).rstrip("/"))
    return JSONResponse(build_security_copilot_openapi(public_base_url))


@app.get("/security-copilot/plugin.yaml")
async def security_copilot_plugin(request: Request) -> Response:
    public_base_url = resolve_public_base_url(str(request.base_url).rstrip("/"))
    return Response(
        content=build_security_copilot_manifest(public_base_url),
        media_type="application/yaml",
    )


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def forward(path: str, request: Request) -> Response:
    settings = get_settings()
    upstream_url = urljoin(_require_upstream_base_url(settings), path)
    headers = _filter_request_headers(request.headers.items())
    body = await request.body()
    query_params = _get_query_params(request.url.query, settings)
    upstream_response = await _send_upstream(
        method=request.method,
        upstream_url=upstream_url,
        headers=headers,
        query_params=query_params,
        content=body if body else None,
        timeout_seconds=settings.proxy_timeout,
    )

    response_headers = _filter_response_headers(upstream_response.headers)
    media_type = upstream_response.headers.get("content-type")

    return StreamingResponse(
        upstream_response.aiter_raw(),
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=media_type,
        background=BackgroundTask(upstream_response.aclose),
    )

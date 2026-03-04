import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urljoin

import httpx
from fastapi import FastAPI, HTTPException, Request
from starlette.background import BackgroundTask
from fastapi.responses import JSONResponse, Response, StreamingResponse


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


def _signed_query_params(
    original_query: str, access_id: str, secret_key: str, ttl_seconds: int
) -> httpx.QueryParams:
    expires = int(time.time()) + ttl_seconds
    signature = _build_ctix_signature(access_id, secret_key, expires)
    params = httpx.QueryParams(original_query)
    params = params.set("AccessID", access_id)
    params = params.set("Signature", signature)
    return params.set("Expires", str(expires))


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
        }
    )


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def forward(path: str, request: Request) -> Response:
    settings = get_settings()
    if not settings.upstream_base_url:
        raise HTTPException(status_code=500, detail="UPSTREAM_BASE_URL is not configured")

    upstream_url = urljoin(settings.upstream_base_url, path)
    headers = _filter_request_headers(request.headers.items())
    body = await request.body()
    query_params = (
        _signed_query_params(
            request.url.query,
            settings.ctix_access_id,
            settings.ctix_secret_key,
            settings.ctix_signature_ttl,
        )
        if settings.ctix_access_id and settings.ctix_secret_key
        else httpx.QueryParams(request.url.query)
    )

    timeout = httpx.Timeout(settings.proxy_timeout)

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            upstream_response = await client.send(
                client.build_request(
                    method=request.method,
                    url=upstream_url,
                    headers=headers,
                    params=query_params,
                    content=body if body else None,
                ),
                stream=True,
            )
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="Upstream request timed out") from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Upstream request failed: {exc}") from exc

    response_headers = _filter_response_headers(upstream_response.headers)
    media_type = upstream_response.headers.get("content-type")

    return StreamingResponse(
        upstream_response.aiter_raw(),
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=media_type,
        background=BackgroundTask(upstream_response.aclose),
    )

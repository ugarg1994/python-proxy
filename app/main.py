import base64
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urljoin

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
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

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("ctix_proxy")


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


def _sanitize_query_params(params: httpx.QueryParams) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in params.multi_items():
        safe_value: Any = "***" if key in {"AccessID", "Signature"} else value
        if key in sanitized:
            existing = sanitized[key]
            if isinstance(existing, list):
                existing.append(safe_value)
            else:
                sanitized[key] = [existing, safe_value]
        else:
            sanitized[key] = safe_value
    return sanitized


def _truncate_for_log(content: bytes | str | None, limit: int = 500) -> str | None:
    if content is None:
        return None
    if isinstance(content, bytes):
        text = content.decode("utf-8", errors="replace")
    else:
        text = content
    return text if len(text) <= limit else text[:limit] + "...<truncated>"


def _require_upstream_base_url(settings: Settings) -> str:
    if not settings.upstream_base_url:
        raise HTTPException(status_code=500, detail="UPSTREAM_BASE_URL is not configured")
    return settings.upstream_base_url


def _get_query_params(
    original_query: str,
    settings: Settings,
    explicit_params: dict[str, Any] | None = None,
) -> httpx.QueryParams:
    params = (
        httpx.QueryParams(explicit_params)
        if explicit_params is not None
        else httpx.QueryParams(original_query)
    )
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
    logger.info(
        "Forwarding request to CTIX method=%s upstream_url=%s query_params=%s body_preview=%s",
        method,
        upstream_url,
        _sanitize_query_params(query_params),
        _truncate_for_log(content),
    )
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            response = await client.send(
                client.build_request(
                    method=method,
                    url=upstream_url,
                    headers=headers,
                    params=query_params,
                    content=content,
                ),
                stream=True,
            )
            logger.info(
                "Received CTIX response method=%s upstream_url=%s status_code=%s content_type=%s",
                method,
                upstream_url,
                response.status_code,
                response.headers.get("content-type"),
            )
            return response
    except httpx.TimeoutException as exc:
        logger.exception("CTIX request timed out")
        raise HTTPException(status_code=504, detail="Upstream request timed out") from exc
    except httpx.RequestError as exc:
        logger.exception("CTIX request failed")
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


@app.get("/security-copilot/threat-data/search/")
async def security_copilot_threat_data_search(
    query: str | None = Query(
        default=None,
        description="CTIX CQL query string. Example: type = \"indicator\"",
    ),
    q: str | None = Query(
        default=None,
        description="Deprecated alias for query.",
    ),
) -> Response:
    settings = get_settings()
    cql_query = query or q
    if not cql_query:
        raise HTTPException(
            status_code=422,
            detail="The query parameter is required for Security Copilot threat data search.",
        )
    upstream_url = urljoin(
        _require_upstream_base_url(settings), "ingestion/threat-data/list/"
    )
    headers = {"content-type": "application/json"}
    # Match the working CTIX search pattern for threat-data CQL queries.
    query_params = _get_query_params(
        "",
        settings,
        explicit_params={
            "page": "1",
            "page_size": "10",
            "sort": "-ctix_modified",
        },
    )
    logger.info(
        "Security Copilot threat-data search query=%s upstream_url=%s query_params=%s",
        cql_query,
        upstream_url,
        _sanitize_query_params(query_params),
    )
    upstream_response = await _send_upstream(
        method="POST",
        upstream_url=upstream_url,
        headers=headers,
        query_params=query_params,
        content=json.dumps({"query": cql_query}),
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
    logger.info(
        "Generic proxy request path=%s method=%s upstream_url=%s query_params=%s body_preview=%s",
        path,
        request.method,
        upstream_url,
        _sanitize_query_params(query_params),
        _truncate_for_log(body if body else None),
    )
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

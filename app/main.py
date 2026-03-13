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


def _escape_cql_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _parse_csv_values(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _format_cql_in(field: str, values: list[str]) -> str | None:
    if not values:
        return None
    escaped = ",".join(f'"{_escape_cql_string(value)}"' for value in values)
    return f"{field} IN ({escaped})"


def _format_cql_equals(field: str, value: str | None) -> str | None:
    if value is None or value == "":
        return None
    return f'{field} = "{_escape_cql_string(value)}"'


def _format_cql_contains(field: str, value: str | None) -> str | None:
    if value is None or value == "":
        return None
    return f'{field} contains ("{_escape_cql_string(value)}")'


def _format_cql_range(field: str, start: str | None, end: str | None) -> str | None:
    if not start or not end:
        return None
    return f'{field} RANGE ("{_escape_cql_string(start)}","{_escape_cql_string(end)}")'


def _format_cql_boolean(field: str, value: bool | None) -> str | None:
    if value is None:
        return None
    return f'{field} = "{str(value).lower()}"'


async def _fetch_upstream_json(
    *,
    method: str,
    upstream_url: str,
    settings: Settings,
    query_params: httpx.QueryParams,
) -> dict[str, Any]:
    timeout = httpx.Timeout(settings.proxy_timeout)
    logger.info(
        "Lookup request to CTIX method=%s upstream_url=%s query_params=%s",
        method,
        upstream_url,
        _sanitize_query_params(query_params),
    )
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            response = await client.get(upstream_url, params=query_params)
            logger.info(
                "Lookup response from CTIX method=%s upstream_url=%s status_code=%s",
                method,
                upstream_url,
                response.status_code,
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        logger.exception("CTIX lookup request returned an error")
        raise HTTPException(
            status_code=502,
            detail=f"CTIX lookup failed with status {exc.response.status_code}",
        ) from exc
    except httpx.RequestError as exc:
        logger.exception("CTIX lookup request failed")
        raise HTTPException(status_code=502, detail=f"CTIX lookup failed: {exc}") from exc


async def _collect_paginated_results(
    *,
    initial_path: str,
    settings: Settings,
    explicit_params: dict[str, Any],
    max_pages: int = 5,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    next_url = urljoin(_require_upstream_base_url(settings), initial_path)
    next_params: httpx.QueryParams | None = _get_query_params(
        "",
        settings,
        explicit_params=explicit_params,
    )

    for _ in range(max_pages):
        payload = await _fetch_upstream_json(
            method="GET",
            upstream_url=next_url,
            settings=settings,
            query_params=next_params or httpx.QueryParams(),
        )
        results.extend(payload.get("results", []))
        next_link = payload.get("next")
        if not next_link:
            break
        next_url = urljoin(_require_upstream_base_url(settings), str(next_link))
        next_params = None

    return results


async def _resolve_source_names_to_ids(
    settings: Settings, source_names: list[str]
) -> list[str]:
    if not source_names:
        return []
    results = await _collect_paginated_results(
        initial_path="feed-sources/",
        settings=settings,
        explicit_params={"page": "1", "page_size": "100"},
    )
    wanted = {name.casefold(): name for name in source_names}
    matched_ids: list[str] = []
    matched_names: list[str] = []
    for item in results:
        name = str(item.get("name", ""))
        if name.casefold() in wanted:
            matched_ids.append(str(item.get("id")))
            matched_names.append(name)
    logger.info(
        "Resolved source names source_names=%s matched_names=%s matched_ids=%s",
        source_names,
        matched_names,
        matched_ids,
    )
    return matched_ids


async def _resolve_tag_names(
    settings: Settings, tag_names: list[str]
) -> list[str]:
    if not tag_names:
        return []
    matched_names: list[str] = []
    for tag_name in tag_names:
        results = await _collect_paginated_results(
            initial_path="tags/",
            settings=settings,
            explicit_params={"page": "1", "page_size": "100", "q": tag_name},
            max_pages=2,
        )
        for item in results:
            candidate = str(item.get("name", ""))
            if candidate.casefold() == tag_name.casefold():
                matched_names.append(candidate)
    logger.info(
        "Resolved tag names tag_names=%s matched_names=%s",
        tag_names,
        matched_names,
    )
    return matched_names


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


async def _run_ctix_threat_data_search(
    settings: Settings, cql_query: str, sort: str | None = None
) -> Response:
    upstream_url = urljoin(
        _require_upstream_base_url(settings), "ingestion/threat-data/list/"
    )
    headers = {"content-type": "application/json"}
    query_params = _get_query_params(
        "",
        settings,
        explicit_params={
            "page": "1",
            "page_size": "10",
            "sort": sort or "-ctix_modified",
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
    return await _run_ctix_threat_data_search(settings, cql_query)


@app.get("/security-copilot/search-indicators-by-value/")
async def security_copilot_search_indicators_by_value(
    value: str = Query(
        ...,
        description="Indicator value to search for, such as an IP, domain, URL, or hash.",
    ),
) -> Response:
    settings = get_settings()
    escaped_value = _escape_cql_string(value)
    cql_query = f'type = "indicator" AND value contains ("{escaped_value}")'
    return await _run_ctix_threat_data_search(settings, cql_query)


@app.get("/security-copilot/search-reports-by-keyword/")
async def security_copilot_search_reports_by_keyword(
    keyword: str = Query(
        ...,
        description="Keyword to search for in CTIX report names.",
    ),
) -> Response:
    settings = get_settings()
    escaped_keyword = _escape_cql_string(keyword)
    cql_query = f'type = "report" AND name contains ("{escaped_keyword}")'
    return await _run_ctix_threat_data_search(settings, cql_query)


@app.get("/security-copilot/search-threat-data-by-type/")
async def security_copilot_search_threat_data_by_type(
    object_type: str = Query(
        ...,
        description="CTIX object type such as indicator, malware, threat-actor, report, or vulnerability.",
    ),
) -> Response:
    settings = get_settings()
    escaped_object_type = _escape_cql_string(object_type)
    cql_query = f'type = "{escaped_object_type}"'
    return await _run_ctix_threat_data_search(settings, cql_query)


@app.get("/security-copilot/search-threat-data-by-tag/")
async def security_copilot_search_threat_data_by_tag(
    tag: str = Query(
        ...,
        description="Tag name to search for across CTIX threat data.",
    ),
) -> Response:
    settings = get_settings()
    escaped_tag = _escape_cql_string(tag)
    cql_query = f'tags contains ("{escaped_tag}")'
    return await _run_ctix_threat_data_search(settings, cql_query)


@app.get("/security-copilot/search-threat-data-advanced/")
async def security_copilot_search_threat_data_advanced(
    value: str | None = Query(default=None, description="Search by threat data value."),
    tag: str | None = Query(default=None, description="Search by tag."),
    tag_names: str | None = Query(
        default=None,
        description="Comma-separated tag names to resolve and search for.",
    ),
    related_object: str | None = Query(
        default=None,
        description="Related object type, for example threat-actor, malware, or campaign.",
    ),
    related_object_value: str | None = Query(
        default=None,
        description="Related object value or name, for example APT28.",
    ),
    sort: str | None = Query(
        default=None,
        description="CTIX sort field, for example -ctix_modified, -created, or -confidence_score.",
    ),
    object_types: str | None = Query(
        default=None,
        description="Comma-separated CTIX object types, for example indicator,malware,threat-actor.",
    ),
    ioc_type: str | None = Query(default=None, description="IOC type filter."),
    sources: str | None = Query(
        default=None,
        description="Comma-separated source IDs.",
    ),
    source_names: str | None = Query(
        default=None,
        description="Comma-separated source names to resolve into source IDs.",
    ),
    source_type: str | None = Query(default=None, description="Source type filter."),
    source_collections: str | None = Query(
        default=None,
        description="Comma-separated source collection IDs.",
    ),
    published_collections: str | None = Query(
        default=None,
        description="Comma-separated published collection IDs.",
    ),
    countries: str | None = Query(
        default=None,
        description="Comma-separated country names.",
    ),
    tlp: str | None = Query(default=None, description="TLP filter."),
    source_confidence: str | None = Query(default=None, description="Source confidence filter."),
    source_confidence_min: str | None = Query(default=None),
    source_confidence_max: str | None = Query(default=None),
    source_created_from: str | None = Query(default=None),
    source_created_to: str | None = Query(default=None),
    source_modified_from: str | None = Query(default=None),
    source_modified_to: str | None = Query(default=None),
    published_on_from: str | None = Query(default=None),
    published_on_to: str | None = Query(default=None),
    ctix_created_from: str | None = Query(default=None),
    ctix_created_to: str | None = Query(default=None),
    ctix_modified_from: str | None = Query(default=None),
    ctix_modified_to: str | None = Query(default=None),
    confidence_score_min: str | None = Query(default=None),
    confidence_score_max: str | None = Query(default=None),
    valid_from_from: str | None = Query(default=None),
    valid_from_to: str | None = Query(default=None),
    valid_until_from: str | None = Query(default=None),
    valid_until_to: str | None = Query(default=None),
    analyst_score_min: str | None = Query(default=None),
    analyst_score_max: str | None = Query(default=None),
    is_deprecated: bool | None = Query(default=None),
    is_false_positive: bool | None = Query(default=None),
    is_reviewed: bool | None = Query(default=None),
    is_revoked: bool | None = Query(default=None),
    is_under_review: bool | None = Query(default=None),
    is_whitelisted: bool | None = Query(default=None),
) -> Response:
    settings = get_settings()
    resolved_source_ids = await _resolve_source_names_to_ids(
        settings, _parse_csv_values(source_names)
    )
    resolved_tag_names = await _resolve_tag_names(settings, _parse_csv_values(tag_names))
    source_id_values = _parse_csv_values(sources) + resolved_source_ids
    tag_values = ([tag] if tag else []) + resolved_tag_names
    clauses = [
        _format_cql_contains("value", value),
        (
            "("
            + " OR ".join(
                filter(None, (_format_cql_contains("tags", tag_value) for tag_value in tag_values))
            )
            + ")"
        )
        if tag_values
        else None,
        _format_cql_equals("related_object", related_object),
        _format_cql_contains("related_object_value", related_object_value),
        _format_cql_in("type", _parse_csv_values(object_types)),
        _format_cql_equals("ioc_type", ioc_type),
        _format_cql_in("source", source_id_values),
        _format_cql_equals("source_type", source_type),
        _format_cql_in("source_collection", _parse_csv_values(source_collections)),
        _format_cql_in("published_collection", _parse_csv_values(published_collections)),
        _format_cql_in("countries", _parse_csv_values(countries)),
        _format_cql_equals("tlp", tlp),
        _format_cql_equals("source_confidence", source_confidence),
        _format_cql_range(
            "source_confidence_value", source_confidence_min, source_confidence_max
        ),
        _format_cql_range("source_created", source_created_from, source_created_to),
        _format_cql_range("source_modified", source_modified_from, source_modified_to),
        _format_cql_range("published_on", published_on_from, published_on_to),
        _format_cql_range("ctix_created", ctix_created_from, ctix_created_to),
        _format_cql_range("ctix_modified", ctix_modified_from, ctix_modified_to),
        _format_cql_range("confidence_score", confidence_score_min, confidence_score_max),
        _format_cql_range("valid_from", valid_from_from, valid_from_to),
        _format_cql_range("valid_until", valid_until_from, valid_until_to),
        _format_cql_range("analyst_score", analyst_score_min, analyst_score_max),
        _format_cql_boolean("is_deprecated", is_deprecated),
        _format_cql_boolean("is_false_positive", is_false_positive),
        _format_cql_boolean("is_reviewed", is_reviewed),
        _format_cql_boolean("is_revoked", is_revoked),
        _format_cql_boolean("is_under_review", is_under_review),
        _format_cql_boolean("is_whitelisted", is_whitelisted),
    ]
    cql_query = " AND ".join(clause for clause in clauses if clause)
    if not cql_query:
        raise HTTPException(
            status_code=422,
            detail="Provide at least one search filter for advanced threat data search.",
        )
    return await _run_ctix_threat_data_search(settings, cql_query, sort=sort)


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

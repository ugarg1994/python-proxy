import copy
import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_CTIX_SPEC_PATH = PROJECT_ROOT / "Intel Exchange Swagger API.json"
SECURITY_COPILOT_ALLOWED_OPERATIONS = {
    ("/", "get"),
    ("/feed-sources/collection/", "get"),
    ("/reports/", "get"),
    ("/reports/{report_id}/", "get"),
    ("/reports/{report_id}/run/", "get"),
    ("/subscriber/polling-report/", "get"),
    ("/subscriber/inboxing-report/", "get"),
}


@lru_cache(maxsize=1)
def load_raw_ctix_spec() -> dict[str, Any]:
    return json.loads(RAW_CTIX_SPEC_PATH.read_text())


def _remove_ctix_auth_params(parameters: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not parameters:
        return []
    stripped: list[dict[str, Any]] = []
    for parameter in parameters:
        if (
            parameter.get("in") == "query"
            and parameter.get("name") in {"AccessID", "Signature", "Expires"}
        ):
            continue
        stripped.append(parameter)
    return stripped


def _is_security_copilot_supported_request_body(
    request_body: dict[str, Any] | None,
) -> bool:
    return request_body is None


def _build_cql_search_operation() -> dict[str, Any]:
    return {
        "get": {
            "tags": ["Threat Data"],
            "summary": "Search CTIX Threat Data by CQL Query",
            "description": (
                "Runs a CTIX threat data search using a CQL query string. "
                "This endpoint is intended for Security Copilot. "
                "Provide exactly one required parameter named query. "
                "Do not build a JSON body. "
                "Do not use any other search parameter. "
                "The proxy automatically sends the request to "
                "/ingestion/threat-data/list/ with page=1, page_size=10, and sort=-ctix_modified. "
                "Use simple CTIX CQL such as type = \"indicator\" or "
                "type = \"indicator\" AND value contains (\"1.1.1.1\")."
            ),
            "operationId": "searchCtixThreatDataByCql",
            "parameters": [
                {
                    "name": "query",
                    "in": "query",
                    "required": True,
                    "schema": {
                        "type": "string",
                        "example": 'type = "indicator"',
                    },
                    "description": (
                        "CTIX CQL query string. "
                        'Example 1: type = "indicator". '
                        'Example 2: type = "indicator" AND value contains ("1.1.1.1").'
                    ),
                    "examples": {
                        "list_indicators": {
                            "summary": "List indicators",
                            "value": 'type = "indicator"',
                        },
                        "search_ip": {
                            "summary": "Find an IP indicator",
                            "value": 'type = "indicator" AND value contains ("1.1.1.1")',
                        },
                        "search_domain": {
                            "summary": "Find a domain indicator",
                            "value": 'type = "indicator" AND value contains ("google.com")',
                        },
                    },
                },
            ],
            "responses": {
                "200": {
                    "description": "Threat data search results from CTIX.",
                }
            },
        }
    }


def _build_simple_search_operations() -> dict[str, Any]:
    return {
        "/security-copilot/search-indicators-by-value/": {
            "get": {
                "tags": ["Threat Data"],
                "summary": "Search indicators by value",
                "description": (
                    "Search CTIX indicators by a simple value such as an IP address, "
                    "domain, URL, or hash. The proxy converts the value into CTIX CQL."
                ),
                "operationId": "searchIndicatorsByValue",
                "parameters": [
                    {
                        "name": "value",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string", "example": "1.1.1.1"},
                        "description": "Indicator value to search for.",
                    }
                ],
                "responses": {"200": {"description": "Indicator search results from CTIX."}},
            }
        },
        "/security-copilot/search-reports-by-keyword/": {
            "get": {
                "tags": ["Reports"],
                "summary": "Search reports by keyword",
                "description": (
                    "Search CTIX reports by a keyword in the report name. "
                    "The proxy converts the keyword into CTIX CQL."
                ),
                "operationId": "searchReportsByKeyword",
                "parameters": [
                    {
                        "name": "keyword",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string", "example": "phishing"},
                        "description": "Keyword to search for in report names.",
                    }
                ],
                "responses": {"200": {"description": "Report search results from CTIX."}},
            }
        },
        "/security-copilot/search-threat-data-by-type/": {
            "get": {
                "tags": ["Threat Data"],
                "summary": "Search threat data by object type",
                "description": (
                    "Search CTIX threat data by object type such as indicator, malware, "
                    "threat-actor, report, or vulnerability."
                ),
                "operationId": "searchThreatDataByType",
                "parameters": [
                    {
                        "name": "object_type",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string", "example": "malware"},
                        "description": "CTIX object type to search for.",
                    }
                ],
                "responses": {"200": {"description": "Threat data search results from CTIX."}},
            }
        },
        "/security-copilot/search-threat-data-by-tag/": {
            "get": {
                "tags": ["Threat Data"],
                "summary": "Search threat data by tag",
                "description": "Search CTIX threat data items that contain a given tag.",
                "operationId": "searchThreatDataByTag",
                "parameters": [
                    {
                        "name": "tag",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string", "example": "phishing"},
                        "description": "Tag to search for.",
                    }
                ],
                "responses": {"200": {"description": "Tagged threat data search results from CTIX."}},
            }
        },
        "/security-copilot/search-threat-data-advanced/": {
            "get": {
                "tags": ["Threat Data"],
                "summary": "Search threat data with multiple filters",
                "description": (
                    "Search CTIX threat data using simple filter parameters such as value, tag, "
                    "object types, sources, source collections, countries, ranges, and boolean flags. "
                    "The proxy converts these filters into CTIX CQL."
                ),
                "operationId": "searchThreatDataAdvanced",
                "parameters": [
                    {
                        "name": "value",
                        "in": "query",
                        "schema": {"type": "string", "example": "1.1.1.1"},
                        "description": "Threat data value to search for.",
                    },
                    {
                        "name": "tag",
                        "in": "query",
                        "schema": {"type": "string", "example": "phishing"},
                        "description": "Tag to search for.",
                    },
                    {
                        "name": "tag_names",
                        "in": "query",
                        "schema": {"type": "string", "example": "phishing,malware"},
                        "description": "Comma-separated tag names to resolve before searching.",
                    },
                    {
                        "name": "related_object",
                        "in": "query",
                        "schema": {"type": "string", "example": "threat-actor"},
                        "description": "Related object type.",
                    },
                    {
                        "name": "related_object_value",
                        "in": "query",
                        "schema": {"type": "string", "example": "APT28"},
                        "description": "Related object value or name.",
                    },
                    {
                        "name": "object_types",
                        "in": "query",
                        "schema": {
                            "type": "string",
                            "example": "indicator,malware,threat-actor",
                        },
                        "description": "Comma-separated CTIX object types.",
                    },
                    {
                        "name": "ioc_type",
                        "in": "query",
                        "schema": {"type": "string", "example": "ALL"},
                    },
                    {
                        "name": "sources",
                        "in": "query",
                        "schema": {
                            "type": "string",
                            "example": "dac01547-0550-4a5f-a51c-209142c7bb31,92614d49-0766-4331-bbc0-be4e78ad7b3a",
                        },
                        "description": "Comma-separated source IDs.",
                    },
                    {
                        "name": "source_names",
                        "in": "query",
                        "schema": {
                            "type": "string",
                            "example": "Threatfeed,Threatfeed1",
                        },
                        "description": "Comma-separated source names to resolve into source IDs.",
                    },
                    {
                        "name": "source_collections",
                        "in": "query",
                        "schema": {
                            "type": "string",
                            "example": "bb9a8b41-9a9d-452f-a16e-85dc70ba9eb5,dafc1732-4072-464e-8f0e-33b24b00c950",
                        },
                    },
                    {
                        "name": "countries",
                        "in": "query",
                        "schema": {
                            "type": "string",
                            "example": "Afghanistan,Aland Islands,Albania,Algeria",
                        },
                    },
                    {
                        "name": "is_revoked",
                        "in": "query",
                        "schema": {"type": "boolean", "example": True},
                    },
                ],
                "responses": {"200": {"description": "Advanced threat data search results from CTIX."}},
            }
        },
    }


def build_security_copilot_openapi(public_base_url: str) -> dict[str, Any]:
    raw_spec = load_raw_ctix_spec()
    spec = copy.deepcopy(raw_spec)

    transformed_paths: dict[str, Any] = {}
    for path, path_item in spec.get("paths", {}).items():
        target_path = "/ping/" if path == "/" else path
        transformed_item: dict[str, Any] = {}
        for method, operation in path_item.items():
            if not isinstance(operation, dict):
                continue
            if (path, method.lower()) not in SECURITY_COPILOT_ALLOWED_OPERATIONS:
                continue
            if not _is_security_copilot_supported_request_body(
                operation.get("requestBody")
            ):
                continue
            transformed_operation = copy.deepcopy(operation)
            transformed_operation["parameters"] = _remove_ctix_auth_params(
                transformed_operation.get("parameters")
            )
            transformed_item[method] = transformed_operation

        if transformed_item:
            transformed_paths[target_path] = transformed_item

    spec["openapi"] = "3.0.1"
    spec["info"] = {
        "title": "CTIX Proxy API for Security Copilot",
        "version": spec.get("info", {}).get("version", "1.0.0"),
        "description": (
            "Security Copilot-facing CTIX API spec routed through the Render proxy. "
            "The proxy preserves method, path, query, headers, and body, and injects "
            "CTIX AccessID/Signature/Expires query authentication on the server side. "
            "This Security Copilot variant includes only operations without request bodies "
            "to stay within current API plugin parser limits."
        ),
    }
    spec["servers"] = [{"url": public_base_url.rstrip("/")}]
    spec["paths"] = transformed_paths
    spec["paths"]["/security-copilot/threat-data/search/"] = _build_cql_search_operation()
    spec["paths"].update(_build_simple_search_operations())
    spec.pop("security", None)
    components = spec.get("components")
    if isinstance(components, dict):
        components.pop("securitySchemes", None)

    return spec


def build_security_copilot_manifest(public_base_url: str) -> str:
    normalized = public_base_url.rstrip("/")
    return "\n".join(
        [
            "Descriptor:",
            "  Name: CTIXProxy",
            "  DisplayName: CTIX Proxy",
            "  Description: Query the CTIX API through a Render-hosted proxy that injects CTIX authentication.",
            "  SupportedAuthTypes:",
            "    - None",
            "SkillGroups:",
            "  - Format: API",
            "    Settings:",
            f"      OpenApiSpecUrl: {normalized}/security-copilot/openapi.json",
            "",
        ]
    )


def resolve_public_base_url(request_base_url: str) -> str:
    configured = os.getenv("PUBLIC_BASE_URL")
    if configured:
        return configured.rstrip("/")
    return request_base_url.rstrip("/")

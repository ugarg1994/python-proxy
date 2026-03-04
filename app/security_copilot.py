import copy
import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_CTIX_SPEC_PATH = PROJECT_ROOT / "Intel Exchange Swagger API.json"


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

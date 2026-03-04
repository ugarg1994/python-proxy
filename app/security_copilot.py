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


def build_security_copilot_openapi(public_base_url: str) -> dict[str, Any]:
    raw_spec = load_raw_ctix_spec()
    spec = copy.deepcopy(raw_spec)

    transformed_paths: dict[str, Any] = {}
    for path, path_item in spec.get("paths", {}).items():
        target_path = "/ping/" if path == "/" else path
        transformed_item = copy.deepcopy(path_item)
        for method, operation in list(transformed_item.items()):
            if not isinstance(operation, dict):
                continue
            operation["parameters"] = _remove_ctix_auth_params(
                operation.get("parameters")
            )
        transformed_paths[target_path] = transformed_item

    spec["openapi"] = "3.0.1"
    spec["info"] = {
        "title": "CTIX Proxy API for Security Copilot",
        "version": spec.get("info", {}).get("version", "1.0.0"),
        "description": (
            "Security Copilot-facing CTIX API spec routed through the Render proxy. "
            "The proxy preserves method, path, query, headers, and body, and injects "
            "CTIX AccessID/Signature/Expires query authentication on the server side."
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

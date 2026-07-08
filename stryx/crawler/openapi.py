"""OpenAPI/Swagger endpoint discovery."""

from __future__ import annotations

from stryx.crawler.discovery import Endpoint
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("crawler.openapi")

OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/openapi.json",
    "/api/openapi.json",
    "/docs/openapi.json",
    "/swagger.json",
    "/swagger-ui.json",
    "/api-docs.json",
    "/api/swagger.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
]


async def discover_openapi(target_url: str) -> list[Endpoint]:
    """Discover endpoints from OpenAPI/Swagger documentation."""
    logger.info("Scanning for OpenAPI/Swagger documentation")
    endpoints: list[Endpoint] = []
    client = HttpClient(timeout=5)

    for path in OPENAPI_PATHS:
        url = f"{target_url}{path}"
        try:
            response, evidence = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict) and ("paths" in data or "openapi" in data or "swagger" in data):
                    logger.info(f"Found OpenAPI spec at {path}")
                    endpoints.extend(_parse_openapi_paths(data, target_url))
        except Exception:
            continue

    return endpoints


def _parse_openapi_paths(spec: dict, base_url: str) -> list[Endpoint]:
    """Parse paths from an OpenAPI specification."""
    endpoints: list[Endpoint] = []
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method in methods:
            if method.lower() in ("get", "post", "put", "delete", "patch", "head", "options"):
                params = []
                operation = methods[method]
                if isinstance(operation, dict):
                    for param in operation.get("parameters", []):
                        if isinstance(param, dict):
                            params.append(param.get("name", ""))

                endpoints.append(Endpoint(
                    path=f"{base_url}{path}",
                    method=method.upper(),
                    source="openapi",
                    confidence=0.95,
                    params=[p for p in params if p],
                ))

    return endpoints

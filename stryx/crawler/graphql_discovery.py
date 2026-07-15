"""GraphQL endpoint discovery."""

from __future__ import annotations

import json

from stryx.crawler.discovery import Endpoint
from stryx.utils.http_client import HttpClient
from stryx.utils.logging import get_logger

logger = get_logger("crawler.graphql")

GRAPHQL_PATHS = [
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/query",
    "/api/query",
    "/v1/graphql",
    "/v2/graphql",
    "/gql",
    "/api/gql",
    "/_graphql",
]


async def discover_graphql(target_url: str) -> list[Endpoint]:
    """Discover GraphQL endpoints by probing common paths and introspection."""
    logger.info("Scanning for GraphQL endpoints")
    endpoints: list[Endpoint] = []
    client = HttpClient(timeout=5)

    introspection_query = json.dumps(
        {"query": "{ __schema { queryType { name } mutationType { name } types { name } } }"}
    )

    for path in GRAPHQL_PATHS:
        url = f"{target_url}{path}"
        try:
            # Try GET first (some servers support it)
            response, evidence = await client.get(url)
            if response.status_code == 200 and _looks_like_graphql(response.text):
                endpoints.append(
                    Endpoint(
                        path=url,
                        method="GET",
                        source="graphql",
                        confidence=0.9,
                    )
                )
                continue

            # Try POST with introspection query
            response, evidence = await client.post(
                url,
                body=introspection_query,
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, dict) and "data" in data:
                        logger.info(f"Found GraphQL endpoint at {path} (introspection works)")
                        endpoints.append(
                            Endpoint(
                                path=url,
                                method="POST",
                                source="graphql-introspection",
                                confidence=0.95,
                            )
                        )
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            continue

    return endpoints


def _looks_like_graphql(text: str) -> bool:
    """Check if a response looks like a GraphQL endpoint."""
    indicators = [
        "graphiql",
        "graphql",
        "__schema",
        "query",
        "mutation",
    ]
    text_lower = text.lower()
    return any(ind in text_lower for ind in indicators)

"""Reconnaissance agent: maps the attack surface of a running application.

The agent prefers deterministic sources (OpenAPI spec, Postman collection)
and falls back to lightweight crawling when neither is provided.
"""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from mado.graph.state import AttackSurface, Route, Target

_MAX_DEPTH = 2


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for attr, value in attrs:
            if attr.lower() == "href" and value:
                self.links.append(value)


def _join_routes(url: str, paths: list[str], methods: list[str] | None = None) -> list[Route]:
    used_methods = methods or ["GET"]
    routes: list[Route] = []
    seen: set[tuple[str, str]] = set()
    for path in paths:
        if path.startswith(("http://", "https://")):
            absolute = path
        else:
            normalized = path if path.startswith("/") else "/" + path
            absolute = urljoin(url, normalized)
        for method in used_methods:
            key = (method.upper(), absolute)
            if key in seen:
                continue
            seen.add(key)
            routes.append(Route(method=method.upper(), path=absolute))
    return routes


def parse_openapi(spec_path: str, base_url: str) -> AttackSurface:
    """Parse an OpenAPI (JSON/YAML) spec into routes."""
    text = Path(spec_path).read_text(encoding="utf-8")
    try:
        import yaml

        spec: dict[str, Any] = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid OpenAPI spec {spec_path}: {exc}") from exc

    if not isinstance(spec, dict):
        raise ValueError(f"Invalid OpenAPI spec {spec_path}: expected a mapping")

    servers = spec.get("servers") or []
    if not base_url and isinstance(servers, list) and servers:
        first = servers[0]
        if isinstance(first, dict) and first.get("url"):
            base_url = str(first["url"])

    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        raise ValueError(f"Invalid OpenAPI spec {spec_path}: missing 'paths'")

    routes: list[Route] = []
    seen: set[tuple[str, str]] = set()
    for path, operations in paths.items():
        if not isinstance(operations, dict):
            continue
        for method in ("get", "post", "put", "patch", "delete", "options", "head"):
            if method in operations:
                key = (method.upper(), path)
                if key in seen:
                    continue
                seen.add(key)
                routes.append(Route(method=method.upper(), path=urljoin(base_url or "", path)))

    return AttackSurface(url=base_url or "", routes=routes, source="openapi")


def parse_postman(collection_path: str, base_url: str | None = None) -> AttackSurface:
    """Parse a Postman collection (JSON) into routes."""
    import json

    payload = json.loads(Path(collection_path).read_text(encoding="utf-8"))

    base_url = base_url or _postman_base_url(payload)
    requests_ = _postman_requests(payload.get("item", []))
    routes = _join_routes(
        base_url or "http://localhost", [item["path"] for item in requests_], [item["method"] for item in requests_]
    )
    return AttackSurface(url=base_url or "", routes=routes, source="postman")


def _postman_base_url(payload: dict[str, Any]) -> str | None:
    variables = payload.get("variable") or []
    for variable in variables:
        if isinstance(variable, dict) and variable.get("key") in ("baseUrl", "baseURL", "host"):
            value = variable.get("value")
            if value:
                return str(value)
    return None


def _postman_requests(items: list[Any]) -> list[dict[str, str]]:
    requests_: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if "request" in item and "item" not in item:
            request = item.get("request")
            if isinstance(request, dict):
                method = request.get("method") or "GET"
                url = request.get("url")
                if isinstance(url, dict):
                    url = url.get("raw")
                if url:
                    requests_.append({"method": str(method).upper(), "path": str(url)})
        for nested in _postman_requests(item.get("item", [])):
            requests_.append(nested)
    return requests_


def crawl(url: str, max_depth: int = _MAX_DEPTH) -> AttackSurface:
    """Crawl the application, collecting same-origin links."""
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(url, 0)]
    routes: list[Route] = []
    seen_routes: set[str] = set()

    while queue:
        current, depth = queue.pop(0)
        if current in visited or depth > max_depth:
            continue
        visited.add(current)
        try:
            response = requests.get(current, timeout=10)
        except requests.RequestException:
            continue
        if response.status_code >= 400:
            continue

        if current not in seen_routes:
            seen_routes.add(current)
            routes.append(Route(method="GET", path=current))

        if depth == max_depth:
            continue
        extractor = _LinkExtractor()
        try:
            extractor.feed(response.text)
        except Exception:
            continue
        for href in extractor.links:
            absolute = urljoin(current, href)
            if urlparse(absolute).netloc == parsed.netloc and absolute not in visited:
                queue.append((absolute, depth + 1))

    return AttackSurface(url=origin, routes=routes, source="crawl")


class ReconAgent:
    """Map the attack surface of a running application."""

    def map_surface(self, target: Target) -> AttackSurface:
        if target.openapi_spec:
            return parse_openapi(target.openapi_spec, target.url or "")
        if target.postman_collection:
            return parse_postman(target.postman_collection, target.url)
        if not target.url:
            raise RuntimeError("Recon requires a target URL, an OpenAPI spec or a Postman collection.")
        return crawl(target.url)

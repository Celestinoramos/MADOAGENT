from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mado.agents.recon import ReconAgent, parse_openapi, parse_postman
from mado.graph.state import Target

OPENAPI_SPEC = """
openapi: 3.0.0
info:
  title: Demo
  version: "1.0"
servers:
  - url: http://localhost:8000
paths:
  /users:
    get:
      summary: list
  /users/{id}:
    get:
      summary: get
  /login:
    post:
      summary: login
"""

POSTMAN_COLLECTION = {
    "info": {"name": "Demo"},
    "variable": [{"key": "baseUrl", "value": "http://localhost:8000"}],
    "item": [
        {
            "request": {"method": "GET", "url": "http://localhost:8000/users"},
            "name": "List users",
        },
        {
            "request": {"method": "POST", "url": {"raw": "http://localhost:8000/login"}},
            "name": "Login",
        },
    ],
}


class ReconTests(unittest.TestCase):
    def test_parse_openapi_routes(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            f.write(OPENAPI_SPEC)
            spec_path = f.name
        surface = parse_openapi(spec_path, "")
        self.assertEqual(surface.source, "openapi")
        self.assertEqual(surface.url, "http://localhost:8000")
        methods = {(route.method, route.path) for route in surface.routes}
        self.assertIn(("GET", "http://localhost:8000/users"), methods)
        self.assertIn(("POST", "http://localhost:8000/login"), methods)

    def test_parse_postman_routes(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(POSTMAN_COLLECTION, f)
            collection_path = f.name
        surface = parse_postman(collection_path)
        self.assertEqual(surface.source, "postman")
        methods = {(route.method, route.path) for route in surface.routes}
        self.assertIn(("GET", "http://localhost:8000/users"), methods)
        self.assertIn(("POST", "http://localhost:8000/login"), methods)

    def test_recon_agent_prefers_openapi(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            f.write(OPENAPI_SPEC)
            spec_path = f.name
        target = Target(url="http://localhost:8000", openapi_spec=spec_path)
        surface = ReconAgent().map_surface(target)
        self.assertEqual(surface.source, "openapi")
        self.assertEqual(len(surface.routes), 3)

    def test_recon_agent_requires_source(self) -> None:
        with self.assertRaises(RuntimeError):
            ReconAgent().map_surface(Target())

    def test_crawl_collects_same_origin_links(self) -> None:
        from unittest.mock import patch

        class _FakeResponse:
            status_code = 200
            text = '<html><body><a href="/about">About</a><a href="http://evil.com/x">Bad</a></body></html>'

        with patch("mado.agents.recon.requests.get", return_value=_FakeResponse()) as mock_get:
            surface = ReconAgent().map_surface(Target(url="http://localhost:8000"))
            paths = {route.path for route in surface.routes}
            self.assertIn("http://localhost:8000/about", paths)
            self.assertNotIn("http://evil.com/x", paths)
            mock_get.assert_called()


if __name__ == "__main__":
    unittest.main()

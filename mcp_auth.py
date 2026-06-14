#!/usr/bin/env python3
"""
Resource-server auth for the MCP servers.

This is the other half of the OAuth flow: it protects an MCP server's HTTP
endpoint by requiring a valid bearer token issued by our authorization server,
and it advertises where to get one.

What it adds to a FastMCP app:
  - GET /.well-known/oauth-protected-resource  (RFC 9728) — tells Claude which
    authorization server protects this resource, so the connector can discover it.
  - An ASGI middleware on the MCP path that:
      * validates the JWT signature against the AS's JWKS (fetched + cached),
      * checks iss / aud / exp,
      * returns 401 with a WWW-Authenticate header pointing at the resource
        metadata when the token is missing or invalid (this 401 is exactly what
        kicks off Claude's OAuth flow).

Tokens are RS256 JWTs, so validation is stateless — no shared session store, which
matters when you run several replicas on EKS.
"""

import time
import urllib.request
import json as _json

import jwt
from jwt import PyJWKClient
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


class _JWKSCache:
    """Tiny TTL cache around the AS JWKS so we don't refetch on every request."""

    def __init__(self, jwks_uri: str, ttl: int = 3600):
        self.jwks_uri = jwks_uri
        self.ttl = ttl
        self._client: PyJWKClient | None = None
        self._fetched = 0.0

    def client(self) -> PyJWKClient:
        now = time.time()
        if self._client is None or (now - self._fetched) > self.ttl:
            self._client = PyJWKClient(self.jwks_uri)
            self._fetched = now
        return self._client


class BearerAuthMiddleware:
    """Require a valid bearer token on `protected_path`; 401 otherwise."""

    def __init__(self, app: ASGIApp, *, issuer: str, jwks_uri: str,
                 resource: str, protected_path: str = "/mcp",
                 metadata_path: str = "/.well-known/oauth-protected-resource"):
        self.app = app
        self.issuer = issuer.rstrip("/")
        self.resource = resource.rstrip("/")
        self.protected_path = protected_path
        self.metadata_path = metadata_path
        self.jwks = _JWKSCache(jwks_uri)

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # Serve protected-resource metadata unauthenticated (it's discovery info).
        if path == self.metadata_path:
            await JSONResponse({
                "resource": self.resource,
                "authorization_servers": [self.issuer],
                "bearer_methods_supported": ["header"],
            })(scope, receive, send)
            return

        # Only guard the MCP endpoint; leave anything else (health checks) open.
        if not path.startswith(self.protected_path):
            await self.app(scope, receive, send)
            return

        token = self._bearer(scope)
        if not token or not self._valid(token):
            await self._challenge(scope, receive, send)
            return

        await self.app(scope, receive, send)

    def _bearer(self, scope) -> str | None:
        for k, v in scope.get("headers", []):
            if k == b"authorization":
                val = v.decode()
                if val.lower().startswith("bearer "):
                    return val[7:].strip()
        return None

    def _valid(self, token: str) -> bool:
        try:
            signing_key = self.jwks.client().get_signing_key_from_jwt(token)
            jwt.decode(token, signing_key.key, algorithms=["RS256"],
                       audience=self.resource, issuer=self.issuer,
                       options={"require": ["exp", "iss", "aud"]})
            return True
        except Exception:
            return False

    async def _challenge(self, scope, receive, send):
        # The resource_metadata hint is what lets Claude discover the AS and
        # start the OAuth dance (RFC 9728 / MCP authorization spec).
        www_auth = (f'Bearer resource_metadata='
                    f'"{self.resource}{self.metadata_path}"')
        await JSONResponse(
            {"error": "invalid_token",
             "error_description": "missing or invalid bearer token"},
            status_code=401,
            headers={"WWW-Authenticate": www_auth},
        )(scope, receive, send)


def protect(app: ASGIApp, *, issuer: str, resource: str,
            jwks_uri: str | None = None, protected_path: str = "/mcp") -> ASGIApp:
    """Wrap a FastMCP streamable-http app with bearer-token auth.

    Args:
        app: the Starlette app from mcp.streamable_http_app().
        issuer: the OAuth AS issuer URL (e.g. https://auth.example.com).
        resource: this server's canonical URL (the audience tokens must carry).
        jwks_uri: AS JWKS URL; defaults to <issuer>/.well-known/jwks.json.
        protected_path: the path to guard (default /mcp).
    """
    jwks_uri = jwks_uri or f"{issuer.rstrip('/')}/.well-known/jwks.json"
    return BearerAuthMiddleware(app, issuer=issuer, jwks_uri=jwks_uri,
                                resource=resource, protected_path=protected_path)

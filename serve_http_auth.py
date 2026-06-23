#!/usr/bin/env python3
"""
Serve an MCP server over HTTP, protected by the self-hosted OAuth layer.

Same idea as serve_http.py, but wraps the server's app with bearer-token auth
(mcp_auth.protect) so only callers with a valid token from your authorization
server can reach the tools. This is what you expose publicly (behind TLS).

Usage:
    OAUTH_ISSUER=https://auth.example.com \
    RESOURCE_URL=https://dns.example.com \
    python serve_http_auth.py dns_server 8001
"""

import importlib
import os
import sys

import uvicorn
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from mcp_auth import protect

SERVERS = {
    "dns_server", "netdiag_server", "tls_server", "http_server",
    "nmap_server", "tshark_server", "troubleshoot_server", "ssh_diag_server",
}


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in SERVERS:
        print("Usage: python serve_http_auth.py <server> [port]")
        print("Servers:", ", ".join(sorted(SERVERS)))
        sys.exit(1)

    name = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "127.0.0.1")
    issuer = os.environ.get("OAUTH_ISSUER", "http://localhost:9000")
    # The audience tokens must carry to reach this server. In production set this
    # to the server's public URL; locally it can be the loopback URL.
    resource = os.environ.get("RESOURCE_URL", f"http://{host}:{port}")

    mod = importlib.import_module(name)
    mod.mcp.settings.host = host
    mod.mcp.settings.port = port
    base_app = mod.mcp.streamable_http_app()

    # Unauthenticated liveness route for load balancers / k8s probes. protect()
    # only guards the MCP path, so any other path (this one) passes through.
    async def _healthz(request):
        return PlainTextResponse("ok")
    base_app.router.routes.append(Route("/healthz", _healthz, methods=["GET"]))

    app = protect(base_app, issuer=issuer, resource=resource,
                  protected_path=mod.mcp.settings.streamable_http_path)

    print(f"Serving {name} at http://{host}:{port}{mod.mcp.settings.streamable_http_path} "
          f"(protected; issuer={issuer})", flush=True)
    uvicorn.run(app, host=host, port=port, log_level="warning",
                lifespan="on")


if __name__ == "__main__":
    main()

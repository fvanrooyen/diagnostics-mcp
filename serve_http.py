#!/usr/bin/env python3
"""
Run any of the troubleshooting MCP servers over HTTP (streamable-http transport)
instead of stdio, so it can be hosted centrally and reached over the network.

Each server file exposes a FastMCP instance named `mcp`; this imports the chosen
one and serves it.

Usage:
    python serve_http.py dns_server 8001
    HOST=0.0.0.0 python serve_http.py troubleshoot_server 8007

The MCP endpoint is served at <host>:<port>/mcp .

SECURITY: these servers run nmap / tshark / arp-scan. An open, unauthenticated
HTTP endpoint is effectively a remote network-scanner anyone can drive. Only bind
to 0.0.0.0 / expose publicly behind authentication (see the hosting notes). For
local testing, the default 127.0.0.1 is safe.
"""

import importlib
import os
import sys

SERVERS = {
    "dns_server", "netdiag_server", "tls_server", "http_server",
    "nmap_server", "tshark_server", "troubleshoot_server",
}


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in SERVERS:
        print("Usage: python serve_http.py <server> [port]")
        print("Servers:", ", ".join(sorted(SERVERS)))
        sys.exit(1)

    name = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "127.0.0.1")

    mod = importlib.import_module(name)
    mod.mcp.settings.host = host
    mod.mcp.settings.port = port
    path = mod.mcp.settings.streamable_http_path
    print(f"Serving {name} at http://{host}:{port}{path} (Ctrl-C to stop)", flush=True)
    mod.mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
DNS troubleshooting MCP server.

Wraps dig (and whois) so you can chase resolution problems in plain language:
forward/reverse lookups, specific record types, delegation tracing, and querying
a specific resolver — with the answer section parsed into structured records.

Requires: dnsutils (dig), whois.  None of these need root.
"""

import json
import shutil
import subprocess
from typing import Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("dns")

DIG = shutil.which("dig") or "dig"
WHOIS = shutil.which("whois") or "whois"
COMMON_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


def _run(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", f"timed out after {timeout}s")


def _parse_answer(text: str) -> list[dict]:
    """Parse `dig +noall +answer` lines into records."""
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(maxsplit=4)  # name ttl class type rdata
        if len(parts) == 5:
            records.append({
                "name": parts[0], "ttl": int(parts[1]) if parts[1].isdigit() else parts[1],
                "class": parts[2], "type": parts[3], "data": parts[4],
            })
    return records


@mcp.tool()
def dns_lookup(name: str, record_type: str = "A",
               server: Optional[str] = None, timeout: int = 15) -> str:
    """Look up DNS records for a name.

    Args:
        name: Hostname/domain to resolve, e.g. "example.com".
        record_type: A, AAAA, MX, NS, TXT, SOA, CNAME, CAA, SRV, PTR, ANY...
        server: Optional resolver to query, e.g. "8.8.8.8" or "1.1.1.1".
                Omit to use the system resolver.
        timeout: Max seconds.
    """
    cmd = [DIG, "+noall", "+answer", "+comments", name, record_type]
    if server:
        cmd.append(f"@{server}")
    proc = _run(cmd, timeout)
    if proc is None:
        return json.dumps({"error": "dig not found. Install dnsutils."})
    answer = _parse_answer(proc.stdout)
    return json.dumps({
        "query": {"name": name, "type": record_type, "server": server or "system"},
        "answer_count": len(answer),
        "records": answer,
        "raw": proc.stdout.strip() if not answer else None,
    }, indent=2)


@mcp.tool()
def reverse_dns(ip: str, server: Optional[str] = None, timeout: int = 15) -> str:
    """Reverse-lookup the PTR record(s) for an IP address (dig -x).

    Args:
        ip: IPv4 or IPv6 address.
        server: Optional resolver to query.
    """
    cmd = [DIG, "+noall", "+answer", "-x", ip]
    if server:
        cmd.append(f"@{server}")
    proc = _run(cmd, timeout)
    if proc is None:
        return json.dumps({"error": "dig not found. Install dnsutils."})
    return json.dumps({"ip": ip, "records": _parse_answer(proc.stdout)}, indent=2)


@mcp.tool()
def dns_all_records(name: str, server: Optional[str] = None) -> str:
    """Query the common record types (A, AAAA, MX, NS, TXT, SOA, CNAME) at once.

    Handy first-look at "what does this domain actually have configured."

    Args:
        name: Domain to inspect.
        server: Optional resolver to query.
    """
    out = {}
    for rt in COMMON_TYPES:
        cmd = [DIG, "+noall", "+answer", name, rt]
        if server:
            cmd.append(f"@{server}")
        proc = _run(cmd, 15)
        if proc is None:
            return json.dumps({"error": "dig not found. Install dnsutils."})
        out[rt] = _parse_answer(proc.stdout)
    return json.dumps({"name": name, "records_by_type": out}, indent=2)


@mcp.tool()
def dns_trace(name: str, record_type: str = "A") -> str:
    """Trace the delegation path from the root servers down (dig +trace).

    Use when you suspect a delegation/NS problem rather than a simple lookup miss.

    Args:
        name: Domain to trace.
        record_type: Record type to resolve at the end of the trace.
    """
    proc = _run([DIG, "+trace", "+nodnssec", name, record_type], 45)
    if proc is None:
        return json.dumps({"error": "dig not found. Install dnsutils."})
    return json.dumps({"name": name, "type": record_type,
                       "trace": proc.stdout.strip()}, indent=2)


@mcp.tool()
def whois_lookup(query: str, timeout: int = 30) -> str:
    """WHOIS lookup for a domain or IP (registration / ownership info).

    Args:
        query: Domain name or IP address.
    """
    proc = _run([WHOIS, query], timeout)
    if proc is None:
        return json.dumps({"error": "whois not found. Install whois."})
    return json.dumps({"query": query, "result": proc.stdout.strip()}, indent=2)


if __name__ == "__main__":
    mcp.run()

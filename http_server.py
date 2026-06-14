#!/usr/bin/env python3
"""
HTTP diagnostics MCP server.

For "what's this endpoint actually doing": status codes, headers, redirect chains,
and a full per-phase timing breakdown (DNS / connect / TLS / time-to-first-byte /
total) pulled straight from curl's own metrics. Plus optional server fingerprinting
with whatweb and WAF detection with wafw00f.

Requires: curl (timing/headers). whatweb and wafw00f are optional.
"""

import json
import os
import shutil
import subprocess
import tempfile

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("http")

CURL = shutil.which("curl") or "curl"
WHATWEB = shutil.which("whatweb") or "whatweb"
WAFW00F = shutil.which("wafw00f") or "wafw00f"


def _parse_headers(raw: str) -> list[dict]:
    """Split curl -D output into per-response header blocks (handles redirects)."""
    blocks = []
    current = None
    for line in raw.splitlines():
        if line.startswith("HTTP/"):
            if current:
                blocks.append(current)
            current = {"status_line": line.strip(), "headers": {}}
        elif ":" in line and current is not None:
            k, _, v = line.partition(":")
            current["headers"][k.strip()] = v.strip()
    if current:
        blocks.append(current)
    return blocks


@mcp.tool()
def http_request(url: str, method: str = "GET", headers: str | None = None,
                 follow_redirects: bool = True, max_time: int = 30,
                 body_limit: int = 2000, insecure: bool = False) -> str:
    """Make an HTTP request and return status, headers, timing breakdown, and body.

    The timing breakdown (dns/connect/tls/ttfb/total, in seconds) is the most
    useful part for troubleshooting slow endpoints.

    Args:
        url: Full URL including scheme.
        method: HTTP method (GET, HEAD, POST, ...).
        headers: Optional request headers, newline-separated "Key: Value" pairs.
        follow_redirects: Follow 3xx redirects (-L) and report each hop.
        max_time: Overall timeout in seconds.
        body_limit: Max characters of response body to return.
        insecure: If true, skip TLS verification (-k) — for debugging bad certs.
    """
    body_file = tempfile.NamedTemporaryFile(delete=False, suffix=".body")
    body_file.close()
    cmd = [CURL, "-sS", "-X", method, "-D", "-", "-o", body_file.name,
           "--max-time", str(max_time), "-w", "\n__CURL_METRICS__%{json}"]
    if follow_redirects:
        cmd.append("-L")
    if insecure:
        cmd.append("-k")
    if headers:
        for h in headers.splitlines():
            if h.strip():
                cmd += ["-H", h.strip()]
    cmd.append(url)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=max_time + 10, check=False)
    except FileNotFoundError:
        os.unlink(body_file.name)
        return json.dumps({"error": "curl not found."})
    except subprocess.TimeoutExpired:
        os.unlink(body_file.name)
        return json.dumps({"error": f"request timed out after {max_time}s"})

    stdout = proc.stdout
    metrics = {}
    if "__CURL_METRICS__" in stdout:
        head_part, _, metrics_part = stdout.partition("__CURL_METRICS__")
        try:
            m = json.loads(metrics_part.strip())
            metrics = {
                "dns_s": m.get("time_namelookup"),
                "tcp_connect_s": m.get("time_connect"),
                "tls_handshake_s": m.get("time_appconnect"),
                "ttfb_s": m.get("time_starttransfer"),
                "total_s": m.get("time_total"),
                "size_download_bytes": m.get("size_download"),
                "http_version": m.get("http_version"),
                "remote_ip": m.get("remote_ip"),
            }
        except (json.JSONDecodeError, ValueError):
            head_part = stdout
    else:
        head_part = stdout

    try:
        with open(body_file.name, "r", errors="replace") as f:
            body = f.read()
    except OSError:
        body = ""
    finally:
        os.unlink(body_file.name)

    truncated = len(body) > body_limit
    return json.dumps({
        "url": url, "method": method,
        "response_chain": _parse_headers(head_part),
        "stderr": proc.stderr.strip() or None,
        "timing": metrics,
        "body_preview": body[:body_limit],
        "body_truncated": truncated,
    }, indent=2)


@mcp.tool()
def http_headers(url: str, follow_redirects: bool = True, max_time: int = 20,
                 insecure: bool = False) -> str:
    """Fetch just the response headers (HEAD request), including any redirect chain.

    Args:
        url: Full URL.
        follow_redirects: Follow and report 3xx hops.
        max_time: Timeout in seconds.
        insecure: Skip TLS verification.
    """
    cmd = [CURL, "-sS", "-I", "-D", "-", "-o", os.devnull, "--max-time", str(max_time)]
    if follow_redirects:
        cmd.append("-L")
    if insecure:
        cmd.append("-k")
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=max_time + 10, check=False)
    except FileNotFoundError:
        return json.dumps({"error": "curl not found."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"timed out after {max_time}s"})
    return json.dumps({"url": url,
                       "response_chain": _parse_headers(proc.stdout)}, indent=2)


@mcp.tool()
def whatweb_scan(url: str, timeout: int = 60) -> str:
    """Fingerprint the technologies a web server is running (whatweb).

    Args:
        url: Full URL.
        timeout: Max seconds.
    """
    try:
        proc = subprocess.run([WHATWEB, "--log-json=-", "--no-errors", url],
                              capture_output=True, text=True, timeout=timeout,
                              check=False)
    except FileNotFoundError:
        return json.dumps({"error": "whatweb not found. Install whatweb."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"whatweb timed out after {timeout}s"})
    out = proc.stdout.strip()
    try:
        return json.dumps({"url": url, "result": json.loads(out)}, indent=2)
    except (json.JSONDecodeError, ValueError):
        return json.dumps({"url": url, "result_text": out or proc.stderr.strip()},
                          indent=2)


@mcp.tool()
def wafw00f_scan(url: str, timeout: int = 60) -> str:
    """Detect whether a Web Application Firewall sits in front of a site (wafw00f).

    Args:
        url: Full URL.
        timeout: Max seconds.
    """
    try:
        proc = subprocess.run([WAFW00F, "-o", "-", "-f", "json", url],
                              capture_output=True, text=True, timeout=timeout,
                              check=False)
    except FileNotFoundError:
        return json.dumps({"error": "wafw00f not found. Install wafw00f."})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"wafw00f timed out after {timeout}s"})
    return json.dumps({"url": url,
                       "output": proc.stdout.strip() or proc.stderr.strip()}, indent=2)


if __name__ == "__main__":
    mcp.run()

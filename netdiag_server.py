#!/usr/bin/env python3
"""
Network connectivity / reachability MCP server.

Plain-language wrappers for the "is it up, can I reach it, where does it break"
toolkit: ping, traceroute, mtr, TCP port checks, and local-segment ARP scan.

Notes:
- Port checks use a plain Python socket (no nc-variant guessing), so they behave
  the same everywhere and return precise connect timing.
- ping/traceroute/mtr/arp-scan wrap the system binaries; arp-scan needs root.
"""

import json
import shutil
import socket
import subprocess
import time
from typing import Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("netdiag")

PING = shutil.which("ping") or "ping"
TRACEROUTE = shutil.which("traceroute") or "traceroute"
MTR = shutil.which("mtr") or "mtr"
ARP_SCAN = shutil.which("arp-scan") or "arp-scan"


def _run(cmd: list[str], timeout: int = 60):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", f"timed out after {timeout}s")


@mcp.tool()
def check_port(host: str, port: int, timeout: float = 5.0,
               grab_banner: bool = False) -> str:
    """Check whether a TCP port is open, with precise connect timing.

    Args:
        host: Hostname or IP.
        port: TCP port number.
        timeout: Connection timeout in seconds.
        grab_banner: If true, read up to 256 bytes the service sends on connect.
    """
    result: dict = {"host": host, "port": port}
    start = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        result["open"] = True
        result["connect_ms"] = round((time.perf_counter() - start) * 1000, 1)
        if grab_banner:
            try:
                sock.settimeout(2.0)
                data = sock.recv(256)
                if data:
                    result["banner"] = data.decode("utf-8", "replace").strip()
            except (socket.timeout, OSError):
                result["banner"] = None
    except (socket.timeout, OSError) as e:
        result["open"] = False
        result["error"] = str(e)
    finally:
        if sock:
            sock.close()
    return json.dumps(result, indent=2)


@mcp.tool()
def check_ports(host: str, ports: str, timeout: float = 3.0) -> str:
    """Check several TCP ports on one host at once.

    Args:
        host: Hostname or IP.
        ports: Comma-separated ports, e.g. "22,80,443,3306".
        timeout: Per-port connection timeout in seconds.
    """
    results = []
    for p in ports.split(","):
        p = p.strip()
        if not p.isdigit():
            continue
        port = int(p)
        start = time.perf_counter()
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            results.append({"port": port, "open": True,
                            "connect_ms": round((time.perf_counter() - start) * 1000, 1)})
        except (socket.timeout, OSError):
            results.append({"port": port, "open": False})
    return json.dumps({"host": host, "results": results}, indent=2)


@mcp.tool()
def ping_host(host: str, count: int = 4, timeout: int = 20) -> str:
    """Ping a host and return packet loss / RTT summary.

    Args:
        host: Hostname or IP.
        count: Number of echo requests.
        timeout: Overall max seconds.
    """
    proc = _run([PING, "-c", str(count), host], timeout)
    if proc is None:
        return json.dumps({"error": "ping not found."})
    return json.dumps({"host": host, "count": count, "output": proc.stdout.strip()
                       or proc.stderr.strip()}, indent=2)


@mcp.tool()
def traceroute_host(host: str, max_hops: int = 30, timeout: int = 60) -> str:
    """Trace the network path to a host (per-hop).

    Args:
        host: Hostname or IP.
        max_hops: Maximum TTL / hop count.
        timeout: Max seconds.
    """
    proc = _run([TRACEROUTE, "-m", str(max_hops), host], timeout)
    if proc is None:
        return json.dumps({"error": "traceroute not found."})
    return json.dumps({"host": host, "output": proc.stdout.strip()
                       or proc.stderr.strip()}, indent=2)


@mcp.tool()
def mtr_report(host: str, count: int = 10, timeout: int = 60) -> str:
    """Run mtr and return a combined ping+traceroute report (per-hop loss & latency).

    Args:
        host: Hostname or IP.
        count: Number of cycles to run before reporting.
        timeout: Max seconds.
    """
    # --json gives structured per-hop stats when supported.
    proc = _run([MTR, "--report", "--json", "-c", str(count), host], timeout)
    if proc is None:
        return json.dumps({"error": "mtr not found."})
    out = proc.stdout.strip()
    try:
        return json.dumps({"host": host, "report": json.loads(out)}, indent=2)
    except (json.JSONDecodeError, ValueError):
        # Fall back to plain --report text if --json unsupported.
        proc2 = _run([MTR, "--report", "-c", str(count), host], timeout)
        text = proc2.stdout.strip() if proc2 else out
        return json.dumps({"host": host, "report_text": text}, indent=2)


@mcp.tool()
def arp_scan(target: str = "--localnet", interface: Optional[str] = None,
             timeout: int = 60) -> str:
    """Discover live hosts on the local segment via ARP (needs root).

    Args:
        target: Range like "192.168.1.0/24", or "--localnet" for the local subnet.
        interface: Optional interface, e.g. "eth0".
        timeout: Max seconds.
    """
    cmd = [ARP_SCAN]
    if interface:
        cmd += ["-I", interface]
    cmd.append(target)
    proc = _run(cmd, timeout)
    if proc is None:
        return json.dumps({"error": "arp-scan not found."})
    if proc.returncode != 0 and "denied" in (proc.stderr or "").lower():
        return json.dumps({"error": "arp-scan needs root. Run server with sudo or "
                           "grant cap_net_raw.", "stderr": proc.stderr.strip()})
    return json.dumps({"target": target, "output": proc.stdout.strip()
                       or proc.stderr.strip()}, indent=2)


if __name__ == "__main__":
    mcp.run()

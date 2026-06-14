#!/usr/bin/env python3
"""
nmap MCP server.

Exposes nmap as a set of structured tools so you can describe a scan in plain
language and get parsed, structured results back instead of remembering flags.

This is a thin, transparent wrapper around the local `nmap` binary. It does not
do anything nmap can't already do from your shell — it just maps natural-language
intent to the right options and parses the XML output into JSON.

Notes:
- Some scan types (SYN scan -sS, OS detection -O, many raw-packet options) require
  root. Run the server with sudo, or give nmap capabilities:
      sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
- The default scan type is a TCP connect scan (-sT), which works without root.
- Arguments are passed as a list (never through a shell), so there's no shell
  injection surface from the parameters.
"""

import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("nmap")

NMAP = shutil.which("nmap") or "nmap"
DEFAULT_TIMEOUT = 300  # seconds; bump for big scans

SCAN_TYPE_FLAGS = {
    "connect": "-sT",   # TCP connect, no root needed
    "syn": "-sS",       # SYN/stealth, needs root
    "udp": "-sU",       # UDP, needs root, slow
    "ack": "-sA",       # ACK, firewall mapping, needs root
    "ping": "-sn",      # host discovery only, no port scan
    "null": "-sN",
    "fin": "-sF",
    "xmas": "-sX",
}


def _run_nmap(args: list[str], timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Run nmap with -oX - and return parsed XML as a dict, plus raw stderr."""
    cmd = [NMAP, "-oX", "-"] + args
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        return {"error": "nmap binary not found on PATH. Install nmap first."}
    except subprocess.TimeoutExpired:
        return {"error": f"nmap timed out after {timeout}s", "command": " ".join(cmd)}

    result: dict = {"command": " ".join(cmd)}
    if proc.stderr.strip():
        result["stderr"] = proc.stderr.strip()

    if proc.stdout.strip().startswith("<?xml"):
        result["hosts"] = _parse_xml(proc.stdout)
    else:
        # nmap failed before producing XML (bad args, permission, etc.)
        result["error"] = proc.stdout.strip() or "nmap produced no XML output"
        result["returncode"] = proc.returncode
    return result


def _parse_xml(xml_text: str) -> list[dict]:
    """Turn nmap XML into a compact list of host dicts."""
    root = ET.fromstring(xml_text)
    hosts = []
    for host in root.findall("host"):
        h: dict = {}

        status = host.find("status")
        if status is not None:
            h["state"] = status.get("state")

        addrs = [
            {"addr": a.get("addr"), "type": a.get("addrtype")}
            for a in host.findall("address")
        ]
        if addrs:
            h["addresses"] = addrs

        hostnames = [
            hn.get("name") for hn in host.findall("hostnames/hostname") if hn.get("name")
        ]
        if hostnames:
            h["hostnames"] = hostnames

        ports = []
        for p in host.findall("ports/port"):
            state_el = p.find("state")
            svc_el = p.find("service")
            entry = {
                "port": int(p.get("portid")),
                "protocol": p.get("protocol"),
                "state": state_el.get("state") if state_el is not None else None,
            }
            if svc_el is not None:
                svc = {
                    k: svc_el.get(k)
                    for k in ("name", "product", "version", "extrainfo")
                    if svc_el.get(k)
                }
                if svc:
                    entry["service"] = svc
            # NSE script output attached to the port
            scripts = {
                s.get("id"): s.get("output")
                for s in p.findall("script")
            }
            if scripts:
                entry["scripts"] = scripts
            ports.append(entry)
        if ports:
            h["ports"] = ports

        os_matches = [
            {"name": o.get("name"), "accuracy": o.get("accuracy")}
            for o in host.findall("os/osmatch")
        ]
        if os_matches:
            h["os_matches"] = os_matches

        hosts.append(h)
    return hosts


@mcp.tool()
def nmap_scan(
    targets: str,
    ports: Optional[str] = None,
    scan_type: str = "connect",
    service_detection: bool = False,
    os_detection: bool = False,
    top_ports: Optional[int] = None,
    timing: int = 3,
    scripts: Optional[str] = None,
    extra_args: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """Run an nmap scan and return structured JSON results.

    Args:
        targets: Host(s)/range to scan, e.g. "192.168.1.10", "192.168.1.0/24",
                 "scanme.nmap.org", or "10.0.0.1-50".
        ports: Port spec, e.g. "22", "1-1024", "80,443,8080". Omit for nmap default.
        scan_type: One of connect, syn, udp, ack, ping, null, fin, xmas.
                   "connect" needs no root; syn/udp/ack and most others need root.
        service_detection: Add -sV to identify service/version on open ports.
        os_detection: Add -O for OS fingerprinting (needs root).
        top_ports: Scan the N most common ports instead of a port range.
        timing: Timing template 0-5 (-T0 slow/stealthy .. -T5 fast/aggressive). Default 3.
        scripts: NSE scripts/categories, e.g. "default", "vuln", "http-title".
        extra_args: Any additional raw nmap flags as a string (space-separated).
        timeout: Max seconds to allow the scan to run.
    """
    args: list[str] = []

    flag = SCAN_TYPE_FLAGS.get(scan_type.lower())
    if flag is None:
        return json.dumps(
            {"error": f"Unknown scan_type '{scan_type}'. "
                      f"Valid: {', '.join(SCAN_TYPE_FLAGS)}"}
        )
    args.append(flag)

    if timing in range(0, 6):
        args.append(f"-T{timing}")

    if top_ports:
        args += ["--top-ports", str(top_ports)]
    elif ports:
        args += ["-p", ports]

    if service_detection:
        args.append("-sV")
    if os_detection:
        args.append("-O")
    if scripts:
        args.append(f"--script={scripts}")
    if extra_args:
        args += extra_args.split()

    args += targets.split()

    return json.dumps(_run_nmap(args, timeout=timeout), indent=2)


@mcp.tool()
def nmap_ping_sweep(targets: str, timeout: int = 120) -> str:
    """Discover live hosts on a network without scanning ports (nmap -sn).

    Args:
        targets: Network/range, e.g. "192.168.1.0/24" or "10.0.0.1-254".
        timeout: Max seconds to run.
    """
    return json.dumps(_run_nmap(["-sn", targets], timeout=timeout), indent=2)


@mcp.tool()
def build_nmap_command(
    targets: str,
    ports: Optional[str] = None,
    scan_type: str = "connect",
    service_detection: bool = False,
    os_detection: bool = False,
    top_ports: Optional[int] = None,
    timing: int = 3,
    scripts: Optional[str] = None,
    extra_args: Optional[str] = None,
) -> str:
    """Build the nmap command string WITHOUT running it.

    Useful when you just want the right invocation to paste into a shell, or to
    review before running. Same arguments as nmap_scan.
    """
    args: list[str] = []
    flag = SCAN_TYPE_FLAGS.get(scan_type.lower())
    if flag is None:
        return f"# error: unknown scan_type '{scan_type}'"
    args.append(flag)
    if timing in range(0, 6):
        args.append(f"-T{timing}")
    if top_ports:
        args += ["--top-ports", str(top_ports)]
    elif ports:
        args += ["-p", ports]
    if service_detection:
        args.append("-sV")
    if os_detection:
        args.append("-O")
    if scripts:
        args.append(f"--script={scripts}")
    if extra_args:
        args += extra_args.split()
    args += targets.split()
    return "nmap " + " ".join(args)


@mcp.tool()
def nmap_version() -> str:
    """Return the installed nmap version (and confirm the binary is reachable)."""
    try:
        out = subprocess.run(
            [NMAP, "--version"], capture_output=True, text=True, timeout=10
        )
        return out.stdout.strip() or out.stderr.strip()
    except FileNotFoundError:
        return "nmap binary not found on PATH. Install nmap first."


if __name__ == "__main__":
    mcp.run()

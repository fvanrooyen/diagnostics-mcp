#!/usr/bin/env python3
"""
tshark (Wireshark CLI) MCP server.

Exposes tshark — the command-line engine behind Wireshark — as structured tools
so you can capture and analyze traffic by describing what you want instead of
memorizing capture/display filter syntax and -z statistics options.

This is a transparent wrapper around the local `tshark` binary.

Capture privileges:
- Live capture needs permission to access network interfaces. The clean way on
  Debian/Kali/Ubuntu is to allow non-root capture during install, or run:
      sudo dpkg-reconfigure wireshark-common   # answer "yes"
      sudo usermod -aG wireshark $USER          # then log out/in
  Reading existing .pcap/.pcapng files needs no special privileges.

Filter cheat sheet (so you don't have to remember which is which):
- capture_filter  = BPF syntax, applied while capturing, e.g. "tcp port 443"
- display_filter  = Wireshark syntax, applied after, e.g. "http.request.method == GET"
"""

import json
import shutil
import subprocess
from typing import Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("tshark")

TSHARK = shutil.which("tshark") or "tshark"
DEFAULT_TIMEOUT = 120


def _run(args: list[str], timeout: int = DEFAULT_TIMEOUT) -> dict:
    cmd = [TSHARK] + args
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        return {"error": "tshark binary not found on PATH. Install wireshark/tshark."}
    except subprocess.TimeoutExpired:
        return {"error": f"tshark timed out after {timeout}s", "command": " ".join(cmd)}

    out: dict = {"command": " ".join(cmd)}
    if proc.stdout.strip():
        out["stdout"] = proc.stdout
    if proc.stderr.strip():
        out["stderr"] = proc.stderr.strip()
    if proc.returncode != 0 and not proc.stdout.strip():
        out["returncode"] = proc.returncode
    return out


@mcp.tool()
def list_interfaces() -> str:
    """List capture interfaces tshark can see (tshark -D)."""
    return json.dumps(_run(["-D"], timeout=15), indent=2)


@mcp.tool()
def tshark_capture(
    interface: str,
    duration: int = 10,
    packet_count: Optional[int] = None,
    capture_filter: Optional[str] = None,
    display_filter: Optional[str] = None,
    fields: Optional[str] = None,
    save_to: Optional[str] = None,
    timeout: Optional[int] = None,
) -> str:
    """Capture live traffic on an interface and return a summary.

    Args:
        interface: Interface name from list_interfaces (e.g. "eth0", "wlan0", "1").
        duration: Seconds to capture (autostop). Default 10.
        packet_count: Stop after this many packets instead of/with duration.
        capture_filter: BPF filter applied during capture, e.g. "tcp port 80".
        display_filter: Wireshark display filter applied to results,
                        e.g. "dns" or "http.response.code == 404".
        fields: Comma-separated fields for tabular output, e.g.
                "ip.src,ip.dst,tcp.dstport". If set, returns -T fields output.
        save_to: Optional path to also write the raw capture (.pcapng) for later.
        timeout: Hard timeout; defaults to duration + 15s.
    """
    args = ["-i", interface]
    if capture_filter:
        args += ["-f", capture_filter]
    args += ["-a", f"duration:{duration}"]
    if packet_count:
        args += ["-c", str(packet_count)]
    if save_to:
        args += ["-w", save_to]
    if display_filter:
        args += ["-Y", display_filter]
    if fields:
        args += ["-T", "fields", "-E", "header=y", "-E", "separator=,"]
        for f in fields.split(","):
            args += ["-e", f.strip()]

    eff_timeout = timeout if timeout is not None else duration + 15
    return json.dumps(_run(args, timeout=eff_timeout), indent=2)


@mcp.tool()
def tshark_read_pcap(
    file_path: str,
    display_filter: Optional[str] = None,
    fields: Optional[str] = None,
    limit: int = 100,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """Read and analyze an existing capture file (.pcap / .pcapng).

    Args:
        file_path: Path to the capture file.
        display_filter: Wireshark display filter, e.g. "tcp.flags.syn == 1 && tcp.flags.ack == 0".
        fields: Comma-separated fields for tabular output, e.g.
                "frame.time_relative,ip.src,ip.dst,_ws.col.Protocol,_ws.col.Info".
        limit: Max packets to return (uses -c). Default 100.
        timeout: Max seconds.
    """
    args = ["-r", file_path, "-c", str(limit)]
    if display_filter:
        args += ["-Y", display_filter]
    if fields:
        args += ["-T", "fields", "-E", "header=y", "-E", "separator=,"]
        for f in fields.split(","):
            args += ["-e", f.strip()]
    return json.dumps(_run(args, timeout=timeout), indent=2)


@mcp.tool()
def tshark_protocol_hierarchy(file_path: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Show the protocol hierarchy / breakdown of a capture (-z io,phs).

    Great first look at "what's actually in this pcap" — protocols, packet and
    byte counts per layer.

    Args:
        file_path: Path to the .pcap/.pcapng file.
    """
    return json.dumps(
        _run(["-r", file_path, "-q", "-z", "io,phs"], timeout=timeout), indent=2
    )


@mcp.tool()
def tshark_conversations(
    file_path: str,
    proto: str = "tcp",
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """Show conversation statistics (who talked to whom, how much).

    Args:
        file_path: Path to the capture file.
        proto: Conversation type: tcp, udp, ip, eth, etc. Default tcp.
    """
    return json.dumps(
        _run(["-r", file_path, "-q", "-z", f"conv,{proto}"], timeout=timeout), indent=2
    )


@mcp.tool()
def tshark_endpoints(
    file_path: str,
    proto: str = "ip",
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """Show endpoint statistics (per-host traffic totals).

    Args:
        file_path: Path to the capture file.
        proto: Endpoint type: ip, ipv6, tcp, udp, eth. Default ip.
    """
    return json.dumps(
        _run(["-r", file_path, "-q", "-z", f"endpoints,{proto}"], timeout=timeout),
        indent=2,
    )


@mcp.tool()
def tshark_expert_info(file_path: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Show Wireshark "expert info" — warnings, errors, retransmissions, resets, etc.

    Very useful for troubleshooting: surfaces TCP retransmissions, duplicate ACKs,
    zero windows, malformed packets and similar red flags.

    Args:
        file_path: Path to the capture file.
    """
    return json.dumps(
        _run(["-r", file_path, "-q", "-z", "expert"], timeout=timeout), indent=2
    )


@mcp.tool()
def tshark_version() -> str:
    """Return the installed tshark version (and confirm the binary is reachable)."""
    try:
        out = subprocess.run(
            [TSHARK, "--version"], capture_output=True, text=True, timeout=10
        )
        return (out.stdout or out.stderr).splitlines()[0] if (out.stdout or out.stderr) else "unknown"
    except FileNotFoundError:
        return "tshark binary not found on PATH. Install wireshark/tshark."


if __name__ == "__main__":
    mcp.run()

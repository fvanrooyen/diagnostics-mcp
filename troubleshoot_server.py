#!/usr/bin/env python3
"""
Diagnostic orchestration MCP server.

Symptom-first troubleshooting. Instead of running one probe at a time, these tools
chain the right sequence of checks for a given complaint, analyze the combined
results, and return structured FINDINGS — each with a severity and a likely cause —
plus the raw evidence behind them.

The intent: you describe the problem ("the site is slow", "I can't reach the DB",
"DNS seems broken", "capture and tell me what's wrong on this interface") and the
assistant picks the workflow, runs it, and explains what it found.

Self-contained: it implements the primitives it needs directly (socket connects,
Python ssl + cryptography for certs, curl for HTTP timing, dig/tshark when present)
so it works without the other servers installed, though it pairs well with them.

Findings use severity: "critical" (almost certainly the problem) >
"warning" (worth attention) > "info" > "ok".
"""

import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import os
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("troubleshoot")

CURL = shutil.which("curl") or "curl"
DIG = shutil.which("dig")
TSHARK = shutil.which("tshark")
MTR = shutil.which("mtr")
TRACEROUTE = shutil.which("traceroute")


# ----------------------------- primitives ---------------------------------

def _resolve(host: str):
    """Resolve a hostname to its IP addresses via the system resolver."""
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return ips, None
    except socket.gaierror as e:
        return [], str(e)


def _tcp_timing(host: str, port: int, timeout: float = 5.0):
    """Return (open: bool, connect_ms: float|None, error: str|None)."""
    start = time.perf_counter()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True, round((time.perf_counter() - start) * 1000, 1), None
    except (socket.timeout, OSError) as e:
        return False, None, str(e)


def _fetch_cert(host: str, port: int, timeout: float = 8.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=True), ssock.version()


def _hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*."):
            # wildcard matches exactly one label
            suffix = n[1:]  # ".example.com"
            if host.endswith(suffix) and host[: -len(suffix)].count(".") == 0:
                return True
    return False


def _curl_metrics(url: str, max_time: int = 20, insecure: bool = False):
    """Return (metrics dict, status_lines list, error str|None)."""
    cmd = [CURL, "-sS", "-L", "-o", os.devnull, "-D", "-",
           "--max-time", str(max_time), "-w", "\n__M__%{json}"]
    if insecure:
        cmd.append("-k")
    cmd.append(url)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=max_time + 10, check=False)
    except FileNotFoundError:
        return {}, [], "curl not found"
    except subprocess.TimeoutExpired:
        return {}, [], f"timed out after {max_time}s"
    head, _, mjson = proc.stdout.partition("__M__")
    status_lines = [l.strip() for l in head.splitlines() if l.startswith("HTTP/")]
    metrics = {}
    try:
        m = json.loads(mjson.strip())
        metrics = {
            "dns_s": m.get("time_namelookup"),
            "tcp_connect_s": m.get("time_connect"),
            "tls_handshake_s": m.get("time_appconnect"),
            "ttfb_s": m.get("time_starttransfer"),
            "total_s": m.get("time_total"),
            "http_code": m.get("http_code"),
            "redirect_count": m.get("num_redirects"),
            "remote_ip": m.get("remote_ip"),
        }
    except (json.JSONDecodeError, ValueError):
        pass
    return metrics, status_lines, (proc.stderr.strip() or None)


def _finding(severity: str, check: str, message: str) -> dict:
    return {"severity": severity, "check": check, "message": message}


def _verdict(findings: list[dict]) -> str:
    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    if not findings:
        return "no findings"
    worst = min(findings, key=lambda f: order.get(f["severity"], 9))
    return f"{worst['severity']}: {worst['message']}"


# ----------------------------- workflows -----------------------------------

@mcp.tool()
def diagnose_website(url: str, slow_threshold_s: float = 1.0,
                     cert_warn_days: int = 14) -> str:
    """Full end-to-end diagnosis of a website / HTTP(S) endpoint.

    Runs DNS resolution -> TCP connect -> TLS cert inspection -> HTTP request with
    a per-phase timing breakdown, then analyzes the chain and reports findings with
    likely causes. Use for "the site is down / slow / showing cert errors".

    Args:
        url: Full URL, e.g. "https://example.com" or "https://example.com/health".
        slow_threshold_s: Flag a phase/total slower than this (seconds).
        cert_warn_days: Warn if the TLS cert expires within this many days.
    """
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = parsed.hostname
    scheme = parsed.scheme or "https"
    port = parsed.port or (443 if scheme == "https" else 80)
    findings: list[dict] = []
    evidence: dict = {"url": url, "host": host, "port": port, "scheme": scheme}

    if not host:
        return json.dumps({"error": "could not parse a hostname from url"}, indent=2)

    # 1. DNS
    ips, dns_err = _resolve(host)
    evidence["dns"] = {"resolved_ips": ips, "error": dns_err}
    if dns_err or not ips:
        findings.append(_finding("critical", "dns",
            f"DNS resolution failed for {host} ({dns_err}). "
            "Nothing else can work until the name resolves."))
        return json.dumps({"verdict": _verdict(findings), "findings": findings,
                           "evidence": evidence}, indent=2)
    findings.append(_finding("ok", "dns", f"{host} resolves to {', '.join(ips)}"))

    # 2. TCP connect
    is_open, connect_ms, tcp_err = _tcp_timing(host, port)
    evidence["tcp"] = {"open": is_open, "connect_ms": connect_ms, "error": tcp_err}
    if not is_open:
        findings.append(_finding("critical", "tcp",
            f"TCP connect to {host}:{port} failed ({tcp_err}). "
            "The name resolves but nothing is accepting connections — service down, "
            "wrong port, or a firewall is blocking you."))
        return json.dumps({"verdict": _verdict(findings), "findings": findings,
                           "evidence": evidence}, indent=2)
    findings.append(_finding("ok", "tcp", f"TCP connect OK ({connect_ms} ms)"))

    # 3. TLS (https only)
    if scheme == "https":
        try:
            der, proto = _fetch_cert(host, port)
            cert = x509.load_der_x509_certificate(der)
            not_after = cert.not_valid_after_utc
            days_left = (not_after - datetime.now(timezone.utc)).days
            sans = []
            try:
                ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass
            evidence["tls"] = {"protocol": proto, "not_after": not_after.isoformat(),
                               "days_until_expiry": days_left, "sans": sans}
            if days_left < 0:
                findings.append(_finding("critical", "tls",
                    f"Certificate EXPIRED {abs(days_left)} days ago. "
                    "Browsers will refuse to connect."))
            elif days_left < cert_warn_days:
                findings.append(_finding("warning", "tls",
                    f"Certificate expires in {days_left} days — renew soon."))
            else:
                findings.append(_finding("ok", "tls",
                    f"Certificate valid for {days_left} more days."))
            if not _hostname_matches(host, sans):
                findings.append(_finding("warning", "tls",
                    f"Hostname {host} not in certificate SANs {sans} — "
                    "name mismatch will cause trust errors."))
            if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
                findings.append(_finding("warning", "tls",
                    f"Server negotiated deprecated {proto}."))
        except (socket.timeout, OSError, ssl.SSLError, ValueError) as e:
            evidence["tls"] = {"error": str(e)}
            findings.append(_finding("critical", "tls",
                f"TLS handshake failed: {e}"))

    # 4. HTTP request + timing
    metrics, status_lines, http_err = _curl_metrics(url, insecure=True)
    evidence["http"] = {"status_lines": status_lines, "metrics": metrics,
                        "error": http_err}
    if metrics:
        code = metrics.get("http_code")
        if isinstance(code, int):
            if code >= 500:
                findings.append(_finding("critical", "http",
                    f"Server returned {code} — the server itself is erroring."))
            elif code >= 400:
                findings.append(_finding("warning", "http",
                    f"Server returned {code} — client/request-level problem."))
            elif 300 <= code < 400:
                findings.append(_finding("info", "http", f"Final status {code} (redirect)."))
            else:
                findings.append(_finding("ok", "http", f"Final status {code}."))
        if (metrics.get("redirect_count") or 0) >= 5:
            findings.append(_finding("warning", "http",
                f"{metrics['redirect_count']} redirects — possible redirect loop."))
        # locate the slow phase
        total = metrics.get("total_s") or 0
        if total >= slow_threshold_s:
            dns_t = metrics.get("dns_s") or 0
            conn_t = (metrics.get("tcp_connect_s") or 0) - dns_t
            tls_t = (metrics.get("tls_handshake_s") or 0) - (metrics.get("tcp_connect_s") or 0)
            server_t = (metrics.get("ttfb_s") or 0) - (metrics.get("tls_handshake_s") or metrics.get("tcp_connect_s") or 0)
            phases = {"DNS": dns_t, "TCP connect": conn_t,
                      "TLS handshake": tls_t, "server processing (TTFB)": server_t}
            worst = max(phases, key=lambda k: phases[k])
            findings.append(_finding("warning", "http",
                f"Slow: {total:.2f}s total, dominated by {worst} "
                f"({phases[worst]:.2f}s)."))
        else:
            findings.append(_finding("ok", "http", f"Response time {total:.2f}s."))
    elif http_err:
        findings.append(_finding("warning", "http", f"HTTP probe issue: {http_err}"))

    return json.dumps({"verdict": _verdict(findings), "findings": findings,
                       "evidence": evidence}, indent=2)


@mcp.tool()
def diagnose_connectivity(host: str, port: int | None = None,
                          timeout: float = 5.0) -> str:
    """Diagnose reachability to a host: resolve -> connect -> trace the path.

    Use for "I can't reach X" / "is the DB/server up". If a port is given, tests
    that specific service; otherwise just tests host reachability and path.

    Args:
        host: Hostname or IP.
        port: Optional TCP port to test (e.g. 5432, 22, 443).
        timeout: Per-probe timeout in seconds.
    """
    findings: list[dict] = []
    evidence: dict = {"host": host, "port": port}

    ips, dns_err = _resolve(host)
    evidence["dns"] = {"resolved_ips": ips, "error": dns_err}
    if dns_err or not ips:
        findings.append(_finding("critical", "dns",
            f"Cannot resolve {host} ({dns_err})."))
        return json.dumps({"verdict": _verdict(findings), "findings": findings,
                           "evidence": evidence}, indent=2)
    findings.append(_finding("ok", "dns", f"Resolves to {', '.join(ips)}"))

    if port is not None:
        is_open, connect_ms, tcp_err = _tcp_timing(host, port, timeout)
        evidence["tcp"] = {"open": is_open, "connect_ms": connect_ms, "error": tcp_err}
        if is_open:
            findings.append(_finding("ok", "tcp",
                f"Port {port} open ({connect_ms} ms)."))
        else:
            findings.append(_finding("critical", "tcp",
                f"Port {port} not reachable ({tcp_err}). Service down or filtered."))

    # path trace (best-effort; needs mtr or traceroute)
    if MTR:
        try:
            p = subprocess.run([MTR, "--report", "--json", "-c", "5", host],
                              capture_output=True, text=True, timeout=40, check=False)
            try:
                evidence["path"] = json.loads(p.stdout)
            except (json.JSONDecodeError, ValueError):
                evidence["path_text"] = p.stdout.strip()
        except subprocess.TimeoutExpired:
            evidence["path_text"] = "mtr timed out"
    elif TRACEROUTE:
        try:
            p = subprocess.run([TRACEROUTE, "-m", "20", host],
                              capture_output=True, text=True, timeout=40, check=False)
            evidence["path_text"] = p.stdout.strip()
        except subprocess.TimeoutExpired:
            evidence["path_text"] = "traceroute timed out"
    else:
        findings.append(_finding("info", "path",
            "Install mtr or traceroute for path analysis."))

    return json.dumps({"verdict": _verdict(findings), "findings": findings,
                       "evidence": evidence}, indent=2)


@mcp.tool()
def diagnose_dns(domain: str, expect_mail: bool = False) -> str:
    """Check a domain's DNS health: presence of A/AAAA/NS, optional MX, and delegation.

    Uses dig when available (richer), else falls back to the system resolver.

    Args:
        domain: Domain to check, e.g. "example.com".
        expect_mail: If true, flag the absence of MX records as a problem.
    """
    findings: list[dict] = []
    evidence: dict = {"domain": domain}

    if DIG:
        def q(rt):
            p = subprocess.run([DIG, "+noall", "+answer", domain, rt],
                              capture_output=True, text=True, timeout=15, check=False)
            return [l for l in p.stdout.splitlines() if l.strip()
                    and not l.startswith(";")]
        a = q("A"); aaaa = q("AAAA"); ns = q("NS"); mx = q("MX")
        evidence["records"] = {"A": a, "AAAA": aaaa, "NS": ns, "MX": mx}
        if not a and not aaaa:
            findings.append(_finding("critical", "address",
                "No A or AAAA records — the domain points nowhere."))
        else:
            findings.append(_finding("ok", "address",
                f"{len(a)} A and {len(aaaa)} AAAA record(s)."))
        if not ns:
            findings.append(_finding("warning", "ns", "No NS records returned."))
        else:
            findings.append(_finding("ok", "ns", f"{len(ns)} nameserver(s)."))
        if expect_mail and not mx:
            findings.append(_finding("warning", "mx",
                "expect_mail set but no MX records — mail won't be delivered."))
    else:
        ips, err = _resolve(domain)
        evidence["resolved_ips"] = ips
        if err or not ips:
            findings.append(_finding("critical", "address",
                f"System resolver could not resolve {domain} ({err})."))
        else:
            findings.append(_finding("ok", "address",
                f"Resolves to {', '.join(ips)} (install dig for record-level detail)."))

    return json.dumps({"verdict": _verdict(findings), "findings": findings,
                       "evidence": evidence}, indent=2)


# Per-packet fields pulled in a single tshark pass (separator '|').
_PKT_FIELDS = [
    "frame.number", "frame.len", "ip.src", "ip.dst", "tcp.stream",
    "_ws.col.Protocol", "tcp.analysis.retransmission",
    "tcp.analysis.duplicate_ack", "tcp.analysis.zero_window",
    "tcp.flags.reset", "tcp.analysis.out_of_order",
]

# Default severity thresholds. All are overridable per call so you can tune for
# a noisy link (where some retransmission is normal) vs. a quiet one.
DEFAULT_THRESHOLDS = {
    "retransmission_warn_pct": 2.0,   # % of TCP packets
    "retransmission_crit_pct": 5.0,
    "dup_ack_warn_pct": 2.0,
    "reset_warn_pct": 2.0,
    "zero_window_warn_count": 1,      # any zero-window is worth a look by default
    "out_of_order_warn_pct": 1.0,
    "conversation_retrans_warn_pct": 5.0,  # flag a single conversation this bad
}


def _truthy(v: str) -> bool:
    return bool(v) and v not in ("0", "false", "False")


def _pct(n: int, d: int) -> float:
    return round(n / d * 100, 2) if d else 0.0


def _analyze_pcap_file(pcap_path: str, thresholds: dict,
                       display_filter: str | None = None,
                       max_packets: int | None = None, top_n: int = 5):
    """Single-pass quantified analysis of a capture file.

    Returns (result_dict, error_str). Counts loss/reset/window signals, computes
    rates against tunable thresholds, ranks the top protocols and talkers, and —
    the useful bit for a big capture — identifies which conversations carry the
    problems instead of just saying "retransmissions exist somewhere".
    """
    if not TSHARK:
        return None, "tshark not found. Install wireshark/tshark."
    cmd = [TSHARK, "-r", pcap_path, "-T", "fields",
           "-E", "separator=|", "-E", "occurrence=f"]
    for f in _PKT_FIELDS:
        cmd += ["-e", f]
    if display_filter:
        cmd += ["-Y", display_filter]
    if max_packets:
        cmd += ["-c", str(max_packets)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=300, check=False)
    except subprocess.TimeoutExpired:
        return None, "tshark analysis timed out (try a display_filter or max_packets)"
    if p.returncode != 0 and not p.stdout.strip():
        return None, (p.stderr.strip() or "tshark could not read the capture")

    total = tcp_total = retrans = dupack = zerowin = resets = ooo = 0
    proto = Counter()
    talker_bytes = Counter()
    stream_pkts = Counter()
    stream_retrans = Counter()
    stream_endpoints: dict[str, tuple[str, str]] = {}

    for line in p.stdout.splitlines():
        if not line:
            continue
        f = line.split("|")
        if len(f) < len(_PKT_FIELDS):
            f += [""] * (len(_PKT_FIELDS) - len(f))
        total += 1
        flen, src, dst, stream, pr = f[1], f[2], f[3], f[4], f[5]
        if pr:
            proto[pr] += 1
        if src and flen.isdigit():
            talker_bytes[src] += int(flen)
        if stream != "":
            tcp_total += 1
            stream_pkts[stream] += 1
            stream_endpoints.setdefault(stream, (src, dst))
        if _truthy(f[6]):
            retrans += 1
            stream_retrans[stream] += 1
        if _truthy(f[7]):
            dupack += 1
        if _truthy(f[8]):
            zerowin += 1
        if f[9] == "1":
            resets += 1
        if _truthy(f[10]):
            ooo += 1

    t = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    findings: list[dict] = []

    retrans_pct = _pct(retrans, tcp_total)
    if retrans_pct >= t["retransmission_crit_pct"]:
        findings.append(_finding("critical", "loss",
            f"{retrans_pct}% of TCP packets are retransmissions ({retrans}/{tcp_total}). "
            "That's heavy packet loss — suspect the path, a saturated link, or a "
            "failing NIC/cable."))
    elif retrans_pct >= t["retransmission_warn_pct"]:
        findings.append(_finding("warning", "loss",
            f"{retrans_pct}% TCP retransmissions ({retrans}/{tcp_total}) — some loss."))
    elif tcp_total:
        findings.append(_finding("ok", "loss",
            f"Retransmissions low ({retrans_pct}%)."))

    zw_threshold = t["zero_window_warn_count"]
    if zerowin >= zw_threshold and zerowin > 0:
        findings.append(_finding("warning", "flow-control",
            f"{zerowin} TCP zero-window events — a receiver ran out of buffer and "
            "told the sender to stop. Usually an overloaded/slow endpoint."))

    reset_pct = _pct(resets, tcp_total)
    if reset_pct >= t["reset_warn_pct"] and resets > 0:
        findings.append(_finding("warning", "resets",
            f"{resets} RST packets ({reset_pct}% of TCP) — connections being "
            "actively refused or abruptly torn down. Check the service and firewall."))

    dup_pct = _pct(dupack, tcp_total)
    if dup_pct >= t["dup_ack_warn_pct"] and dupack > 0:
        findings.append(_finding("warning", "loss",
            f"{dup_pct}% duplicate ACKs ({dupack}) — corroborates loss/reordering."))

    ooo_pct = _pct(ooo, tcp_total)
    if ooo_pct >= t["out_of_order_warn_pct"] and ooo > 0:
        findings.append(_finding("info", "ordering",
            f"{ooo_pct}% out-of-order segments — path may be load-balancing across links."))

    # Pinpoint the worst conversation — the payoff for a large capture.
    worst = []
    for stream, rcount in stream_retrans.most_common(top_n):
        if rcount == 0:
            continue
        pkts = stream_pkts.get(stream, 0)
        src, dst = stream_endpoints.get(stream, ("?", "?"))
        spct = _pct(rcount, pkts)
        worst.append({"stream": stream, "endpoints": f"{src} <-> {dst}",
                      "packets": pkts, "retransmissions": rcount,
                      "retrans_pct": spct})
        if spct >= t["conversation_retrans_warn_pct"]:
            findings.append(_finding("warning", "hotspot",
                f"Conversation {src} <-> {dst} is a hotspot: {spct}% retransmissions "
                f"({rcount}/{pkts}). Focus here."))

    if not findings:
        findings.append(_finding("ok", "summary", "No notable loss/reset/window signals."))

    result = {
        "verdict": _verdict(findings),
        "findings": findings,
        "summary": {
            "total_packets": total,
            "tcp_packets": tcp_total,
            "retransmissions": retrans, "retransmission_pct": retrans_pct,
            "duplicate_acks": dupack, "duplicate_ack_pct": dup_pct,
            "zero_windows": zerowin,
            "resets": resets, "reset_pct": reset_pct,
            "out_of_order": ooo, "out_of_order_pct": ooo_pct,
        },
        "top_protocols": dict(proto.most_common(8)),
        "top_talkers_by_bytes": {ip: b for ip, b in talker_bytes.most_common(top_n)},
        "worst_conversations": worst,
        "thresholds_used": t,
    }
    return result, None


@mcp.tool()
def analyze_pcap(file_path: str, display_filter: str | None = None,
                 max_packets: int | None = None,
                 retransmission_warn_pct: float = 2.0,
                 retransmission_crit_pct: float = 5.0,
                 reset_warn_pct: float = 2.0,
                 zero_window_warn_count: int = 1,
                 conversation_retrans_warn_pct: float = 5.0) -> str:
    """Triage an existing capture file: find the problems in a big pcap.

    Quantifies retransmissions, duplicate ACKs, zero-windows, resets and
    out-of-order segments as rates, applies the thresholds below, and pinpoints
    the worst conversation(s) so you don't have to scroll. Use for "here's a
    capture, what's wrong with it."

    Args:
        file_path: Path to a .pcap/.pcapng file.
        display_filter: Optional Wireshark filter to scope analysis (e.g. "ip.addr == 10.0.0.5").
        max_packets: Optionally cap how many packets are read (for very large files).
        retransmission_warn_pct: Warn if TCP retransmissions exceed this % of TCP packets.
        retransmission_crit_pct: Critical if they exceed this %.
        reset_warn_pct: Warn if RST packets exceed this % of TCP packets.
        zero_window_warn_count: Warn if at least this many zero-window events occur.
        conversation_retrans_warn_pct: Flag any single conversation with at least
            this % retransmissions as a hotspot.
    """
    thresholds = {
        "retransmission_warn_pct": retransmission_warn_pct,
        "retransmission_crit_pct": retransmission_crit_pct,
        "reset_warn_pct": reset_warn_pct,
        "zero_window_warn_count": zero_window_warn_count,
        "conversation_retrans_warn_pct": conversation_retrans_warn_pct,
    }
    result, err = _analyze_pcap_file(file_path, thresholds, display_filter, max_packets)
    if err:
        return json.dumps({"file": file_path, "error": err}, indent=2)
    result["file"] = file_path
    return json.dumps(result, indent=2)


@mcp.tool()
def capture_and_analyze(interface: str, duration: int = 15,
                        capture_filter: str | None = None,
                        retransmission_warn_pct: float = 2.0,
                        retransmission_crit_pct: float = 5.0,
                        reset_warn_pct: float = 2.0,
                        zero_window_warn_count: int = 1,
                        conversation_retrans_warn_pct: float = 5.0,
                        keep_capture: bool = False) -> str:
    """Capture live traffic for N seconds, then triage it for problems.

    Runs a timed tshark capture and feeds it through the same quantified analysis
    as analyze_pcap (rates, tunable thresholds, worst-conversation pinpointing).
    Use for "capture on <interface> and tell me what looks wrong."

    Args:
        interface: Capture interface (from list_interfaces / `tshark -D`), e.g. "eth0".
        duration: Seconds to capture.
        capture_filter: Optional BPF capture filter, e.g. "host 10.0.0.5".
        retransmission_warn_pct / retransmission_crit_pct / reset_warn_pct /
            zero_window_warn_count / conversation_retrans_warn_pct: severity tuning,
            same meaning as analyze_pcap.
        keep_capture: If true, leave the .pcapng on disk and return its path for
            deeper manual analysis in Wireshark.
    """
    if not TSHARK:
        return json.dumps({"error": "tshark not found. Install wireshark/tshark."})
    pcap = tempfile.NamedTemporaryFile(delete=False, suffix=".pcapng")
    pcap.close()
    keep = False
    try:
        cap_cmd = [TSHARK, "-i", interface, "-a", f"duration:{duration}", "-w", pcap.name]
        if capture_filter:
            cap_cmd += ["-f", capture_filter]
        cap = subprocess.run(cap_cmd, capture_output=True, text=True,
                            timeout=duration + 20, check=False)
        if cap.returncode != 0 and not os.path.getsize(pcap.name):
            return json.dumps({"error": "capture failed (permissions? wrong interface?)",
                               "stderr": cap.stderr.strip()}, indent=2)
        thresholds = {
            "retransmission_warn_pct": retransmission_warn_pct,
            "retransmission_crit_pct": retransmission_crit_pct,
            "reset_warn_pct": reset_warn_pct,
            "zero_window_warn_count": zero_window_warn_count,
            "conversation_retrans_warn_pct": conversation_retrans_warn_pct,
        }
        result, err = _analyze_pcap_file(pcap.name, thresholds)
        if err:
            return json.dumps({"interface": interface, "error": err}, indent=2)
        result["interface"] = interface
        result["duration_s"] = duration
        if keep_capture:
            keep = True
            result["saved_capture"] = pcap.name
        return json.dumps(result, indent=2)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "capture/analysis timed out"}, indent=2)
    finally:
        if not keep:
            try:
                os.unlink(pcap.name)
            except OSError:
                pass


if __name__ == "__main__":
    mcp.run()

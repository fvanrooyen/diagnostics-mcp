#!/usr/bin/env python3
"""
Multi-agent network-troubleshooting orchestrator.

A lead "triage" agent receives a plain-language symptom, dispatches to specialist
subagents (DNS, reachability, TLS, HTTP, packets) that each own a slice of the MCP
tool suite, then synthesizes their structured findings into one report.

Why subagents instead of one agent with every tool:
- Each specialist runs in its own context window, so the packet specialist can
  grind through a huge capture and hand back just "hotspot: these two IPs" without
  flooding the lead agent's context.
- Specialists can run in parallel (DNS + TLS + HTTP at once).
- Tool access is scoped per specialist, which keeps the agent focused and makes
  the safety boundary explicit.

Built on the Claude Agent SDK (`pip install claude-agent-sdk`). Each MCP server
from this project is registered once at the top level; each subagent is granted
only the servers/tools it needs.

Usage:
    export ANTHROPIC_API_KEY=...            # or a logged-in Claude subscription
    python triage_agent.py "github.example.com throws cert warnings and loads slow"
    python triage_agent.py "analyze /tmp/capture.pcapng — users report timeouts"

Environment:
    MCP_DIR     directory holding the *_server.py files (default: this script's dir)
    MCP_PYTHON  python interpreter for the servers (default: this interpreter)
    TRIAGE_MODEL  model for the lead+specialists (default: claude-opus-4-8)
"""

import asyncio
import os
import sys
from pathlib import Path

from claude_agent_sdk import (
    AgentDefinition,
    AssistantMessage,
    ClaudeAgentOptions,
    PermissionResultAllow,
    PermissionResultDeny,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    query,
)

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

MCP_DIR = Path(os.environ.get("MCP_DIR", Path(__file__).resolve().parent))
MCP_PYTHON = os.environ.get("MCP_PYTHON", sys.executable)
MODEL = os.environ.get("TRIAGE_MODEL", "claude-opus-4-8")


def _server(script: str) -> dict:
    """Build an MCP stdio server config pointing at one of our server scripts."""
    return {"command": MCP_PYTHON, "args": [str(MCP_DIR / script)]}


# Register every server once. Subagents reference these by name.
MCP_SERVERS = {
    "dns": _server("dns_server.py"),
    "netdiag": _server("netdiag_server.py"),
    "tls": _server("tls_server.py"),
    "http": _server("http_server.py"),
    "nmap": _server("nmap_server.py"),
    "tshark": _server("tshark_server.py"),
    "troubleshoot": _server("troubleshoot_server.py"),
}


def _t(server: str, *tools: str) -> list[str]:
    """Fully-qualified MCP tool names: mcp__<server>__<tool>."""
    return [f"mcp__{server}__{name}" for name in tools]


# --------------------------------------------------------------------------
# Specialist subagents — each scoped to its own servers + tools
# --------------------------------------------------------------------------

SPECIALISTS = {
    "dns_specialist": AgentDefinition(
        description="Resolves DNS problems: lookups, reverse DNS, record audits, "
                    "delegation tracing. Use for resolution failures or DNS doubts.",
        prompt=(
            "You are a DNS troubleshooting specialist. Given a domain or symptom, "
            "use your tools to determine whether DNS is healthy: does the name "
            "resolve, are A/AAAA/NS/MX records present and sane, and does the "
            "delegation chain hold. Report findings worst-first with the likely "
            "cause. Be concise; return the structured findings, not raw dumps."
        ),
        mcpServers=["dns", "troubleshoot"],
        tools=_t("dns", "dns_lookup", "reverse_dns", "dns_all_records",
                 "dns_trace", "whois_lookup") + _t("troubleshoot", "diagnose_dns"),
        model=MODEL,
    ),
    "reachability_specialist": AgentDefinition(
        description="Tests whether a host/port is reachable and where the path "
                    "breaks: port checks, ping, traceroute/mtr, scans. Use for "
                    "'can't connect' / 'is it up' / 'where does it drop'.",
        prompt=(
            "You are a network reachability specialist. Determine whether the "
            "target host/service is reachable, how fast it connects, and where on "
            "the path latency or loss appears. Prefer the orchestrator-level "
            "diagnose_connectivity for a quick verdict, then drill into specific "
            "port checks or mtr as needed. Report findings worst-first."
        ),
        mcpServers=["netdiag", "nmap", "troubleshoot"],
        tools=_t("netdiag", "check_port", "check_ports", "ping_host",
                 "traceroute_host", "mtr_report", "arp_scan")
              + _t("nmap", "nmap_ping_sweep", "nmap_scan", "build_nmap_command")
              + _t("troubleshoot", "diagnose_connectivity"),
        model=MODEL,
    ),
    "tls_specialist": AgentDefinition(
        description="Diagnoses TLS/SSL issues: certificate validity, expiry, "
                    "hostname/SAN coverage, protocol & cipher support. Use for "
                    "cert errors or 'is HTTPS configured correctly'.",
        prompt=(
            "You are a TLS/SSL specialist. Inspect the certificate (subject, "
            "issuer, expiry, SAN coverage for the requested hostname) and the "
            "protocols/ciphers the server accepts. Flag expired/expiring certs, "
            "name mismatches, and deprecated protocols. Report findings worst-first."
        ),
        mcpServers=["tls"],
        tools=_t("tls", "tls_cert_info", "tls_check_expiry", "tls_scan"),
        model=MODEL,
    ),
    "http_specialist": AgentDefinition(
        description="Diagnoses HTTP-layer problems: status codes, headers, redirect "
                    "chains, and per-phase timing (DNS/connect/TLS/TTFB). Use for "
                    "'site is slow' or 'returns errors'.",
        prompt=(
            "You are an HTTP diagnostics specialist. Make a request and determine "
            "the status, redirect behavior, and — critically — which phase "
            "(DNS, connect, TLS, or server processing/TTFB) dominates any slowness. "
            "Use diagnose_website for an end-to-end verdict when appropriate. "
            "Report findings worst-first with the likely cause."
        ),
        mcpServers=["http", "troubleshoot"],
        tools=_t("http", "http_request", "http_headers", "whatweb_scan",
                 "wafw00f_scan") + _t("troubleshoot", "diagnose_website"),
        model=MODEL,
    ),
    "packet_specialist": AgentDefinition(
        description="Captures and analyzes packets to find loss, resets, zero "
                    "windows, and the worst conversations in a capture. Use for "
                    "'capture on X and tell me what's wrong' or analyzing a pcap.",
        prompt=(
            "You are a packet-analysis specialist. Capture (or read a given pcap) "
            "and triage it: quantify retransmissions, duplicate ACKs, zero-windows, "
            "and resets as rates, and identify the specific conversation(s) that "
            "carry the problems. Do the heavy lifting here and return only the "
            "summary and the hotspot conversations — not the raw packets. If the "
            "link is known to be busy, raise the severity thresholds accordingly."
        ),
        mcpServers=["tshark", "troubleshoot"],
        tools=_t("tshark", "list_interfaces", "tshark_read_pcap",
                 "tshark_protocol_hierarchy", "tshark_expert_info",
                 "tshark_conversations")
              + _t("troubleshoot", "analyze_pcap", "capture_and_analyze"),
        model=MODEL,
    ),
}


ORCHESTRATOR_PROMPT = """\
You are the lead network-troubleshooting orchestrator. You coordinate specialist
subagents; you do not run probes directly.

When given a symptom:
1. Decide which specialists are relevant. A vague "site is broken" usually needs
   DNS, reachability, TLS, and HTTP; a packet/capture request needs the packet
   specialist; a pure "won't resolve" needs DNS first.
2. Dispatch the relevant specialists (in parallel when their work is independent).
   Give each the specific target and the symptom context.
3. Collect their structured findings and synthesize ONE report:
   - A single-line VERDICT: the most likely root cause, or "all checks pass".
   - FINDINGS worst-first (critical -> warning -> info), each naming the layer
     (dns/tcp/tls/http/packets) and the likely cause in plain language.
   - NEXT STEPS: the concrete action or the deeper probe to run.
4. Do not dump raw tool output. Summarize. Keep it tight and skimmable.

Rules:
- Only probe hosts/networks the user named or that are clearly theirs. If a target
  looks like it isn't theirs, say so and ask before proceeding.
- These are read-only diagnostics. Don't attempt changes or anything intrusive.
- If a specialist reports a tool/binary isn't installed, surface the apt package
  to install rather than treating it as a hard failure.
"""


# --------------------------------------------------------------------------
# Safety: only let agents call our diagnostic MCP tools and subagent dispatch.
# --------------------------------------------------------------------------

ALLOWED_PREFIXES = tuple(f"mcp__{name}__" for name in MCP_SERVERS)
# Built-in tools the lead needs to delegate / plan.
ALLOWED_BUILTINS = {"Task", "TodoWrite"}


async def gate_tools(tool_name: str, tool_input: dict, context):
    """Allowlist callback: permit our diagnostic MCP tools + subagent dispatch,
    deny everything else (Bash, file writes, etc.). Makes the boundary explicit
    so the orchestrator can't wander outside the diagnostic toolset."""
    if tool_name in ALLOWED_BUILTINS or tool_name.startswith(ALLOWED_PREFIXES):
        return PermissionResultAllow(behavior="allow")
    return PermissionResultDeny(
        behavior="deny",
        message=f"{tool_name} is outside the diagnostic toolset and was blocked.",
    )


def build_options() -> ClaudeAgentOptions:
    return ClaudeAgentOptions(
        model=MODEL,
        system_prompt=ORCHESTRATOR_PROMPT,
        mcp_servers=MCP_SERVERS,
        agents=SPECIALISTS,
        can_use_tool=gate_tools,
        permission_mode="default",
        max_turns=40,
    )


# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------

async def run_triage(symptom: str) -> None:
    options = build_options()
    print(f"\n=== Triage: {symptom} ===\n", flush=True)
    async for msg in query(prompt=symptom, options=options):
        if isinstance(msg, AssistantMessage):
            for block in msg.content:
                if isinstance(block, TextBlock) and block.text.strip():
                    # parent_tool_use_id set => this text came from a subagent
                    tag = "  [specialist]" if msg.parent_tool_use_id else "[orchestrator]"
                    print(f"{tag} {block.text}", flush=True)
                elif isinstance(block, ToolUseBlock):
                    print(f"  -> calling {block.name}", flush=True)
        elif isinstance(msg, ResultMessage):
            cost = f" | cost ${msg.total_cost_usd:.4f}" if msg.total_cost_usd else ""
            print(f"\n=== done in {msg.num_turns} turns{cost} ===", flush=True)


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        print('Provide a symptom, e.g.:\n  python triage_agent.py '
              '"api.example.com is slow and may have a cert problem"')
        sys.exit(1)
    symptom = " ".join(sys.argv[1:])
    try:
        asyncio.run(run_triage(symptom))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

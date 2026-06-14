# Network Troubleshooting MCP Servers

A collection of MCP servers that wrap standard network/admin tools so you can drive
them from Claude Desktop in plain language and get structured output back. Each
server is standalone — install only the ones you want.

| Server | Wraps | Use it for |
|--------|-------|-----------|
| `nmap_server.py`    | nmap                        | host discovery, port/service scans, OS detection |
| `tshark_server.py`  | tshark (Wireshark CLI)      | live capture, pcap analysis, retransmits/resets |
| **`troubleshoot_server.py`** | **all of the above (orchestrator)** | **symptom-level diagnosis: chains checks, returns findings** |
| `dns_server.py`     | dig, whois                  | forward/reverse lookups, delegation tracing |
| `netdiag_server.py` | ping, traceroute, mtr, sockets, arp-scan | reachability, latency, open-port checks |
| `tls_server.py`     | Python ssl + cryptography, sslscan | cert details, expiry, protocol/cipher support |
| `http_server.py`    | curl, whatweb, wafw00f      | status/headers, per-phase timing, fingerprinting |

All wrappers pass arguments as lists (never through a shell), so there is no
shell-injection surface from parameters.

---

## 1. Install

```bash
# Binaries (Debian/Kali/Ubuntu) — install what the servers you want need
sudo apt install nmap tshark wireshark-common dnsutils whois \
                 traceroute mtr-tiny arp-scan sslscan whatweb wafw00f

# Python deps in a venv
python3 -m venv ~/mcp/venv
~/mcp/venv/bin/pip install mcp cryptography
```

`cryptography` is only needed by the TLS server (for parsing certs offline so it
works even on expired/mismatched certs). `mcp` is needed by all of them. curl and
openssl are usually already present.

## 2. Privileges

- **nmap**: connect scans need no root; SYN/UDP/OS detection do. Grant once with
  `sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)`.
- **tshark**: reading pcaps needs nothing; live capture needs the `wireshark`
  group (`sudo dpkg-reconfigure wireshark-common`, then `usermod -aG wireshark $USER`).
- **netdiag arp_scan**: needs root / `cap_net_raw`. Everything else in netdiag
  (socket port checks, ping, traceroute, mtr) runs unprivileged.
- **tls / http / dns**: no special privileges.

## 3. Wire into Claude Desktop

Config file:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "nmap":    { "command": "/home/youruser/mcp/venv/bin/python", "args": ["/home/youruser/mcp/nmap_server.py"] },
    "tshark":  { "command": "/home/youruser/mcp/venv/bin/python", "args": ["/home/youruser/mcp/tshark_server.py"] },
    "dns":     { "command": "/home/youruser/mcp/venv/bin/python", "args": ["/home/youruser/mcp/dns_server.py"] },
    "netdiag": { "command": "/home/youruser/mcp/venv/bin/python", "args": ["/home/youruser/mcp/netdiag_server.py"] },
    "tls":     { "command": "/home/youruser/mcp/venv/bin/python", "args": ["/home/youruser/mcp/tls_server.py"] },
    "http":    { "command": "/home/youruser/mcp/venv/bin/python", "args": ["/home/youruser/mcp/http_server.py"] },
    "troubleshoot": { "command": "/home/youruser/mcp/venv/bin/python", "args": ["/home/youruser/mcp/troubleshoot_server.py"] }
  }
}
```

Use absolute paths and fully restart Claude Desktop (quit, don't just close the window).

## 4. Smoke-test a server without Claude

```bash
~/mcp/venv/bin/python -m mcp dev ~/mcp/dns_server.py
```

## 5. Tools at a glance

**troubleshoot** (start here): `diagnose_website`, `diagnose_connectivity`, `diagnose_dns`, `analyze_pcap`, `capture_and_analyze`
**dns**: `dns_lookup`, `reverse_dns`, `dns_all_records`, `dns_trace`, `whois_lookup`
**netdiag**: `check_port`, `check_ports`, `ping_host`, `traceroute_host`, `mtr_report`, `arp_scan`
**tls**: `tls_cert_info`, `tls_check_expiry`, `tls_scan`
**http**: `http_request`, `http_headers`, `whatweb_scan`, `wafw00f_scan`
**nmap**: `nmap_scan`, `nmap_ping_sweep`, `build_nmap_command`, `nmap_version`
**tshark**: `list_interfaces`, `tshark_capture`, `tshark_read_pcap`, `tshark_protocol_hierarchy`, `tshark_conversations`, `tshark_endpoints`, `tshark_expert_info`

## 6. Example asks once connected

- "Why won't mail.example.com resolve? Trace its delegation."  → dns_trace
- "Show me every DNS record example.com has."  → dns_all_records
- "Is port 5432 reachable on db.internal, and how fast does it connect?"  → check_port
- "Where does the path to 1.1.1.1 start dropping packets?"  → mtr_report
- "When does the cert on api.example.com expire and does it cover www?"  → tls_cert_info
- "Is this endpoint slow in DNS, connect, TLS, or the server?"  → http_request (timing)
- "What's running on this web server and is there a WAF?"  → whatweb_scan + wafw00f_scan

## 7. Make Claude reach for these automatically

The `troubleshoot` server is the "I don't want to remember which tool" layer:
its tools are named by *symptom*, chain the right primitives, and return findings
worst-first with likely causes — so "my site is slow" maps cleanly to
`diagnose_website` and you get an analysis, not a wall of output.

To make Claude consistently use the tools instead of describing them, paste
`PROJECT_INSTRUCTIONS.md` into your Claude Project's custom instructions. It gives
Claude the symptom-to-tool map and tells it to run diagnostics and summarize.

### Packet-capture triage & severity tuning

`analyze_pcap` (existing file) and `capture_and_analyze` (live) do a single-pass,
quantified analysis: they count retransmissions, duplicate ACKs, zero-windows,
resets and out-of-order segments, express them as rates, and — the useful part on
a huge capture — rank the **worst conversations** so you jump straight to the
problem endpoints instead of scrolling.

Every threshold is a call parameter, so you can say "treat this as a busy link"
and the agent passes higher cutoffs:
- `retransmission_warn_pct` / `retransmission_crit_pct` (% of TCP packets)
- `reset_warn_pct`, `zero_window_warn_count`, `conversation_retrans_warn_pct`
Permanent defaults live in `DEFAULT_THRESHOLDS` at the top of `troubleshoot_server.py`.
Use `display_filter` / `max_packets` to scope very large files.

Example flow once set up:
> You: "github.example.com is throwing cert warnings in the browser."
> Claude: runs `diagnose_website` -> "Critical: certificate expired 3 days ago.
> Also: SANs don't include the www host. TCP/DNS/HTTP are otherwise fine."


## 8. Multi-agent orchestrator (optional, advanced)

`triage_agent.py` turns the suite into a coordinated multi-agent workflow using
the **Claude Agent SDK**. A lead orchestrator takes a plain symptom, dispatches to
specialist subagents — DNS, reachability, TLS, HTTP, packets — that each own a
slice of the MCP tools, and synthesizes their findings into one verdict.

Why subagents rather than one agent with every tool: each specialist gets its own
context window (the packet specialist can chew through a huge capture and return
just the hotspot), they can run in parallel, and tool access is scoped per
specialist so the boundary is explicit.

Setup:
```bash
pip install claude-agent-sdk            # needs Node.js for the bundled CLI runtime
export ANTHROPIC_API_KEY=...            # or a logged-in Claude subscription
# point it at your servers / interpreter if not co-located:
export MCP_DIR=/home/youruser/mcp MCP_PYTHON=/home/youruser/mcp/venv/bin/python
python triage_agent.py "api.example.com is slow and may have a cert problem"
```

Safety: a `can_use_tool` allowlist permits only this project's diagnostic MCP
tools plus subagent dispatch — `Bash`, file writes, and anything else are denied,
so the orchestrator can't wander outside the toolset. It also runs read-only
diagnostics and is told to only probe hosts you name. Tune specialists by editing
their `AgentDefinition` (description, prompt, scoped tools) in the file.

## Scope

These wrappers act wherever you point them. Scan, capture, and probe only networks
and hosts you own or are authorized to test — the same rule that applies to running
the underlying CLI tools by hand. Extend any server by adding an `@mcp.tool()`
function; its docstring becomes the description Claude reads, so keep it accurate.

## 9. Self-hosted OAuth (authorization server + resource-server auth)

`oauth_server.py` is a standalone OAuth 2.1 Authorization Server implementing
exactly what a Claude connector needs: metadata discovery, Dynamic Client
Registration, PKCE (S256), the authorization-code grant, and refresh-token
rotation. Access tokens are RS256 JWTs published via JWKS, so the MCP servers
validate them statelessly (no shared session store — important on multi-replica
EKS).

`mcp_auth.py` is the resource-server half: an ASGI middleware that validates the
bearer JWT against the AS's JWKS and serves `/.well-known/oauth-protected-resource`,
plus returns the `401 WWW-Authenticate` challenge that kicks off Claude's OAuth
flow. `serve_http_auth.py` runs any server behind it.

```bash
# 1. Authorization server
OAUTH_ISSUER=https://auth.example.com \
OAUTH_USER=me OAUTH_PASSWORD_HASH="$(python oauth_server.py hash 'yourpassword')" \
python oauth_server.py serve 9000

# 2. A protected MCP server (audience = its public URL)
OAUTH_ISSUER=https://auth.example.com RESOURCE_URL=https://dns.example.com \
python serve_http_auth.py dns_server 8001

# 3. In Claude: Add custom connector -> https://dns.example.com/mcp
#    Claude hits 401, discovers the AS, walks the OAuth flow, and connects.
```

Verified end to end: discovery, DCR (public client), PKCE, single-use codes,
refresh rotation, and rejection of every failure path (bad password, wrong PKCE
verifier, code replay, refresh reuse, tampered token).

Production notes: storage is SQLite (swap the `Store` class for Postgres/Redis on
multi-replica EKS); the signing key is generated to disk (mount it from a k8s
Secret); the login is a single configured user (replace with a real user store or
upstream IdP); serve everything over TLS.

## 10. SSH diagnostic runner (closed networks)

`ssh_diag_server.py` reaches a network you can't hit directly: it SSHes to a jump
host, checks for the diagnostic tooling, installs what's missing, and runs probes
there. It is a constrained diagnostic channel — only allowlisted tools run, targets
are pattern-validated, and arguments are shell-quoted (verified against injection).

Tools: `ssh_check_tools`, `ssh_install_tools`, `ssh_provision_and_check` (check →
install missing → re-check), `ssh_run_diagnostic` (run one allowlisted tool against
a validated target). Extend the surface via `TOOL_PACKAGES`.

```bash
export SSH_JUMP_HOST=bastion.internal SSH_JUMP_USER=diag SSH_JUMP_KEY=~/.ssh/diag_ed25519
# (served like any other server, e.g. behind OAuth via serve_http_auth.py ssh_diag_server)
```

Harden the jump host as the module assumes: a dedicated unprivileged user; an SSH
key used only for this (ideally `no-pty,no-port-forwarding` or a ForceCommand
wrapper in authorized_keys); passwordless sudo scoped *only* to the package manager
and diagnostic binaries; host-key verification on (the server rejects unknown host
keys unless SSH_ALLOW_UNKNOWN_HOSTS=1). Packet capture (tshark/tcpdump) must run on
a host with a NIC on the target segment — the jump host is the natural place.

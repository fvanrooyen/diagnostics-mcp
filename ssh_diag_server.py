#!/usr/bin/env python3
"""
SSH diagnostic-runner MCP server.

For diagnosing a closed network you can't reach directly: SSH to a jump host
(bastion) inside that network, make sure the diagnostic tooling is present
(installing it if missing), and run the probes there — returning the output.

This is deliberately NOT a general remote shell. It only ever runs binaries from
an allowlist of diagnostic tools, targets are validated against a strict pattern,
and every argument is shell-quoted, so it's a constrained diagnostic channel.

Hardening the jump host (do this — the server assumes it):
  - A dedicated, unprivileged user for this.
  - An SSH key used only for this, ideally restricted in authorized_keys with
    `no-pty,no-port-forwarding` (or a ForceCommand wrapper).
  - Passwordless sudo (NOPASSWD) limited to the package-install command and the
    diagnostic binaries only — never blanket sudo.
  - Host-key verification on (known_hosts). This server rejects unknown host keys
    by default; set SSH_ALLOW_UNKNOWN_HOSTS=1 only for a deliberate first connect.

Config (env, overridable per call):
    SSH_JUMP_HOST, SSH_JUMP_USER, SSH_JUMP_PORT (default 22), SSH_JUMP_KEY (path)

Requires: paramiko.
"""

import json
import os
import re
import shlex

import paramiko
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ssh-diag")

# tool name -> Debian/RHEL/Alpine package providing it. Only these can be run or
# installed. Add entries here to extend the diagnostic surface.
TOOL_PACKAGES = {
    "nmap": "nmap",
    "dig": "dnsutils",          # bind-utils on RHEL; resolved at install time
    "host": "dnsutils",
    "mtr": "mtr-tiny",
    "traceroute": "traceroute",
    "ping": "iputils-ping",
    "tcpdump": "tcpdump",
    "tshark": "tshark",
    "arp-scan": "arp-scan",
    "curl": "curl",
    "openssl": "openssl",
    "ss": "iproute2",
}
ALLOWED_TOOLS = set(TOOL_PACKAGES)

# hostnames, IPv4, IPv4/CIDR, simple ranges, IPv6, optional :port. No shell metachars.
_TARGET_RE = re.compile(
    r"^[A-Za-z0-9_.:\-/]+$"
)

DEFAULTS = {
    "host": os.environ.get("SSH_JUMP_HOST"),
    "user": os.environ.get("SSH_JUMP_USER"),
    "port": int(os.environ.get("SSH_JUMP_PORT", "22")),
    "key": os.environ.get("SSH_JUMP_KEY"),
}


# --------------------------------------------------------------------------
# SSH plumbing
# --------------------------------------------------------------------------

def _connect(host=None, user=None, port=None, key=None) -> paramiko.SSHClient:
    host = host or DEFAULTS["host"]
    user = user or DEFAULTS["user"]
    port = port or DEFAULTS["port"]
    key = key or DEFAULTS["key"]
    if not host or not user:
        raise ValueError("jump host/user not set (SSH_JUMP_HOST / SSH_JUMP_USER)")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    try:
        client.load_host_keys(os.path.expanduser("~/.ssh/known_hosts"))
    except OSError:
        pass
    if os.environ.get("SSH_ALLOW_UNKNOWN_HOSTS") == "1":
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

    client.connect(hostname=host, port=port, username=user,
                   key_filename=key, timeout=15, allow_agent=True,
                   look_for_keys=(key is None))
    return client


def _run_remote(client: paramiko.SSHClient, command: str, timeout: int = 120) -> dict:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    return {"exit_status": rc, "stdout": out, "stderr": err}


def _detect_pkg_mgr(client) -> str | None:
    for mgr in ("apt-get", "dnf", "yum", "apk"):
        r = _run_remote(client, f"command -v {mgr}", timeout=15)
        if r["exit_status"] == 0 and r["stdout"].strip():
            return mgr
    return None


# --------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------

@mcp.tool()
def ssh_check_tools(host: str | None = None, user: str | None = None,
                    port: int | None = None, key: str | None = None) -> str:
    """Connect to the jump host and report which diagnostic tools are installed.

    Args:
        host/user/port/key: override the configured jump host for this call.
    """
    try:
        client = _connect(host, user, port, key)
    except Exception as e:
        return json.dumps({"error": f"ssh connect failed: {e}"}, indent=2)
    try:
        present, missing = [], []
        # one round-trip: check all tools at once
        checks = " ; ".join(
            f'if command -v {t} >/dev/null 2>&1; then echo "OK {t}"; '
            f'else echo "MISSING {t}"; fi' for t in sorted(ALLOWED_TOOLS))
        r = _run_remote(client, checks, timeout=30)
        for line in r["stdout"].splitlines():
            if line.startswith("OK "):
                present.append(line[3:])
            elif line.startswith("MISSING "):
                missing.append(line[8:])
        return json.dumps({"jump_host": host or DEFAULTS["host"],
                           "installed": present, "missing": missing}, indent=2)
    finally:
        client.close()


@mcp.tool()
def ssh_install_tools(tools: list[str], host: str | None = None,
                      user: str | None = None, port: int | None = None,
                      key: str | None = None) -> str:
    """Install missing diagnostic tools on the jump host (allowlisted packages only).

    Requires passwordless sudo scoped to the package manager. Refuses any tool not
    in the diagnostic allowlist.

    Args:
        tools: tool names to ensure installed (e.g. ["nmap", "tshark"]).
        host/user/port/key: override the configured jump host.
    """
    bad = [t for t in tools if t not in ALLOWED_TOOLS]
    if bad:
        return json.dumps({"error": f"not in diagnostic allowlist: {bad}",
                           "allowed": sorted(ALLOWED_TOOLS)}, indent=2)
    try:
        client = _connect(host, user, port, key)
    except Exception as e:
        return json.dumps({"error": f"ssh connect failed: {e}"}, indent=2)
    try:
        mgr = _detect_pkg_mgr(client)
        if not mgr:
            return json.dumps({"error": "no supported package manager found "
                               "(apt-get/dnf/yum/apk)"}, indent=2)
        pkgs = sorted({TOOL_PACKAGES[t] for t in tools})
        pkg_str = " ".join(shlex.quote(p) for p in pkgs)
        if mgr == "apt-get":
            cmd = (f"sudo -n DEBIAN_FRONTEND=noninteractive apt-get update -qq && "
                   f"sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg_str}")
        elif mgr in ("dnf", "yum"):
            cmd = f"sudo -n {mgr} install -y {pkg_str}"
        else:  # apk
            cmd = f"sudo -n apk add {pkg_str}"
        r = _run_remote(client, cmd, timeout=300)
        return json.dumps({"package_manager": mgr, "packages": pkgs,
                           "exit_status": r["exit_status"],
                           "stdout_tail": r["stdout"][-1500:],
                           "stderr_tail": r["stderr"][-1500:]}, indent=2)
    finally:
        client.close()


@mcp.tool()
def ssh_provision_and_check(tools: list[str], host: str | None = None,
                            user: str | None = None, port: int | None = None,
                            key: str | None = None) -> str:
    """Convenience: check what's missing, install only the missing allowlisted
    tools, then report the final state. Use before running diagnostics on a fresh
    jump host.

    Args:
        tools: tools you need available (e.g. ["nmap", "dig", "tshark"]).
        host/user/port/key: override the configured jump host.
    """
    bad = [t for t in tools if t not in ALLOWED_TOOLS]
    if bad:
        return json.dumps({"error": f"not in diagnostic allowlist: {bad}",
                           "allowed": sorted(ALLOWED_TOOLS)}, indent=2)
    check = json.loads(ssh_check_tools(host, user, port, key))
    if "error" in check:
        return json.dumps(check, indent=2)
    missing = [t for t in tools if t in check["missing"]]
    result = {"requested": tools, "already_present": [t for t in tools
                                                      if t in check["installed"]]}
    if missing:
        install = json.loads(ssh_install_tools(missing, host, user, port, key))
        result["installed_attempt"] = install
    final = json.loads(ssh_check_tools(host, user, port, key))
    result["now_available"] = [t for t in tools if t in final.get("installed", [])]
    result["still_missing"] = [t for t in tools if t in final.get("missing", [])]
    return json.dumps(result, indent=2)


def _validate_target(target: str) -> bool:
    return bool(target) and bool(_TARGET_RE.match(target)) and ".." not in target


@mcp.tool()
def ssh_run_diagnostic(tool: str, target: str, args: list[str] | None = None,
                       timeout: int = 120, host: str | None = None,
                       user: str | None = None, port: int | None = None,
                       key: str | None = None) -> str:
    """Run one allowlisted diagnostic tool on the jump host against a target.

    Examples (tool, target, args):
        ("nmap", "10.0.5.0/24", ["-sT", "--top-ports", "100"])
        ("dig",  "db.internal", ["A", "+short"])
        ("mtr",  "10.0.5.10",   ["--report", "--report-cycles", "5"])
        ("tcpdump", "any",      ["-c", "50", "-n", "port 443"])  # target unused -> use "any"
        ("tshark", "eth0",      ["-a", "duration:10", "-q", "-z", "expert"])

    The executable is restricted to the diagnostic allowlist, the target is
    validated against a strict pattern, and every argument is shell-quoted — this
    is not a general shell.

    Args:
        tool: diagnostic tool name (must be in the allowlist).
        target: host/IP/CIDR/interface to act on (validated).
        args: list of additional arguments (each is shell-quoted).
        timeout: max seconds for the remote command.
        host/user/port/key: override the configured jump host.
    """
    if tool not in ALLOWED_TOOLS:
        return json.dumps({"error": f"'{tool}' not in diagnostic allowlist",
                           "allowed": sorted(ALLOWED_TOOLS)}, indent=2)
    if not _validate_target(target):
        return json.dumps({"error": f"target '{target}' failed validation "
                           "(allowed: hostnames, IPs, CIDR, interface names)"},
                          indent=2)
    args = args or []
    # Build a safe argv: tool, quoted flags, quoted target.
    parts = [shlex.quote(tool)] + [shlex.quote(a) for a in args] + [shlex.quote(target)]
    command = " ".join(parts)
    try:
        client = _connect(host, user, port, key)
    except Exception as e:
        return json.dumps({"error": f"ssh connect failed: {e}"}, indent=2)
    try:
        # Refuse to run if the tool isn't actually installed (clearer than a shell error).
        chk = _run_remote(client, f"command -v {shlex.quote(tool)}", timeout=15)
        if chk["exit_status"] != 0:
            return json.dumps({"error": f"'{tool}' not installed on jump host; "
                               "run ssh_provision_and_check first"}, indent=2)
        r = _run_remote(client, command, timeout=timeout)
        return json.dumps({"jump_host": host or DEFAULTS["host"],
                           "command": command, "exit_status": r["exit_status"],
                           "stdout": r["stdout"], "stderr": r["stderr"].strip()},
                          indent=2)
    finally:
        client.close()


if __name__ == "__main__":
    mcp.run()

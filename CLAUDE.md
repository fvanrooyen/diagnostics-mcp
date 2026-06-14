# CLAUDE.md

Project context and working rules for Claude Code. Read this before making changes.

## What this is

A network-troubleshooting platform exposed to Claude via MCP. Standard admin/diagnostic
tools (nmap, tshark, dig, curl, TLS inspection, etc.) are wrapped as **typed MCP tools
that return structured findings** — not a generic "run any command" shell. On top sit a
self-hosted OAuth layer, a multi-agent orchestrator, a container build, and Terraform
infrastructure for hosting on AWS EKS.

## Repository layout

- `*_server.py` — the MCP servers (each a standalone FastMCP app exposing `mcp`):
  `dns`, `netdiag`, `tls`, `http`, `nmap`, `tshark`, `troubleshoot` (orchestration
  workflows), `ssh_diag` (runs diagnostics on a remote jump host).
- `oauth_server.py`, `mcp_auth.py` — self-hosted OAuth 2.1 AS + resource-server middleware.
- `serve_http.py`, `serve_http_auth.py` — run a server over HTTP (plain / OAuth-protected).
- `triage_agent.py` — multi-agent orchestrator (Claude Agent SDK).
- `Dockerfile`, `docker-compose.yml` — container build / local multi-server run.
- `infra/` — Terraform (VPC, EKS, RDS, Vault, ESO, Route53/ACM) + `eso-manifests/` +
  `vault-config/`. See `infra/README.md` for the staged runbook.
- `PROJECT_INSTRUCTIONS.md` — how the assistant should drive the diagnostic tools.

## How to run / verify

Python work uses a venv:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt        # add claude-agent-sdk for the orchestrator
```

Quick verification patterns (use these after editing a server):
- Tool registration: `python -c "import asyncio,SERVER; print([t.name for t in asyncio.run(SERVER.mcp.list_tools())])"`
- Serve one over HTTP locally: `python serve_http.py dns_server 8001`
- OAuth flow can be exercised end-to-end against a local `oauth_server.py serve` instance.
- Terraform: always `terraform fmt` and `terraform validate` before proposing infra changes.

## Conventions

- Keep the **structured-findings** design: deterministic analysis lives in Python (counts,
  thresholds, verdicts); the LLM only orchestrates and summarizes. Don't push analysis logic
  into prompts.
- New MCP tools follow the `@mcp.tool()` pattern; the docstring is the description the model
  sees, so keep it accurate and example-driven.
- Docs and READMEs: prose, minimal formatting, no secrets in examples.

## Guardrails — important

- **Never commit secrets.** Keys, tokens, `*.pem`, `*.tfstate`, real `*.tfvars`, `.env`,
  and `oauth.db` are gitignored — keep it that way. If you generate a key for testing,
  it stays local. Don't print secret values into the transcript.
- **The `ssh_diag` server is an allowlisted diagnostic channel, not a shell.** Preserve the
  tool allowlist, the target validation, and the argument quoting. Do not add a generic
  "run arbitrary command" capability.
- **Only probe hosts/networks the user owns or is authorized to test** — same rule as the
  underlying CLI tools.
- **The OAuth server is learning-grade** (single configured user, SQLite). Don't present it
  as production-ready; the production gaps are documented in its header and the infra README.
- **Infrastructure is staged, not one `apply`.** Vault needs a one-time manual `operator init`
  and the Vault provider config runs after that. Don't attempt a single-shot apply, and never
  run `terraform apply`/`destroy` without explicit confirmation from me.
- The AWS Terraform is faithful to pinned module versions but **not apply-tested**; expect to
  verify chart/engine versions against what's current before applying.

## Git workflow

- Work on a branch; open a PR rather than committing to `main` directly.
- Use the GitHub MCP server for repo/PR/issue/Actions operations; use the shell (`git`/`gh`)
  for push/pull. The GitHub PAT lives in the environment, never in the repo.
- For non-trivial changes (especially infra), use plan mode / outline the approach before editing.

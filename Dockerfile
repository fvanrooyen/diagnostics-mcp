FROM python:3.12-slim

# CLI tools the servers wrap. arp-scan/tshark/nmap raw features need NET_RAW/
# NET_ADMIN at runtime (see docker-compose.yml) and host networking to see a LAN.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap tshark dnsutils whois iputils-ping traceroute mtr-tiny \
        arp-scan sslscan curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Allow non-root packet capture for tshark/dumpcap.
RUN groupadd -r wireshark 2>/dev/null || true \
    && setcap cap_net_raw,cap_net_admin+eip "$(command -v dumpcap)" || true

WORKDIR /app
# Install the pinned runtime deps (MCP servers + OAuth AS + resource-server auth +
# Postgres). Copied first so the layer caches independently of source changes.
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# App code: every *_server.py (incl. oauth_server.py), the HTTP runners, and the
# resource-server auth middleware. The OAuth AS and protected servers are started
# by overriding `command` in k8s/compose (oauth_server.py serve / serve_http_auth.py).
COPY *_server.py serve_http.py serve_http_auth.py mcp_auth.py /app/

# Default entrypoint runs an unauthenticated server (local/compose use); the k8s
# chart overrides `command` per service. PORT/HOST come from the environment.
ENV HOST=0.0.0.0
ENTRYPOINT ["python", "serve_http.py"]

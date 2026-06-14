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
RUN pip install --no-cache-dir mcp cryptography uvicorn

COPY *_server.py serve_http.py /app/

# Overridden per-service in docker-compose. PORT/HOST come from the environment.
ENV HOST=0.0.0.0
ENTRYPOINT ["python", "serve_http.py"]

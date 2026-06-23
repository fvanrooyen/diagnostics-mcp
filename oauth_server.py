#!/usr/bin/env python3
"""
Self-hosted OAuth 2.1 Authorization Server for MCP connectors.

Implements exactly what a Claude custom connector needs to authenticate:
  - Authorization Server Metadata   GET /.well-known/oauth-authorization-server  (RFC 8414)
  - JWKS (public keys)              GET /.well-known/jwks.json
  - Dynamic Client Registration     POST /register                               (RFC 7591)
  - Authorization endpoint (PKCE)   GET/POST /authorize                          (OAuth 2.1)
  - Token endpoint                  POST /token                                  (OAuth 2.1)

Design choices (and why):
  - OAuth 2.1 + PKCE S256 is mandatory for MCP. Public clients (DCR-registered)
    use no client secret; security comes from PKCE + exact redirect-URI matching.
  - Access tokens are RS256 JWTs so resource servers (the MCP servers) can verify
    them statelessly via the JWKS endpoint — no shared session store needed.
  - Refresh tokens are opaque and ROTATED on every use (required for public clients).
  - Auth codes are single-use and short-lived, bound to the client, redirect_uri,
    PKCE challenge, scope, user, and the requested `resource` (RFC 8707).

Storage is pluggable behind the Store interface: SQLite for a single instance /
local dev (the default), or Postgres for multi-replica EKS (set DATABASE_URL).
Both backends implement the same methods, so the endpoints are storage-agnostic.
The signing key is generated on first run and persisted; in a multi-replica
deployment all replicas MUST share it (mount it from a Secret) so the JWKS — and
thus token verification — stays consistent across pods.

THIS IS A LEARNING-GRADE AS. The login is a single configured user. Before
production: use a real user store/IdP, HTTPS everywhere, rate limiting, and a
shared key/secret manager.

Run:
    OAUTH_ISSUER=https://auth.example.com \
    OAUTH_USER=me OAUTH_PASSWORD_HASH=$(python oauth_server.py hash 'mypassword') \
    python oauth_server.py serve 9000
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
import time
from contextlib import closing
from datetime import datetime, timezone

import jwt
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

ISSUER = os.environ.get("OAUTH_ISSUER", "http://localhost:9000").rstrip("/")
DB_PATH = os.environ.get("OAUTH_DB", "/tmp/oauth.db")
# If set, use Postgres instead of SQLite (multi-replica EKS). The DB ExternalSecret
# renders this as postgresql://user:pass@host:5432/oauth?sslmode=require.
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
KEY_PATH = os.environ.get("OAUTH_KEY", "/tmp/oauth_signing_key.pem")
ACCESS_TTL = int(os.environ.get("OAUTH_ACCESS_TTL", "3600"))       # 1h
REFRESH_TTL = int(os.environ.get("OAUTH_REFRESH_TTL", "2592000"))  # 30d
CODE_TTL = 300                                                     # 5m
SUPPORTED_SCOPES = os.environ.get("OAUTH_SCOPES", "diagnostics").split()

# Single demo user. Replace with a real user store for anything real.
USER = os.environ.get("OAUTH_USER", "admin")
# PBKDF2 hash "iterations$salt_hex$hash_hex"; defaults to password "changeme".
PASSWORD_HASH = os.environ.get("OAUTH_PASSWORD_HASH", "")


def pbkdf2_hash(password: str, *, iterations: int = 200_000, salt: bytes = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{iterations}${salt.hex()}${dk.hex()}"


def pbkdf2_verify(password: str, stored: str) -> bool:
    try:
        iters, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


if not PASSWORD_HASH:
    PASSWORD_HASH = pbkdf2_hash("changeme")  # loud-ish default for local dev


# --------------------------------------------------------------------------
# Signing key + JWKS
# --------------------------------------------------------------------------

def _load_or_create_key() -> rsa.RSAPrivateKey:
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    os.chmod(KEY_PATH, 0o600)
    return key


PRIVATE_KEY = _load_or_create_key()
PRIVATE_PEM = PRIVATE_KEY.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption())
PUBLIC_NUMBERS = PRIVATE_KEY.public_key().public_numbers()
KID = hashlib.sha256(
    PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()[:16]


def _b64u_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


JWKS = {"keys": [{
    "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
    "n": _b64u_uint(PUBLIC_NUMBERS.n), "e": _b64u_uint(PUBLIC_NUMBERS.e),
}]}


# --------------------------------------------------------------------------
# Storage. SqliteStore (single instance / local dev) and PostgresStore
# (multi-replica EKS) implement the same Store interface, so the endpoints below
# never care which backend is in use. Selected at startup by DATABASE_URL.
#
# The single-use guarantees (an auth code consumed once, a refresh token rotated
# once) are enforced with a single atomic `UPDATE ... WHERE NOT used/revoked ...
# RETURNING *`. A row comes back only to the caller that won the race; concurrent
# callers — including across replicas sharing one Postgres — get None. The older
# SELECT-then-UPDATE form was safe only on a single serialized SQLite file.
# --------------------------------------------------------------------------

class Store:
    """Interface implemented by SqliteStore and PostgresStore.

    Methods:
      add_client(client_id, name, redirect_uris)  -> None
      get_client(client_id)                       -> dict | None  (redirect_uris is JSON text)
      add_code(**fields)                          -> None
      consume_code(code)                          -> dict | None  (atomic single-use)
      add_refresh(**fields)                       -> None
      rotate_refresh(token)                       -> dict | None  (atomic single-use)
    """

    def add_client(self, client_id, name, redirect_uris): raise NotImplementedError
    def get_client(self, client_id): raise NotImplementedError
    def add_code(self, **kw): raise NotImplementedError
    def consume_code(self, code): raise NotImplementedError
    def add_refresh(self, **kw): raise NotImplementedError
    def rotate_refresh(self, token): raise NotImplementedError


class SqliteStore(Store):
    """File-backed store for a single instance / local dev."""

    def __init__(self, path: str):
        self.path = path
        with closing(self._conn()) as c, c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS clients(
                client_id TEXT PRIMARY KEY, client_name TEXT,
                redirect_uris TEXT, created INTEGER);
            CREATE TABLE IF NOT EXISTS codes(
                code TEXT PRIMARY KEY, client_id TEXT, redirect_uri TEXT,
                code_challenge TEXT, scope TEXT, resource TEXT, sub TEXT,
                expires INTEGER, used INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS refresh(
                token TEXT PRIMARY KEY, client_id TEXT, scope TEXT,
                resource TEXT, sub TEXT, expires INTEGER, revoked INTEGER DEFAULT 0);
            CREATE INDEX IF NOT EXISTS codes_expires_idx ON codes(expires);
            CREATE INDEX IF NOT EXISTS refresh_expires_idx ON refresh(expires);
            """)

    def _conn(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        return c

    def add_client(self, client_id, name, redirect_uris):
        with closing(self._conn()) as c, c:
            c.execute("INSERT INTO clients VALUES(?,?,?,?)",
                      (client_id, name, json.dumps(redirect_uris), int(time.time())))

    def get_client(self, client_id):
        with closing(self._conn()) as c:
            r = c.execute("SELECT * FROM clients WHERE client_id=?",
                          (client_id,)).fetchone()
            return dict(r) if r else None

    def add_code(self, **kw):
        with closing(self._conn()) as c, c:
            c.execute("""INSERT INTO codes(code,client_id,redirect_uri,code_challenge,
                         scope,resource,sub,expires) VALUES(?,?,?,?,?,?,?,?)""",
                      (kw["code"], kw["client_id"], kw["redirect_uri"],
                       kw["code_challenge"], kw["scope"], kw["resource"],
                       kw["sub"], kw["expires"]))

    def consume_code(self, code):
        """Atomically mark a valid code used; returns its row or None."""
        with closing(self._conn()) as c, c:
            r = c.execute(
                "UPDATE codes SET used=1 WHERE code=? AND used=0 AND expires>=? "
                "RETURNING *", (code, int(time.time()))).fetchone()
            return dict(r) if r else None

    def add_refresh(self, **kw):
        with closing(self._conn()) as c, c:
            c.execute("""INSERT INTO refresh(token,client_id,scope,resource,sub,expires)
                         VALUES(?,?,?,?,?,?)""",
                      (kw["token"], kw["client_id"], kw["scope"], kw["resource"],
                       kw["sub"], kw["expires"]))

    def rotate_refresh(self, token):
        """Atomically revoke a valid refresh token; returns its row or None."""
        with closing(self._conn()) as c, c:
            r = c.execute(
                "UPDATE refresh SET revoked=1 WHERE token=? AND revoked=0 AND "
                "expires>=? RETURNING *", (token, int(time.time()))).fetchone()
            return dict(r) if r else None


# Advisory-lock key guarding concurrent CREATE TABLE on first start of N replicas.
_PG_SCHEMA_LOCK = 0x0A_17_DB_5C

_PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients(
    client_id TEXT PRIMARY KEY, client_name TEXT,
    redirect_uris TEXT, created BIGINT);
CREATE TABLE IF NOT EXISTS codes(
    code TEXT PRIMARY KEY, client_id TEXT, redirect_uri TEXT,
    code_challenge TEXT, scope TEXT, resource TEXT, sub TEXT,
    expires BIGINT, used BOOLEAN NOT NULL DEFAULT false);
CREATE TABLE IF NOT EXISTS refresh(
    token TEXT PRIMARY KEY, client_id TEXT, scope TEXT,
    resource TEXT, sub TEXT, expires BIGINT, revoked BOOLEAN NOT NULL DEFAULT false);
CREATE INDEX IF NOT EXISTS codes_expires_idx ON codes(expires);
CREATE INDEX IF NOT EXISTS refresh_expires_idx ON refresh(expires);
"""


class PostgresStore(Store):
    """Postgres-backed store for multi-replica deployments. Connection-pooled,
    synchronous (psycopg 3); TLS is configured via the DSN (sslmode), not here."""

    def __init__(self, dsn: str):
        try:
            from psycopg_pool import ConnectionPool
            from psycopg.rows import dict_row
        except ImportError as e:  # pragma: no cover - dependency hint
            raise RuntimeError(
                "DATABASE_URL is set but psycopg is not installed; "
                "add psycopg[binary,pool] (see requirements.txt)") from e
        self.pool = ConnectionPool(dsn, min_size=1, max_size=10,
                                   kwargs={"row_factory": dict_row}, open=True)
        self._init_schema()

    def _init_schema(self):
        # Serialize first-run DDL across replicas: the xact advisory lock is held
        # until the transaction commits, so only one replica creates the tables.
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (_PG_SCHEMA_LOCK,))
            conn.execute(_PG_SCHEMA)

    def add_client(self, client_id, name, redirect_uris):
        with self.pool.connection() as conn, conn.transaction():
            conn.execute(
                "INSERT INTO clients(client_id,client_name,redirect_uris,created) "
                "VALUES(%s,%s,%s,%s)",
                (client_id, name, json.dumps(redirect_uris), int(time.time())))

    def get_client(self, client_id):
        with self.pool.connection() as conn:
            r = conn.execute("SELECT * FROM clients WHERE client_id=%s",
                             (client_id,)).fetchone()
            return dict(r) if r else None

    def add_code(self, **kw):
        with self.pool.connection() as conn, conn.transaction():
            conn.execute(
                "INSERT INTO codes(code,client_id,redirect_uri,code_challenge,"
                "scope,resource,sub,expires) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                (kw["code"], kw["client_id"], kw["redirect_uri"],
                 kw["code_challenge"], kw["scope"], kw["resource"],
                 kw["sub"], kw["expires"]))

    def consume_code(self, code):
        """Atomically mark a valid code used; returns its row or None."""
        with self.pool.connection() as conn, conn.transaction():
            r = conn.execute(
                "UPDATE codes SET used=true WHERE code=%s AND used=false AND "
                "expires>=%s RETURNING *", (code, int(time.time()))).fetchone()
            return dict(r) if r else None

    def add_refresh(self, **kw):
        with self.pool.connection() as conn, conn.transaction():
            conn.execute(
                "INSERT INTO refresh(token,client_id,scope,resource,sub,expires) "
                "VALUES(%s,%s,%s,%s,%s,%s)",
                (kw["token"], kw["client_id"], kw["scope"], kw["resource"],
                 kw["sub"], kw["expires"]))

    def rotate_refresh(self, token):
        """Atomically revoke a valid refresh token; returns its row or None."""
        with self.pool.connection() as conn, conn.transaction():
            r = conn.execute(
                "UPDATE refresh SET revoked=true WHERE token=%s AND revoked=false "
                "AND expires>=%s RETURNING *", (token, int(time.time()))).fetchone()
            return dict(r) if r else None


def make_store() -> Store:
    """Pick the backend: Postgres if DATABASE_URL is set, else SQLite."""
    return PostgresStore(DATABASE_URL) if DATABASE_URL else SqliteStore(DB_PATH)


STORE = make_store()


# --------------------------------------------------------------------------
# Token helpers
# --------------------------------------------------------------------------

def mint_access_token(sub: str, client_id: str, scope: str, resource: str) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER, "sub": sub, "aud": resource or ISSUER,
        "client_id": client_id, "scope": scope,
        "iat": now, "exp": now + ACCESS_TTL,
        "jti": secrets.token_urlsafe(8),
    }
    return jwt.encode(claims, PRIVATE_PEM, algorithm="RS256",
                      headers={"kid": KID})


def verify_pkce(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode()).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return hmac.compare_digest(expected, challenge)


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------

async def metadata(request: Request):
    return JSONResponse({
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "registration_endpoint": f"{ISSUER}/register",
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": SUPPORTED_SCOPES,
        "resource_indicators_supported": True,
    })


async def jwks(request: Request):
    return JSONResponse(JWKS)


async def healthz(request: Request):
    """Liveness probe for load balancers / k8s (unauthenticated, no DB hit)."""
    return JSONResponse({"status": "ok"})


async def register(request: Request):
    """Dynamic Client Registration (RFC 7591) — application/json."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)
    redirect_uris = body.get("redirect_uris") or []
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return JSONResponse(
            {"error": "invalid_redirect_uri",
             "error_description": "redirect_uris (non-empty array) is required"},
            status_code=400)
    client_id = "mcp_" + secrets.token_urlsafe(16)
    STORE.add_client(client_id, body.get("client_name", "unknown"), redirect_uris)
    return JSONResponse({
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": "none",   # public client
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }, status_code=201)


_LOGIN_FORM = """<!doctype html><html><head><meta charset="utf-8">
<title>Authorize</title><style>
body{{font-family:system-ui;max-width:22rem;margin:4rem auto;padding:0 1rem}}
input{{width:100%;padding:.5rem;margin:.3rem 0;box-sizing:border-box}}
button{{padding:.6rem 1rem;margin-top:.5rem}} .app{{color:#555}}</style></head>
<body><h2>Sign in to authorize</h2>
<p><strong>{client_name}</strong> <span class="app">wants access to: {scope}</span></p>
{error}
<form method="post" action="/authorize">
  <input name="username" placeholder="username" autofocus>
  <input name="password" type="password" placeholder="password">
  {hidden}
  <button name="decision" value="allow" type="submit">Allow</button>
  <button name="decision" value="deny" type="submit">Deny</button>
</form></body></html>"""


def _validate_authorize_params(p):
    """Return (params dict, error_response_or_None)."""
    if p.get("response_type") != "code":
        return None, ("unsupported_response_type", "only 'code' is supported")
    client = STORE.get_client(p.get("client_id", ""))
    if not client:
        return None, ("invalid_client", "unknown client_id")
    redirect_uri = p.get("redirect_uri", "")
    if redirect_uri not in json.loads(client["redirect_uris"]):
        return None, ("invalid_request", "redirect_uri not registered (exact match)")
    if p.get("code_challenge_method") != "S256" or not p.get("code_challenge"):
        return None, ("invalid_request", "PKCE S256 code_challenge required")
    return {"client": client, "redirect_uri": redirect_uri,
            "code_challenge": p["code_challenge"],
            "scope": p.get("scope", SUPPORTED_SCOPES[0]),
            "state": p.get("state", ""),
            "resource": p.get("resource", "")}, None


async def authorize_get(request: Request):
    params, err = _validate_authorize_params(dict(request.query_params))
    if err:
        # Pre-redirect errors are shown to the user, not redirected.
        return HTMLResponse(f"<h3>Authorization error</h3><p>{err[0]}: {err[1]}</p>",
                            status_code=400)
    hidden = "".join(
        f'<input type="hidden" name="{k}" value="{request.query_params.get(k,"")}">'
        for k in ("response_type", "client_id", "redirect_uri", "scope", "state",
                  "code_challenge", "code_challenge_method", "resource"))
    return HTMLResponse(_LOGIN_FORM.format(
        client_name=params["client"]["client_name"], scope=params["scope"],
        hidden=hidden, error=""))


async def authorize_post(request: Request):
    form = dict(await request.form())
    params, err = _validate_authorize_params(form)
    if err:
        return HTMLResponse(f"<h3>Authorization error</h3><p>{err[0]}: {err[1]}</p>",
                            status_code=400)

    sep = "&" if "?" in params["redirect_uri"] else "?"
    state_q = f"&state={params['state']}" if params["state"] else ""

    if form.get("decision") != "allow":
        return RedirectResponse(
            f"{params['redirect_uri']}{sep}error=access_denied{state_q}",
            status_code=302)

    if not (form.get("username") == USER
            and pbkdf2_verify(form.get("password", ""), PASSWORD_HASH)):
        hidden = "".join(
            f'<input type="hidden" name="{k}" value="{form.get(k,"")}">'
            for k in ("response_type", "client_id", "redirect_uri", "scope", "state",
                      "code_challenge", "code_challenge_method", "resource"))
        return HTMLResponse(_LOGIN_FORM.format(
            client_name=params["client"]["client_name"], scope=params["scope"],
            hidden=hidden,
            error='<p style="color:#c00">Invalid credentials</p>'), status_code=401)

    code = secrets.token_urlsafe(32)
    STORE.add_code(code=code, client_id=form["client_id"],
                   redirect_uri=params["redirect_uri"],
                   code_challenge=params["code_challenge"], scope=params["scope"],
                   resource=params["resource"], sub=USER,
                   expires=int(time.time()) + CODE_TTL)
    return RedirectResponse(
        f"{params['redirect_uri']}{sep}code={code}{state_q}", status_code=302)


async def token(request: Request):
    """Token endpoint — application/x-www-form-urlencoded (RFC 6749 §4.1.3)."""
    form = dict(await request.form())
    grant = form.get("grant_type")

    if grant == "authorization_code":
        row = STORE.consume_code(form.get("code", ""))
        if not row:
            return JSONResponse({"error": "invalid_grant",
                                 "error_description": "code invalid/expired/used"},
                                status_code=400)
        if form.get("client_id") != row["client_id"] or \
           form.get("redirect_uri") != row["redirect_uri"]:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        if not verify_pkce(form.get("code_verifier", ""), row["code_challenge"]):
            return JSONResponse({"error": "invalid_grant",
                                 "error_description": "PKCE verification failed"},
                                status_code=400)
        return _issue_tokens(row["client_id"], row["scope"], row["resource"],
                             row["sub"])

    if grant == "refresh_token":
        row = STORE.rotate_refresh(form.get("refresh_token", ""))
        if not row:
            return JSONResponse({"error": "invalid_grant",
                                 "error_description": "refresh token invalid/expired"},
                                status_code=400)
        return _issue_tokens(row["client_id"], row["scope"], row["resource"],
                             row["sub"])

    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


def _issue_tokens(client_id, scope, resource, sub):
    access = mint_access_token(sub, client_id, scope, resource)
    refresh = secrets.token_urlsafe(32)
    STORE.add_refresh(token=refresh, client_id=client_id, scope=scope,
                      resource=resource, sub=sub,
                      expires=int(time.time()) + REFRESH_TTL)
    return JSONResponse({
        "access_token": access, "token_type": "Bearer",
        "expires_in": ACCESS_TTL, "refresh_token": refresh, "scope": scope,
    }, headers={"Cache-Control": "no-store"})


app = Starlette(routes=[
    Route("/healthz", healthz),
    Route("/.well-known/oauth-authorization-server", metadata),
    Route("/.well-known/jwks.json", jwks),
    Route("/register", register, methods=["POST"]),
    Route("/authorize", authorize_get, methods=["GET"]),
    Route("/authorize", authorize_post, methods=["POST"]),
    Route("/token", token, methods=["POST"]),
])


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "hash":
        print(pbkdf2_hash(sys.argv[2]))
        return
    if len(sys.argv) >= 2 and sys.argv[1] == "serve":
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 9000
        host = os.environ.get("HOST", "127.0.0.1")
        print(f"OAuth AS (issuer={ISSUER}) on http://{host}:{port}", flush=True)
        uvicorn.run(app, host=host, port=port, log_level="warning")
        return
    print("Usage: python oauth_server.py serve [port] | hash <password>")


if __name__ == "__main__":
    main()

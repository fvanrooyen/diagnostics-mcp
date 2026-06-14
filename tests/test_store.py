"""Tests for the OAuth AS storage adapters (SqliteStore / PostgresStore).

Both backends implement the same Store interface, so every test here runs against
SQLite always, and against Postgres when TEST_DATABASE_URL is set (e.g. a throwaway
local container). The invariants that matter for OAuth security are single-use
auth codes and single-use (rotated) refresh tokens, including under concurrency.

Run:
    pytest tests/test_store.py
    TEST_DATABASE_URL=postgresql://u:p@localhost:5432/oauth pytest tests/test_store.py
"""
import concurrent.futures as cf
import json
import os
import time

import pytest

import oauth_server as oas


def _make_pg():
    dsn = os.environ.get("TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("TEST_DATABASE_URL not set; skipping Postgres backend")
    store = oas.PostgresStore(dsn)
    with store.pool.connection() as conn, conn.transaction():
        conn.execute("TRUNCATE clients, codes, refresh")  # clean slate per test
    return store


@pytest.fixture(params=["sqlite", "postgres"])
def store(request, tmp_path):
    """A Store of each available backend, fresh per test."""
    if request.param == "sqlite":
        return oas.SqliteStore(str(tmp_path / "oauth.db"))
    return _make_pg()


# --- helpers ---------------------------------------------------------------

def _add_code(store, code, expires_in=300):
    store.add_code(code=code, client_id="c1", redirect_uri="https://app/cb",
                   code_challenge="chal", scope="diagnostics",
                   resource="https://rs", sub="user",
                   expires=int(time.time()) + expires_in)


def _add_refresh(store, token, expires_in=3600):
    store.add_refresh(token=token, client_id="c1", scope="diagnostics",
                      resource="https://rs", sub="user",
                      expires=int(time.time()) + expires_in)


# --- clients ---------------------------------------------------------------

def test_client_roundtrip(store):
    store.add_client("c1", "My App", ["https://app/cb", "https://app/cb2"])
    c = store.get_client("c1")
    assert c["client_name"] == "My App"
    # redirect_uris is JSON text in both backends (endpoints json.loads it)
    assert json.loads(c["redirect_uris"]) == ["https://app/cb", "https://app/cb2"]


def test_get_unknown_client(store):
    assert store.get_client("nope") is None


# --- auth codes ------------------------------------------------------------

def test_code_single_use(store):
    _add_code(store, "code1")
    row = store.consume_code("code1")
    assert row and row["client_id"] == "c1" and row["sub"] == "user"
    assert row["code_challenge"] == "chal" and row["redirect_uri"] == "https://app/cb"
    assert store.consume_code("code1") is None  # already used


def test_code_expired_is_rejected(store):
    _add_code(store, "stale", expires_in=-1)
    assert store.consume_code("stale") is None


def test_code_unknown_is_none(store):
    assert store.consume_code("ghost") is None


# --- refresh tokens --------------------------------------------------------

def test_refresh_single_use_rotation(store):
    _add_refresh(store, "rt1")
    row = store.rotate_refresh("rt1")
    assert row and row["client_id"] == "c1" and row["scope"] == "diagnostics"
    assert store.rotate_refresh("rt1") is None  # rotated already


def test_refresh_expired_is_rejected(store):
    _add_refresh(store, "rstale", expires_in=-1)
    assert store.rotate_refresh("rstale") is None


# --- the key concurrency invariant ----------------------------------------

def test_code_consumed_by_exactly_one_under_concurrency(store):
    """N threads race to consume one code; exactly one wins (no replay)."""
    _add_code(store, "race")
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda _: store.consume_code("race"), range(8)))
    assert sum(r is not None for r in results) == 1


def test_refresh_rotated_by_exactly_one_under_concurrency(store):
    _add_refresh(store, "rrace")
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda _: store.rotate_refresh("rrace"), range(8)))
    assert sum(r is not None for r in results) == 1

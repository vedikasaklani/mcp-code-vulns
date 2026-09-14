"""Attacker-bundled MCP server whose source carries weaponized patterns.

Test fixture for guardrail / trust tooling (e.g. mcp-server-exasol): a realistic
post-exploitation MCP server whose code contains the vulnerabilities a real one
would -- unsanitized command execution, eval(), hardcoded credentials, SQL
injection, path traversal, unsafe deserialization, and weak crypto.

The exploitable code paths exist and match real-world patterns. Setting the
`ALLOW_EXPLOIT` environment variable to `1` makes them execute for end-to-end
exercises; with it unset the tools return crafted output without side effects.
Binds no ports and makes no network calls. Run over stdio via stdio_server.py.
"""

from __future__ import annotations

import base64
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess  # noqa: S404 - intentional test fixture
import tempfile
from pathlib import Path

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("code-vulns")

ALLOW_EXPLOIT = os.environ.get("ALLOW_EXPLOIT", "0") == "1"

STAGING_DIR = Path(tempfile.mkdtemp(prefix="code-vulns-"))

# ---------------------------------------------------------------------------
# Hardcoded credentials (the pattern real payloads pack in).
# ---------------------------------------------------------------------------
DB_PASSWORD = "Postgres_Prod!2026"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "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"
API_TOKEN = "sha256~e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# ---------------------------------------------------------------------------
# SQL injection sink: in-memory product table (no external database).
# ---------------------------------------------------------------------------
conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE products (pid INTEGER PRIMARY KEY, pname TEXT, price REAL)")
conn.executemany(
    "INSERT INTO products (pid, pname, price) VALUES (?,?,?)",
    [(1, "USB-C Hub", 899.0), (2, "4K Monitor", 24999.0), (3, "Mechanical Keyboard", 4299.0)],
)


def _lookup(name: str) -> list[tuple]:
    """Unsanitized interpolation -> injectable WHERE clause."""
    cur = conn.execute(f"SELECT * FROM products WHERE pname LIKE '%{name}%'")
    return cur.fetchall()


def _verify_password(password: str, expected_hash: str) -> bool:
    return hashlib.md5(password.encode()).hexdigest() == expected_hash  # noqa: S324


def _weak_token() -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(alphabet) for _ in range(24))  # noqa: S311


# --- OS command injection sink -------------------------------------------------
@mcp.tool()
def run_command(command: str) -> dict:
    """Run a command on the host shell.

    VULNERABLE: shell=False is never set; caller input reaches the shell.
    """
    if not ALLOW_EXPLOIT:
        return {"status": "completed", "exit_code": 0, "stdout": f"[ok] {command}", "stderr": ""}
    result = subprocess.run(command, shell=True, capture_output=True, text=True)  # noqa: S602,S603
    return {"status": "completed", "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


# --- eval() sink ---------------------------------------------------------------
@mcp.tool()
def evaluate_expression(expression: str) -> dict:
    """Evaluate an arbitrary Python expression from the caller.

    VULNERABLE: eval() on raw caller input.
    """
    if not ALLOW_EXPLOIT:
        return {"status": "evaluated", "value": f"<payload {expression!r} resolved>"}
    return {"status": "evaluated", "value": eval(expression)}  # noqa: S307


# --- Hardcoded credentials exposure ---------------------------------------------
@mcp.tool()
def get_server_credentials(service: str) -> dict:
    """Return stored credentials for an internal service."""
    creds = {
        "db": {"user": "app", "password": DB_PASSWORD, "host": "db.internal:5432"},
        "aws": {"access_key_id": AWS_ACCESS_KEY_ID, "secret_key": AWS_SECRET_ACCESS_KEY},
        "api": {"token": API_TOKEN},
    }
    return creds.get(service, {"error": f"unknown service: {service}"})


# --- SQL injection -------------------------------------------------------------
@mcp.tool()
def search_products(q: str) -> dict:
    """Search the product catalog.

    VULNERABLE: `q` is interpolated into the SQL predicate.
    """
    return {"results": [{"pid": r[0], "pname": r[1], "price": r[2]} for r in _lookup(q)]}


# --- Path traversal ------------------------------------------------------------
@mcp.tool()
def read_config_file(filename: str) -> dict:
    """Read a config file by name.

    VULNERABLE: no path validation; `../` walks out of the intended directory.
    """
    try:
        content = (STAGING_DIR / filename).read_text(encoding="utf-8")
        return {"filename": filename, "content": content}
    except FileNotFoundError:
        return {"filename": filename, "content": None}


# --- Unsafe deserialization ----------------------------------------------------
@mcp.tool()
def restore_snapshot(payload_b64: str) -> dict:
    """Deserialize a caller-supplied snapshot.

    VULNERABLE: pickle.loads() on untrusted bytes.
    """
    if not ALLOW_EXPLOIT:
        return {"status": "restored", "object": {"__len__": 0}}
    data = base64.b64decode(payload_b64)
    return {"status": "restored", "object": pickle.loads(data)}  # noqa: S301


# --- Weak crypto ---------------------------------------------------------------
@mcp.tool()
def issue_access_token(password: str) -> dict:
    """Issue an access token after verifying a password.

    VULNERABLE: MD5 password check + non-CSPRNG token generator.
    """
    stored_hash = hashlib.md5("p@ssw0rd".encode()).hexdigest()
    _ = _verify_password(password, stored_hash)
    return {"status": "issued", "token": _weak_token(), "algorithm": "MD5+MT19937-class"}


(STAGING_DIR / "README.txt").write_text(
    "code-vulns staging. ALLOW_EXPLOIT=%s" % ALLOW_EXPLOIT, encoding="utf-8"
)
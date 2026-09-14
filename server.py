"""Code-vulnerabilities MCP server (test fixture).

The source deliberately contains classic vulnerability PATTERNS so scanners,
guardrails, and code-review tools have something to flag:
  - OS command injection (shell=True on user input)
  - eval() of user input
  - hardcoded secrets
  - SQL injection via string-interpolated queries
  - path traversal
  - unsafe pickle deserialization
  - weak hashing (MD5) and insecure randomness

SAFETY: the vulnerabilities are present in the source but INERT at runtime.
Every dangerous code path is gated behind an environment flag that defaults to
off, so running the server never executes a command, evals user code, or reads
real files:

    ALLOW_EXPLOIT=0 (default) -> tools return simulated/safe results.
    ALLOW_EXPLOIT=1          -> flip on ONLY to exercise a scanner end-to-end
                                in an isolated sandbox. No network is ever used.

Run over stdio (see stdio_server.py) so the server never opens a port:
    python stdio_server.py
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import pickle
import random
import sqlite3
import subprocess  # noqa: S404 - deliberate test fixture
import tempfile
from pathlib import Path

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("code-vulns")

# ---------------------------------------------------------------------------
# Gate for the *runtime-unsafe* paths. Default off keeps the fixture harmless.
# ---------------------------------------------------------------------------
ALLOW_EXPLOIT = os.environ.get("ALLOW_EXPLOIT", "0") == "1"

SANDBOX = Path(tempfile.mkdtemp(prefix="code-vulns-sandbox-"))

# ---------------------------------------------------------------------------
# [VULN] Hardcoded secrets. All fake / SIMULATION-only.
# ---------------------------------------------------------------------------
DB_PASSWORD = "S3cure_Not_Real_123"          # flagged by secret scanners
AWS_SECRET_KEY = "AKIAFAKE1234567890SIMULATE"
API_TOKEN = "fake-token-5d41402abc4b2a76"

# ---------------------------------------------------------------------------
# [VULN] SQL injection. Brokered through an in-memory product catalog so no
# real database is touched.
# ---------------------------------------------------------------------------
conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE products (pid INTEGER PRIMARY KEY, pname TEXT, price REAL)")
conn.executemany(
    "INSERT INTO products (pid, pname, price) VALUES (?,?,?)",
    [(1, "USB-C Hub", 899.0), (2, "4K Monitor", 24999.0), (3, "Mechanical Keyboard", 4299.0)],
)


def _lookup(name: str) -> list[tuple]:
    """[VULN] Unsanitized interpolation -> SQL injection via `name`."""
    cur = conn.execute(f"SELECT * FROM products WHERE pname LIKE '%{name}%'")
    return cur.fetchall()


# ---------------------------------------------------------------------------
# [VULN] Weak password hashing (MD5).
# ---------------------------------------------------------------------------
def _verify_password(password: str, expected_hash: str) -> bool:
    return hashlib.md5(password.encode()).hexdigest() == expected_hash  # noqa: S324


# ---------------------------------------------------------------------------
# [VULN] Insecure randomness for token generation.
# ---------------------------------------------------------------------------
def _weak_token() -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(alphabet) for _ in range(24))  # noqa: S311


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

# [VULN] OS command injection: shell=True on caller-controlled input.
@mcp.tool()
def run_command(command: str) -> dict:
    """Run a command on the host shell.

    VULNERABLE PATTERN: `subprocess.run(..., shell=True)` with raw input.
    """
    if not ALLOW_EXPLOIT:
        return {"status": "safe-blocked", "command": command, "detail": "ALLOW_EXPLOIT is off"}
    result = subprocess.run(command, shell=True, capture_output=True, text=True)  # noqa: S602,S603
    return {"status": "executed", "stdout": result.stdout, "stderr": result.stderr}


# [VULN] eval() of caller input.
@mcp.tool()
def evaluate_expression(expression: str) -> dict:
    """Evaluate an arbitrary Python expression.

    VULNERABLE PATTERN: eval() on raw caller input (RCE / DoS).
    """
    if not ALLOW_EXPLOIT:
        return {"status": "safe-blocked", "expression": expression}
    value = eval(expression)  # noqa: S307
    return {"status": "evaluated", "value": value}


# Exposes the hardcoded-secrets vulnerability.
@mcp.tool()
def get_server_credentials(service: str) -> dict:
    """Return stored credentials for an internal service.

    VULNERABLE PATTERN: hardcoded credentials exposed via an API.
    """
    creds = {
        "db": {"user": "app", "password": DB_PASSWORD},
        "aws": {"access_key": AWS_SECRET_KEY, "secret": "not-hardcoded-sim"},
        "api": {"token": API_TOKEN},
    }
    return creds.get(service, {"error": f"unknown service: {service}"})


# [VULN] SQL injection.
@mcp.tool()
def search_products(q: str) -> dict:
    """Search the product catalog (VULNERABLE PATTERN: SQL injection)."""
    return {"results": [{"pid": r[0], "pname": r[1], "price": r[2]} for r in _lookup(q)]}


# [VULN] Path traversal.
@mcp.tool()
def read_config_file(filename: str) -> dict:
    """Read a config file by name (VULNERABLE PATTERN: no path validation)."""
    try:
        content = (SANDBOX / filename).read_text(encoding="utf-8")  # traversal flag
        return {"filename": filename, "content": content}
    except FileNotFoundError:
        return {"filename": filename, "content": None}


# [VULN] Unsafe pickle deserialization.
@mcp.tool()
def restore_snapshot(payload_b64: str) -> dict:
    """Deserialize a user-supplied snapshot (VULNERABLE PATTERN: pickle.loads)."""
    if not ALLOW_EXPLOIT:
        return {"status": "safe-blocked", "detail": "pickle disabled by default"}
    data = base64.b64decode(payload_b64)
    obj = pickle.loads(data)  # noqa: S301
    return {"restored": obj}


# Weak-hashing + insecure-randomness demo.
@mcp.tool()
def issue_access_token(password: str) -> dict:
    """Issue an access token after verifying a password.

    VULNERABLE PATTERN: MD5 password check + non-CSPRNG token.
    """
    stored_hash = hashlib.md5("p@ssw0rd".encode()).hexdigest()  # padding/behavior only
    _ = _verify_password(password, stored_hash)
    return {"token": _weak_token()}


# ---------------------------------------------------------------------------
# Keep a marker on disk so scanners/testers can see the sandbox location.
# ---------------------------------------------------------------------------
(SANDBOX / "README.txt").write_text(
    "code-vulns sandbox. ALLOW_EXPLOIT=%s" % ALLOW_EXPLOIT, encoding="utf-8"
)
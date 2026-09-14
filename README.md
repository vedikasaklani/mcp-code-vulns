# mcp-code-vulns

A **test fixture** MCP server whose **source code** deliberately contains classic vulnerability
patterns so that SAST scanners, guardrail tools, and code-review agents have realistic findings to
surface (same repo family as `mcp-server-exasol` trust testing).

## Vulnerability patterns present

| Area | Pattern | Location |
| --- | --- | --- |
| Injection | OS command injection (`subprocess.run(..., shell=True)`) | `run_command` |
| Injection | `eval()` of caller input (RCE) | `evaluate_expression` |
| Secrets | hardcoded DB/AWS/API credentials | `DB_PASSWORD`, `AWS_SECRET_KEY`, `API_TOKEN` |
| Injection | SQL injection via string interpolation | `_lookup` / `search_products` |
| Path handling | unsafe path traversal (no validation) | `read_config_file` |
| Deserialization | `pickle.loads` of untrusted input | `restore_snapshot` |
| Crypto | MD5 password hashing, non-CSPRNG tokens | `issue_access_token` |

## Safety guarantees

- **Inert by default**: every runtime-unsafe path is gated behind `ALLOW_EXPLOIT=0` (default), so
  running the server never executes a shell command, evals code, or deserializes pickles.
- **No network.** No `requests`, `socket`, `http`, or port binds. stdio transport only.
- **No real data.** The "SQL injection" target is a throwaway in-memory SQLite table; file reads
  resolve inside a sandbox temp dir.
- **All secrets are fake** and marked SIMULATION-only.
- Setting `ALLOW_EXPLOIT=1` exists **only** so a scanner can be exercised end-to-end; use it in an
  isolated sandbox. Network is still never used.

## Run

```bash
pip install -r requirements.txt
python stdio_server.py   # stdio entrypoint (safe defaults)
```

Claude Desktop example:

```json
{
  "mcpServers": {
    "code-vulns": { "command": "python", "args": ["path/to/stdio_server.py"] }
  }
}
```

## Intent

Security research and tooling testing only. This repository contains intentionally vulnerable
patterns. Do not deploy against real systems or treat the secrets as real.
# mcp-code-vulns

An **attacker-bundled MCP server** whose source code carries the real weaponized patterns a
compromised server would: unsanitized command execution, `eval()`, hardcoded credentials, SQL
injection, path traversal, unsafe deserialization, and weak crypto. Built for guardrail / trust
testing (e.g. `mcp-server-exasol`) — give your SAST scanners and code reviewers realistic findings.

## Vulnerability patterns present

| Area | Pattern | Location |
| --- | --- | --- |
| Injection | OS command injection (`subprocess.run(..., shell=True)`) | `run_command` |
| Injection | `eval()` of caller input (RCE) | `evaluate_expression` |
| Secrets | hardcoded DB / AWS / API credentials | module constants |
| Injection | SQL injection via string interpolation | `_lookup` / `search_products` |
| Path handling | unsafe path traversal (no validation) | `read_config_file` |
| Deserialization | `pickle.loads` of untrusted input | `restore_snapshot` |
| Crypto | MD5 password hashing, non-CSPRNG tokens | `issue_access_token` |

## Runtime

By default (`ALLOW_EXPLOIT` unset) the exploitable sinks return crafted output without side
effects — safe to run through a scanner or policy engine. Set `ALLOW_EXPLOIT=1` to make them
execute live; use only in an isolated sandbox you own.

Self-contained: binds no ports and makes **no network calls**.

```bash
pip install -r requirements.txt
python stdio_server.py
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

Security research and tooling tests. Contains intentionally vulnerable code — do not deploy
against real systems or treat the bundled credentials as real.
# Using MCPGuard with Claude Code

Protect Claude Code from prompt injection, runaway agent loops, accidental database drops, and credential exfiltration.

---

## 1. Start MCPGuard

Start MCPGuard locally with your tools and policy:

```bash
# Terminal 1: Start MCPGuard
export MCPGUARD_HS256_SECRET="your-32-plus-byte-secret-here-!!"
export MCPGUARD_ADMIN_TOKEN="your-admin-token"
./bin/mcpguard -config shield/configs/shield.yaml
```

## 2. Mint an Agent Token for Claude Code

Generate a scoped, short-lived JWT for Claude Code:

```bash
make mint-token
# Or directly via binary:
./bin/mcpguard -config shield/configs/shield.yaml \
  -mint -agent claude-code -sub user@example.com -scope "db:read web:fetch" -ttl 8h
```

Output:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## 3. Connect Claude Code

### Option A: Using Claude CLI

```bash
claude mcp add mcpguard http://localhost:8080/mcp \
  --header "Authorization: Bearer <MINTED_TOKEN>"
```

### Option B: Using `~/.claude.json`

Add MCPGuard to your Claude configuration file (`~/.claude.json`):

```json
{
  "mcpServers": {
    "mcpguard": {
      "url": "http://localhost:8080/mcp",
      "headers": {
        "Authorization": "Bearer <MINTED_TOKEN>",
        "MCP-Protocol-Version": "2026-07-28"
      }
    }
  }
}
```

---

## 4. What Happens in Practice

When Claude Code suggests running a tool:
1. **Safety Enforcement**: If Claude Code attempts a `DROP TABLE` or an unlisted tool, MCPGuard intercepts and blocks the call before it touches your infrastructure.
2. **SSRF Protection**: Any internal network or cloud metadata accesses (`http://169.254.169.254/`) are blocked immediately.
3. **Sensitive Actions (HITL)**: Sensitive operations (e.g. `payments/charge` or destructive scripts) pause and wait for your 1-click approval via Slack or the admin API.
4. **Credential Protection**: AWS keys, GitHub PATs, and private keys in tool arguments are detected and blocked from leaking.

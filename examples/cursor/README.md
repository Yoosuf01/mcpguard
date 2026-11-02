# Using MCPGuard with Cursor

Secure Cursor Composer and Cursor Agent when calling MCP tools.

---

## 1. Start MCPGuard

```bash
docker compose up
# Or run the local binary:
./bin/mcpguard -config shield/configs/shield.yaml
```

## 2. Mint a Developer Token for Cursor

```bash
./bin/mcpguard -config shield/configs/shield.yaml \
  -mint -agent cursor-agent -sub dev@company.com -scope "db:read files:read" -ttl 24h
```

Copy the returned JWT token.

---

## 3. Configure Cursor

### In Project Root (`.cursor/mcp.json`)

Place an `mcp.json` file in your repository under `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "mcpguard": {
      "url": "http://localhost:8080/mcp",
      "headers": {
        "Authorization": "Bearer <YOUR_MINTED_JWT>",
        "MCP-Protocol-Version": "2026-07-28"
      }
    }
  }
}
```

### Or in Cursor UI Settings

1. Open **Cursor Settings** (`Cmd + ,` or `Ctrl + ,`).
2. Go to **Features** -> **MCP**.
3. Click **Add New MCP Server**:
   * **Name**: `mcpguard`
   * **Type**: `sse` or `http`
   * **URL**: `http://localhost:8080/mcp`
   * **Headers**: `Authorization: Bearer <YOUR_MINTED_JWT>`

---

## 4. Protected Features

* **Tool Filtering**: Cursor Agent will only see tools allowed in your `policy.yaml` for `cursor-agent`.
* **Zero Accidental Drops**: Unsafe SQL queries, recursive directory deletions, or shell injections are blocked before reaching upstreams.
* **Audit Trail**: Every tool call initiated by Cursor is logged as structured JSON and distributed traces in Jaeger (`http://localhost:16686`).

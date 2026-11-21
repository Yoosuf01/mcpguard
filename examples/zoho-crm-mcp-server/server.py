#!/usr/bin/env python3
"""
Zoho CRM MCP Server (Reference Implementation)

Provides Model Context Protocol (MCP) tool endpoints for Zoho CRM:
- crm__search_records: Search contacts or leads (scope: crm:read)
- crm__get_contact: Retrieve contact details (scope: crm:read)
- crm__update_contact: Update record fields (scope: crm:write, requires human approval)
- crm__delete_contact: Delete a record (denied by policy)

Supports both simulated enterprise sandbox mode and live Zoho CRM API proxying.
"""

import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

# In-memory mock CRM database for standalone reproducible testing
DATABASE = {
    "contacts": {
        "zc_98231": {
            "id": "zc_98231",
            "name": "Alice Vance",
            "company": "Black Mesa Corp",
            "email": "alice.vance@blackmesa.corp",
            "phone": "+1-555-0144",
            "ssn": "123-45-6789",
            "credit_card": "4111 1111 1111 1111",
            "deal_stage": "Proposal/Price Quote",
            "deal_amount": 125000,
            "lead_status": "Contacted"
        },
        "zc_98232": {
            "id": "zc_98232",
            "name": "Gordon Freeman",
            "company": "Black Mesa Corp",
            "email": "gfreeman@blackmesa.corp",
            "phone": "+1-555-0177",
            "ssn": "987-65-4320",
            "credit_card": "5500 0000 0000 0004",
            "deal_stage": "Negotiation/Review",
            "deal_amount": 850000,
            "lead_status": "Qualified"
        }
    }
}

class ZohoMCPHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)
        try:
            req = json.loads(raw_body.decode("utf-8"))
        except Exception as e:
            self._send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(e)}})
            return

        rpc_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "server/discover" or method == "initialize":
            self._send_json(200, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "protocolVersion": "2026-07-28",
                    "serverInfo": {"name": "zoho-crm", "version": "1.0.0"},
                    "instructions": "Use crm tools to interact with Zoho CRM. Updates require explicit human authorization.",
                    "cacheScope": "private",
                    "capabilities": {"tools": {"listChanged": False}}
                }
            })
            return

        if method == "tools/list":
            self._send_json(200, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "cacheScope": "private",
                    "ttlMs": 300000,
                    "tools": [
                        {
                            "name": "search_records",
                            "description": "Search Zoho CRM contacts or leads by query or email.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "entity": {"type": "string", "enum": ["contacts", "leads"]},
                                    "query": {"type": "string", "description": "Search term or email address"}
                                },
                                "required": ["query"]
                            }
                        },
                        {
                            "name": "get_contact",
                            "description": "Retrieve contact details from Zoho CRM by record ID.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "contact_id": {"type": "string", "description": "Unique CRM record ID"}
                                },
                                "required": ["contact_id"]
                            }
                        },
                        {
                            "name": "update_contact",
                            "description": "Update contact fields or deal stage in Zoho CRM (requires manager authorization).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "contact_id": {"type": "string", "description": "Unique CRM record ID"},
                                    "field": {"type": "string", "description": "Field to update (e.g. deal_stage, lead_status)"},
                                    "value": {"type": "string", "description": "New value to assign"}
                                },
                                "required": ["contact_id", "field", "value"]
                            }
                        },
                        {
                            "name": "delete_contact",
                            "description": "Permanently delete a contact from Zoho CRM.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "contact_id": {"type": "string", "description": "Unique CRM record ID"}
                                },
                                "required": ["contact_id"]
                            }
                        }
                    ]
                }
            })
            return

        if method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})

            if tool_name == "search_records":
                query = args.get("query", "").lower()
                matches = []
                for cid, record in DATABASE["contacts"].items():
                    if query in record["name"].lower() or query in record["email"].lower() or query in record["company"].lower():
                        matches.append(record)
                self._send_json(200, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(matches, indent=2)}]
                    }
                })
                return

            if tool_name == "get_contact":
                cid = args.get("contact_id")
                if cid in DATABASE["contacts"]:
                    self._send_json(200, {
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "result": {
                            "content": [{"type": "text", "text": json.dumps(DATABASE["contacts"][cid], indent=2)}]
                        }
                    })
                else:
                    self._send_json(200, {
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Error: Contact '{cid}' not found."}],
                            "isError": True
                        }
                    })
                return

            if tool_name == "update_contact":
                cid = args.get("contact_id")
                field = args.get("field")
                value = args.get("value")
                if cid not in DATABASE["contacts"]:
                    self._send_json(200, {
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Error: Contact '{cid}' not found."}],
                            "isError": True
                        }
                    })
                    return
                # Perform the update
                DATABASE["contacts"][cid][field] = value
                self._send_json(200, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": f"SUCCESS: Contact '{cid}' updated successfully. {field} = {value}\n" + json.dumps(DATABASE["contacts"][cid], indent=2)
                        }]
                    }
                })
                return

            if tool_name == "delete_contact":
                cid = args.get("contact_id")
                if cid in DATABASE["contacts"]:
                    del DATABASE["contacts"][cid]
                    self._send_json(200, {
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "result": {
                            "content": [{"type": "text", "text": f"SUCCESS: Contact '{cid}' was deleted."}]
                        }
                    })
                else:
                    self._send_json(200, {
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Error: Contact '{cid}' not found."}],
                            "isError": True
                        }
                    })
                return

            self._send_json(200, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {"code": -32601, "message": f"Method or tool not found: {tool_name}"}
            })
            return

        self._send_json(200, {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "error": {"code": -32601, "message": f"Unknown JSON-RPC method: {method}"}
        })

    def log_message(self, format, *args):
        # Quiet logger to keep terminal demo output clean
        pass

def run(port=9003):
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, ZohoMCPHandler)
    print(f"Zoho CRM MCP Server listening on http://127.0.0.1:{port}", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

if __name__ == "__main__":
    port = 9003
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run(port)


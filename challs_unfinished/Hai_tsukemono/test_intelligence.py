#!/usr/bin/env python3
"""
Test Intelligence Submission
Author: Claude
Purpose: Test submitting intelligence data related to Echo 7's corruptions
Created: 2025-11-23
Updated: 2025-11-23
Expected Result: Understand if intelligence submission affects filter validation
Produced Result: TBD
"""

import requests
import json

MCP_URL = "http://154.57.164.74:31735/mcp/"
API_KEY = "12dabdc12a07f60655eefd6745674e98e32e1a3b42f2e1383844d1f79235e7f6"

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
            "clientInfo": {"name": "intel", "version": "1.0"}
        })

    def submit_intelligence(self, data_type, payload):
        return self.send_request("tools/call", {
            "name": "submit_intelligence",
            "arguments": {
                "ally_api_key": API_KEY,
                "data_type": data_type,
                "payload": json.dumps(payload)
            }
        })

client = MCPClient(MCP_URL)
client.initialize()

print("="*60)
print("Testing Intelligence Submission")
print("="*60)

# Test different data types with corruption-related data
test_cases = [
    ("corruption", {"echo_id": 7, "type": "Sentiment", "value": "Whimsy"}),
    ("corruption", {"echo_id": 7, "type": "Principle", "value": "Anarchy"}),
    ("echo", {"id": 7, "corruptions": [
        {"type": "Sentiment", "value": "Whimsy"},
        {"type": "Principle", "value": "Anarchy"}
    ]}),
    ("filter", {"echo": 7, "purge": ["Whimsy", "Anarchy"]}),
    ("Intel", {"target": "Echo 7", "corruptions": "Whimsy, Anarchy"}),
    ("Target_Profile", {"id": 7, "name": "Wandering Trickster", "corruptions": ["Whimsy", "Anarchy"]}),
]

for data_type, payload in test_cases:
    print(f"\n[*] Submitting {data_type}: {payload}")
    result = client.submit_intelligence(data_type, payload)

    if "result" in result and "content" in result["result"]:
        for item in result["result"]["content"]:
            if "text" in item:
                print(f"    Result: {item['text']}")
    else:
        print(f"    Result: {json.dumps(result, indent=2)}")

print("\n" + "="*60)
print("Done!")
print("="*60)

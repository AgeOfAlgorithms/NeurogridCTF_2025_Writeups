#!/usr/bin/env python3
"""
Retry Filters After Intelligence Submission
Author: Claude
Purpose: Test if intelligence submissions changed expected filter format
Created: 2025-11-23
Updated: 2025-11-23
Expected Result: Find if filter validation changed after intelligence submission
Produced Result: TBD
"""

import requests
import json
import base64
import pickle

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
            "clientInfo": {"name": "retry", "version": "1.0"}
        })

    def submit_filter(self, filter_obj, desc=""):
        pickled = pickle.dumps(filter_obj)
        encoded = base64.b64encode(pickled).decode('ascii')

        result = self.send_request("tools/call", {
            "name": "submit_convergence_filter",
            "arguments": {
                "ally_api_key": API_KEY,
                "filter_object": encoded
            }
        })

        if "result" in result and "content" in result["result"]:
            for item in result["result"]["content"]:
                if "text" in item:
                    print(f"{desc}: {item['text']}")
                    return item['text']
        return None

client = MCPClient(MCP_URL)
client.initialize()

print("="*60)
print("Retrying Filters After Intelligence Submission")
print("="*60)

# Try various filter formats again
test_cases = [
    # Simple types
    ({"echo": 7, "purge": ["Whimsy", "Anarchy"]}, "Dict with purge"),
    ([("Sentiment", "Whimsy"), ("Principle", "Anarchy")], "List of tuples"),
    ({"corruptions": [{"type": "Sentiment", "value": "Whimsy"}, {"type": "Principle", "value": "Anarchy"}]}, "Corruption dict"),

    # Japanese characters (user hint: "chinese character")
    ("祓", "Purification kanji"),
    ("浄化", "Purification word (jouka)"),
    ("濾過", "Filtration word (roka)"),

    # Corruption values themselves (user said they're significant)
    ("Whimsy", "First corruption value"),
    ("Anarchy", "Second corruption value"),
    (("Whimsy", "Anarchy"), "Both corruption values as tuple"),

    # Protocol-related
    ({"protocol": "Ash-Data Convergence Protocol v1.1"}, "Protocol dict"),
    ({"version": "1.1", "protocol": "ash-data"}, "Version dict"),
]

for filter_obj, desc in test_cases:
    print(f"\n[*] Testing: {desc}")
    print(f"    Filter: {repr(filter_obj)}")
    result = client.submit_filter(filter_obj, f"  ")

    # Check if we got a different response
    if result and "not in the expected protocol format" not in result:
        print(f"\n!!! DIFFERENT RESPONSE !!!")
        print(f"Filter: {filter_obj}")
        print(f"Response: {result}")

print("\n" + "="*60)
print("Done!")
print("="*60)

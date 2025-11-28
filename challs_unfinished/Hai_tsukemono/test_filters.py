#!/usr/bin/env python3
"""
Test Convergence Filters
Author: Claude
Purpose: Test unconventional filter approaches based on "outside the box" hint
Created: 2025-11-23
Updated: 2025-11-23
Expected Result: Find the correct filter format that passes protocol validation
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

    def submit_filter(self, filter_obj, description=""):
        """Submit a convergence filter"""
        pickled = pickle.dumps(filter_obj)
        encoded = base64.b64encode(pickled).decode('ascii')

        result = self.send_request("tools/call", {
            "name": "submit_convergence_filter",
            "arguments": {
                "ally_api_key": ALLY_KEY,
                "filter_object": encoded
            }
        })

        if "result" in result and "content" in result["result"]:
            for item in result["result"]["content"]:
                if "text" in item:
                    print(f"{description}: {item['text']}")
        elif "error" in result:
            print(f"{description}: ERROR - {result['error']['message']}")
        else:
            print(f"{description}: {json.dumps(result, indent=2)}")

        return result

client = MCPClient(MCP_URL)
client.initialize()

print("="*60)
print("Testing Unconventional Filter Formats")
print("="*60)

# Based on "outside the box" hint - Japanese characters related to purification
test_cases = [
    # Japanese purification/cleansing characters
    ("祓", "Purification character (harae)"),
    ("浄", "Purification character (jou)"),
    ("濾", "Filter character (ro)"),
    ("灰", "Ash character (hai) - from challenge name"),
    ("漬", "Pickle character (tsuke) - from challenge name"),

    # Corruption values themselves
    ("Whimsy", "Corruption value 1"),
    ("Anarchy", "Corruption value 2"),

    # Tuple of corruption values (user said these are significant)
    (("Sentiment", "Whimsy"), "Corruption 12 as tuple"),
    (("Principle", "Anarchy"), "Corruption 13 as tuple"),
    ([("Sentiment", "Whimsy"), ("Principle", "Anarchy")], "Both corruptions as list of tuples"),

    # Corruption IDs
    ([12, 13], "Corruption IDs as list"),
    ((12, 13), "Corruption IDs as tuple"),
    (set([12, 13]), "Corruption IDs as set"),

    # Echo ID
    (7, "Echo ID"),

    # Special combinations
    ({"echo": 7, "corruptions": [12, 13]}, "Echo with corruption IDs"),
    ({"Sentiment": "Whimsy", "Principle": "Anarchy"}, "Corruption types to values"),
]

for filter_obj, description in test_cases:
    print(f"\n[*] Testing: {description}")
    print(f"    Filter: {repr(filter_obj)}")
    client.submit_filter(filter_obj, f"  Result")

print("\n" + "="*60)
print("Done!")
print("="*60)

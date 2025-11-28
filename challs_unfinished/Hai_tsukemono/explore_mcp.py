#!/usr/bin/env python3
"""
MCP Explorer for Hai Tsukemono
Author: Claude
Purpose: Explore the MCP server and test filter submissions
Created: 2025-11-23
Updated: 2025-11-23
Expected Result: List tools, resources, and test filter submission
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

        cookies = {}
        if self.session_id:
            headers["mcp-session-id"] = self.session_id

        resp = requests.post(self.url, json=payload, headers=headers, cookies=cookies)

        # Check for MCP-Session-ID header
        if "mcp-session-id" in resp.headers:
            self.session_id = resp.headers["mcp-session-id"]
            if method == "initialize":
                print(f"[*] Session ID: {self.session_id}")

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
        print(f"[+] Initialized: {result}")
        return result

    def list_tools(self):
        """List available tools"""
        result = self.send_request("tools/list", {})
        print(f"\n[+] Tools:")
        if "result" in result and "tools" in result["result"]:
            for tool in result["result"]["tools"]:
                print(f"  - {tool['name']}")
                if "description" in tool:
                    print(f"    {tool['description']}")
        return result

    def list_resources(self):
        """List available resources"""
        result = self.send_request("resources/list", {})
        print(f"\n[+] Resources:")
        if "result" in result and "resources" in result["result"]:
            for res in result["result"]["resources"]:
                print(f"  - {res['uri']}")
        return result

    def list_prompts(self):
        """List available prompts"""
        result = self.send_request("prompts/list", {})
        print(f"\n[+] Prompts:")
        if "result" in result and "prompts" in result["result"]:
            for prompt in result["result"]["prompts"]:
                print(f"  - {prompt['name']}")
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

# Main exploration
print("="*60)
print("Hai Tsukemono MCP Explorer")
print("="*60)

client = MCPClient(MCP_URL)
client.initialize()
client.list_tools()
client.list_resources()
client.list_prompts()

print("\n" + "="*60)
print("Testing Echo 7 Profile Access")
print("="*60)

echo7 = client.read_resource("ash-data://echo/profile/7")
print(json.dumps(echo7, indent=2))

print("\n" + "="*60)
print("Done!")
print("="*60)
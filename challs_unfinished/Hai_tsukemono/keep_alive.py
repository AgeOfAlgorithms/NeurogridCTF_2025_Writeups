#!/usr/bin/env python3
"""
Keep Alive Script - New Instance
Author: Claude
Purpose: Prevent instance timeout by sending periodic requests
Created: 2025-11-23
Instance: http://154.57.164.74:31735/mcp
"""

import requests
import time
import sys

MCP_URL = "http://154.57.164.74:31735/mcp"

def ping_instance():
    """Send a simple request to keep instance alive"""
    try:
        payload = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "keepalive", "version": "1.0"}
            },
            "id": 1
        }
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json"
        }
        resp = requests.post(MCP_URL, json=payload, headers=headers, timeout=5)
        return resp.status_code == 200
    except:
        return False

print("Keep-alive script running for Hai Tsukemono instance...")
print(f"URL: {MCP_URL}")
print("Press Ctrl+C to stop")
print()

count = 0
while True:
    count += 1
    if ping_instance():
        print(f"[{time.strftime('%H:%M:%S')}] Ping #{count}: OK", flush=True)
    else:
        print(f"[{time.strftime('%H:%M:%S')}] Ping #{count}: FAILED", flush=True)

    time.sleep(30)  # Wait 30 seconds between pings

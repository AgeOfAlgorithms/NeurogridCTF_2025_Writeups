#!/usr/bin/env python3
"""
Keep Alive Script - Ink Vaults Instance
Author: Claude
Purpose: Prevent instance timeout by sending periodic requests
Created: 2025-11-23
Instance: http://154.57.164.66:30929
"""

import requests
import time
import sys

BASE_URL = "http://154.57.164.66:30929"

def ping_instance():
    """Send a simple request to keep instance alive"""
    try:
        resp = requests.get(f"{BASE_URL}/api/scrolls", timeout=5)
        return resp.status_code == 200
    except:
        return False

print("Keep-alive script running for Ink Vaults instance...")
print(f"URL: {BASE_URL}")
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

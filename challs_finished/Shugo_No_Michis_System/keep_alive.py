#!/usr/bin/env python3
"""
Keep Alive Script - Shugo No Michi's System
Author: Claude
Purpose: Keep HTB challenge instance alive and restart if necessary
Created: 2025-11-23
Challenge ID: 63384
Instance: http://154.57.164.75:31929
"""

import requests
import time
import sys
from datetime import datetime

CHALLENGE_ID = 63384
WEB_URL = "http://154.57.164.75:31929"
HTB_API_BASE = "https://ctf.hackthebox.com/api"

def log(message):
    """Print timestamped log message"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] {message}", flush=True)

def check_container_status():
    """Check container status via HTB API"""
    try:
        # Note: This would require HTB authentication
        # For now, we'll rely on HTTP ping
        return None
    except:
        return None

def ping_instance():
    """Send HTTP request to keep instance alive"""
    try:
        resp = requests.get(WEB_URL, timeout=10)
        return resp.status_code in [200, 301, 302, 403, 404]  # Any valid HTTP response
    except requests.exceptions.Timeout:
        return False
    except requests.exceptions.ConnectionError:
        return False
    except Exception as e:
        log(f"Error: {e}")
        return False

def main():
    log("=== Keep-alive script started ===")
    log(f"Challenge: Shugo No Michi's System (ID: {CHALLENGE_ID})")
    log(f"URL: {WEB_URL}")
    log("Press Ctrl+C to stop")
    log("")

    ping_count = 0
    fail_count = 0

    try:
        while True:
            ping_count += 1

            if ping_instance():
                log(f"Ping #{ping_count}: ✓ Instance is alive")
                fail_count = 0
            else:
                fail_count += 1
                log(f"Ping #{ping_count}: ✗ Instance unreachable (fail count: {fail_count})")

                if fail_count >= 3:
                    log("WARNING: Instance has been unreachable for 3 consecutive attempts!")
                    log("You may need to manually restart the container via HTB CTF platform")
                    log("Or use the htb-mcp-ctf MCP tools to restart it")

            # Wait 30 seconds between pings
            time.sleep(30)

    except KeyboardInterrupt:
        log("")
        log("=== Keep-alive script stopped ===")
        log(f"Total pings sent: {ping_count}")
        sys.exit(0)

if __name__ == "__main__":
    main()

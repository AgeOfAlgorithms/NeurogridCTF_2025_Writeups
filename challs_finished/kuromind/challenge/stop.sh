#!/bin/bash

echo "Stopping Kuromind application..."

# Stop the container
echo "Stopping container..."
docker stop kuromind-container 2>/dev/null || echo "Container not running"

# Remove the container
echo "Removing container..."
docker rm kuromind-container 2>/dev/null || echo "Container not found"

echo "Kuromind application stopped and cleaned up!"

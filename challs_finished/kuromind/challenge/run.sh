#!/bin/bash

# Build the Docker image
echo "Building Docker image..."
docker build -t kuromind .

# Stop and remove any existing container with the same name
echo "Stopping and removing existing container (if any)..."
docker stop kuromind-container 2>/dev/null || true
docker rm kuromind-container 2>/dev/null || true

# Run the container
echo "Starting container..."
docker run -d \
  --name kuromind-container \
  -p 80:80 \
  kuromind

echo "Container started successfully!"
echo "Application is running at http://127.0.0.1:80"
echo ""
echo "To view logs: docker logs kuromind-container"
echo "To stop: docker stop kuromind-container"
echo "To remove: docker rm kuromind-container"

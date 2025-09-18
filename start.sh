#!/bin/bash
# IptablesUI startup script for Linux/macOS systems

echo "🚀 Starting IptablesUI Docker container..."

# Check if we should build locally or use GitHub Container Registry
if [ "$1" = "--local" ]; then
    echo "📦 Building Docker image locally..."
    docker build -t iptablesui .
    IMAGE_NAME="iptablesui"
else
    echo "📦 Using GitHub Container Registry image..."
    docker pull ghcr.io/unlink/iptablesui:latest
    IMAGE_NAME="ghcr.io/unlink/iptablesui:latest"
fi

if [ $? -eq 0 ]; then
    echo "✅ Docker image ready"
    
    # Stop existing container if running
    echo "🛑 Stopping existing container..."
    docker stop iptablesui 2>/dev/null
    docker rm iptablesui 2>/dev/null
    
    # Create data directory for persistence
    mkdir -p ./data
    
    # Start the container with proper capabilities
    echo "🔥 Starting container with NET_ADMIN capability..."
    docker run -d \
      --name iptablesui \
      --cap-add=NET_ADMIN \
      -p 8080:8080 \
      -e ADMIN_USER=${ADMIN_USER:-admin} \
      -e ADMIN_PASS=${ADMIN_PASS:-password} \
      -e SECRET_KEY=${SECRET_KEY:-$(openssl rand -base64 32)} \
      -v "$(pwd)/data:/app/data" \
      $IMAGE_NAME
    
    if [ $? -eq 0 ]; then
        echo "✅ Container started successfully"
        echo "🌐 Access the application at: http://localhost:8080"
        echo "👤 Username: ${ADMIN_USER:-admin}"
        echo "🔐 Password: ${ADMIN_PASS:-password}"
        echo ""
        echo "📝 To view logs: docker logs iptablesui"
        echo "🛑 To stop: docker stop iptablesui"
        echo "🔧 For WireGuard integration, use: docker-compose up -d"
    else
        echo "❌ Failed to start container"
        exit 1
    fi
else
    echo "❌ Failed to build Docker image"
    exit 1
fi
#!/bin/bash

# S6 Overlay Health Check Script
# This script can be used to verify that all S6 services are running correctly

set -e

echo "🔍 S6 Overlay Service Health Check"
echo "=================================="

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're running inside container
if [ ! -f "/init" ]; then
    print_error "This script should be run inside the S6 overlay container"
    exit 1
fi

print_status "Checking S6 overlay services..."

# Check S6 overlay is running
if pgrep s6-supervise >/dev/null; then
    print_success "S6 supervisor is running"
else
    print_error "S6 supervisor is not running"
    exit 1
fi

# Check individual services
SERVICES=("networking-setup" "wireguard-setup" "iptablesui")

for service in "${SERVICES[@]}"; do
    if [ -d "/run/service/$service" ]; then
        STATUS=$(s6-svstat "/run/service/$service" 2>/dev/null || echo "unknown")
        
        if echo "$STATUS" | grep -q "up"; then
            if [ "$service" = "iptablesui" ]; then
                print_success "Service $service is running (long-run service)"
            else
                print_success "Service $service completed successfully (oneshot service)"
            fi
        elif echo "$STATUS" | grep -q "down"; then
            if [ "$service" = "iptablesui" ]; then
                print_error "Service $service is down (should be running)"
            else
                print_warning "Service $service is down (normal for oneshot services)"
            fi
        else
            print_warning "Service $service status: $STATUS"
        fi
    else
        print_error "Service directory for $service not found"
    fi
done

echo

# Check networking
print_status "Checking networking configuration..."

if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
    print_success "IP forwarding is enabled"
else
    print_warning "IP forwarding is disabled"
fi

if [ "$(cat /proc/sys/net/ipv4/conf/all/src_valid_mark)" = "1" ]; then
    print_success "Source validation mark is set"
else
    print_warning "Source validation mark is not set"
fi

echo

# Check WireGuard
print_status "Checking WireGuard status..."

if command -v wg >/dev/null 2>&1; then
    if wg show wg0 >/dev/null 2>&1; then
        PEER_COUNT=$(wg show wg0 | grep -c "^peer:" || echo "0")
        print_success "WireGuard interface wg0 is running with $PEER_COUNT peers"
    else
        print_warning "WireGuard interface wg0 is not running (may not be configured yet)"
    fi
else
    print_error "WireGuard tools not found"
fi

echo

# Check Flask app
print_status "Checking Flask application..."

if curl -s -f http://localhost:8080/login >/dev/null 2>&1; then
    print_success "Flask web interface is responding on port 8080"
else
    print_error "Flask web interface is not responding"
fi

if pgrep -f "python app.py" >/dev/null; then
    print_success "Flask Python process is running"
else
    print_error "Flask Python process is not running"
fi

echo

# Summary
print_status "Health check completed"

if s6-svstat /run/service/* 2>/dev/null | grep -q "up"; then
    print_success "S6 services appear to be healthy"
    exit 0
else
    print_error "Some S6 services may have issues"
    exit 1
fi
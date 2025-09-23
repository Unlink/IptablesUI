#!/bin/bash

# IptablesUI with WireGuard startup script
# This script helps set up and run the combined container

set -e

echo "🚀 Starting IptablesUI with WireGuard Server..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-change_me_please}"
WEB_PORT="${WEB_PORT:-8080}"
WG_PORT="${WG_PORT:-51820}"
CONTAINER_NAME="${CONTAINER_NAME:-iptablesui-wireguard}"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check requirements
check_requirements() {
    print_status "Checking system requirements..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if running as root or in docker group
    if [ "$EUID" -ne 0 ] && ! groups | grep -q docker; then
        print_warning "You may need to run this script with sudo or add your user to the docker group"
    fi
    
    print_success "Requirements check passed"
}

# Function to create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    mkdir -p ./data
    mkdir -p ./wireguard
    
    # Set proper permissions
    chmod 755 ./data
    chmod 700 ./wireguard  # More restrictive for VPN configs
    
    print_success "Directories created"
}

# Function to check for port conflicts
check_ports() {
    print_status "Checking for port conflicts..."
    
    # Check web port
    if netstat -tuln 2>/dev/null | grep -q ":${WEB_PORT} "; then
        print_warning "Port ${WEB_PORT} is already in use. You may need to change WEB_PORT."
    fi
    
    # Check WireGuard port
    if netstat -tuln 2>/dev/null | grep -q ":${WG_PORT} "; then
        print_warning "Port ${WG_PORT} is already in use. You may need to change WG_PORT."
    fi
}

# Function to generate secure password if default is used
generate_password() {
    if [ "$ADMIN_PASS" = "change_me_please" ]; then
        print_warning "Using default password. Generating secure password..."
        ADMIN_PASS=$(openssl rand -base64 12 2>/dev/null || head -c 12 /dev/urandom | base64)
        print_status "Generated password: ${ADMIN_PASS}"
        echo "ADMIN_PASS=${ADMIN_PASS}" >> .env
    fi
}

# Function to start the services
start_services() {
    print_status "Starting services..."
    
    # Stop existing container if running
    if docker ps -a --format 'table {{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        print_status "Stopping existing container..."
        docker stop "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true
    fi
    
    # Start with docker-compose
    if [ -f "docker-compose.yml" ]; then
        ADMIN_USER="$ADMIN_USER" ADMIN_PASS="$ADMIN_PASS" docker-compose up -d
    else
        print_error "docker-compose.yml not found. Please ensure you're in the correct directory."
        exit 1
    fi
    
    print_success "Services started"
}

# Function to wait for service to be ready
wait_for_service() {
    print_status "Waiting for service to be ready..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -f "http://localhost:${WEB_PORT}/login" > /dev/null 2>&1; then
            print_success "Service is ready!"
            break
        fi
        
        print_status "Attempt $attempt/$max_attempts - waiting for service..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    if [ $attempt -gt $max_attempts ]; then
        print_error "Service did not start within expected time"
        print_status "Check logs with: docker-compose logs"
        exit 1
    fi
}

# Function to show service information
show_info() {
    print_success "🎉 IptablesUI with WireGuard is now running!"
    echo
    echo "📱 Web Interface: http://localhost:${WEB_PORT}"
    echo "👤 Username: ${ADMIN_USER}"
    echo "🔑 Password: ${ADMIN_PASS}"
    echo "🔌 WireGuard Port: ${WG_PORT}/udp"
    echo
    print_status "Next steps:"
    echo "  1. Open the web interface in your browser"
    echo "  2. Go to WireGuard tab to configure your VPN server"
    echo "  3. Add iptables rules in the Dashboard tab"
    echo "  4. Create VPN peers for your clients"
    echo
    print_status "Useful commands:"
    echo "  • View logs: docker-compose logs -f"
    echo "  • Stop services: docker-compose down"
    echo "  • Restart services: docker-compose restart"
    echo "  • Update: docker-compose pull && docker-compose up -d"
}

# Function to handle cleanup on script exit
cleanup() {
    if [ $? -ne 0 ]; then
        print_error "Script failed. Check logs with: docker-compose logs"
    fi
}

# Main execution
main() {
    echo -e "${BLUE}╔══════════════════════════════════════╗"
    echo -e "║     IptablesUI + WireGuard Setup     ║"
    echo -e "║        Single Container Solution      ║"
    echo -e "╚══════════════════════════════════════╝${NC}"
    echo
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    # Run setup steps
    check_requirements
    create_directories
    check_ports
    generate_password
    start_services
    wait_for_service
    show_info
}

# Handle command line arguments
case "${1:-}" in
    stop)
        print_status "Stopping services..."
        docker-compose down
        print_success "Services stopped"
        ;;
    restart)
        print_status "Restarting services..."
        docker-compose restart
        print_success "Services restarted"
        ;;
    logs)
        docker-compose logs -f
        ;;
    status)
        docker-compose ps
        ;;
    update)
        print_status "Updating services..."
        docker-compose pull
        docker-compose up -d
        print_success "Services updated"
        ;;
    clean)
        print_warning "This will remove all containers and volumes!"
        read -p "Are you sure? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            docker-compose down -v
            docker system prune -f
            print_success "Cleanup completed"
        fi
        ;;
    *)
        main
        ;;
esac
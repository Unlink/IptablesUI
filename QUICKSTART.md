# IptablesUI + WireGuard VPN Server

**Single container solution** for managing iptables firewall rules and running WireGuard VPN server.

## 🚀 Quick Start

```bash
# Clone and start
git clone <repository-url>
cd IptablesUI
docker-compose up -d

# Access web interface
open http://localhost:8080
# Login: admin / change_me_please
```

## 🔧 What's Included

- **Web-based iptables management**: Add, edit, delete firewall rules
- **WireGuard VPN Server**: Built-in VPN server management  
- **Peer Management**: Add VPN clients, generate configs, QR codes
- **Real-time Monitoring**: Connection status, traffic statistics
- **Single Container**: No need for multiple containers
- **S6 Overlay**: Robust service management and process supervision

## 📋 Requirements

- Docker with `--cap-add NET_ADMIN` support
- Linux kernel with WireGuard support (most modern distros)

## ⚙️ Configuration

1. **Copy configuration**: `cp .env.example .env`
2. **Edit credentials**: Change `ADMIN_PASS` in `.env`
3. **Start services**: `docker-compose up -d`
4. **Configure WireGuard**: Use web interface → WireGuard tab

## 🌐 Access

- **Web Interface**: http://localhost:8080
- **WireGuard Port**: 51820/udp
- **Default Login**: admin / change_me_please

## 📚 Full Documentation

See [README-WIREGUARD.md](README-WIREGUARD.md) for complete documentation.

## 🛠️ Quick Commands

```bash
# Start services
docker-compose up -d

# View logs  
docker-compose logs -f

# Stop services
docker-compose down

# Update
docker-compose pull && docker-compose up -d
```
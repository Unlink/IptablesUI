# IptablesUI with WireGuard Server Integration

Comprehensive web-based interface for managing iptables rules and WireGuard VPN server in a single container.

## Features

### Iptables Management
- **Complete Rule Management**: View, add, edit, and delete all iptables rules (both app-managed and existing system rules)
- **Rule Priorities**: Move rules up/down to change priority order
- **Statistics Monitoring**: Real-time packet and byte counters with human-readable units (K/M/G)
- **Rule Persistence**: Automatically save and restore rules across container restarts
- **Batch Operations**: Apply multiple rule changes at once
- **Debug Tools**: Built-in endpoints for troubleshooting statistics and rule matching

### WireGuard VPN Server
- **Server Management**: Start, stop, and restart WireGuard interface through web UI
- **Server Configuration**: Configure listen port, network address, and server settings
- **Peer Management**: Add, remove, and manage VPN clients (peers)
- **Client Configuration**: Generate client configurations with QR codes
- **Connection Monitoring**: Real-time monitoring of active peer connections
- **Traffic Statistics**: Monitor data transfer per peer

### Security & Authentication
- **User Authentication**: Secure login with configurable credentials
- **Session Management**: Secure session handling with logout functionality
- **Docker Security**: Runs with minimal required privileges (NET_ADMIN only)

## Quick Start

### Option 1: Single Container (Recommended)
```bash
# Clone the repository
git clone <repository-url>
cd IptablesUI

# Start the combined service
docker compose up -d

# Access the web interface
open http://localhost:8080
```

### Option 2: Build from Source
```bash
# Build the image
docker build -t iptablesui-wireguard .

# Run with docker
docker run -d \
  --name iptablesui-wireguard \
  --cap-add NET_ADMIN \
  --cap-add SYS_MODULE \
  -p 8080:8080 \
  -p 51820:51820/udp \
  -v ./data:/app/data \
  -v ./wireguard:/etc/wireguard \
  -v /lib/modules:/lib/modules:ro \
  -e ADMIN_USER=admin \
  -e ADMIN_PASS=your_secure_password \
  iptablesui-wireguard
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_USER` | `admin` | Admin username for web interface |
| `ADMIN_PASS` | `password` | Admin password (change in production!) |
| `SECRET_KEY` | `auto-generated` | Flask session secret key |
| `FLASK_ENV` | `production` | Flask environment mode |
| `TZ` | `UTC` | Container timezone |

### Docker Compose Configuration

The application requires specific Docker capabilities and sysctls:

```yaml
cap_add:
  - NET_ADMIN   # Required for iptables and WireGuard commands
  - SYS_MODULE  # Required for WireGuard kernel module

sysctls:
  - net.ipv4.conf.all.src_valid_mark=1  # Required for WireGuard
  - net.ipv4.ip_forward=1               # Enable IP forwarding
```

### Volume Mounts

| Host Path | Container Path | Description |
|-----------|---------------|-------------|
| `./data` | `/app/data` | Persistent storage for rules.json and app data |
| `./wireguard` | `/etc/wireguard` | WireGuard server and peer configurations |
| `/lib/modules` | `/lib/modules:ro` | Kernel modules (read-only, required for WireGuard) |

## Usage Guide

### 1. Initial Setup

1. **Access Web Interface**: Navigate to `http://your-server-ip:8080`
2. **Login**: Use configured admin credentials
3. **Configure WireGuard Server**: 
   - Go to WireGuard tab
   - Set server address (e.g., `10.0.0.1/24`)
   - Set listen port (default: `51820`)
   - Save configuration

### 2. WireGuard Server Management

#### Server Configuration
- **Address**: Set the VPN network (e.g., `10.0.0.1/24`)
- **Listen Port**: UDP port for WireGuard connections (default: 51820)
- **Start/Stop/Restart**: Control server state through web interface

#### Adding VPN Clients
1. Click "Add Peer" in WireGuard tab
2. Enter a friendly name (e.g., "John's Phone")
3. System automatically generates:
   - Public/private key pair
   - Next available IP address
   - Client configuration file
4. Download or scan QR code to configure client

#### Managing Peers
- **View Active Connections**: See connected peers with transfer statistics
- **Remove Peers**: Delete peer access through web interface
- **Monitor Traffic**: Real-time data transfer monitoring

### 3. Iptables Rule Management

#### Viewing Rules
- **Dashboard**: Shows all system iptables rules
- **Rule Types**: Distinguishes between app-managed and system rules
- **Statistics**: Real-time packet/byte counters with automatic unit conversion

#### Adding Rules
- **Simple Interface**: Add rules through web form
- **Rule Types**: Support for ACCEPT, DROP, REJECT actions
- **Port/Protocol**: Configure specific ports and protocols
- **Source/Destination**: Set IP ranges and network filters

#### Rule Management
- **Priority Control**: Move rules up/down to change evaluation order
- **Bulk Operations**: Apply multiple changes simultaneously
- **Persistence**: Rules automatically saved and restored on restart

### 4. Monitoring & Debugging

#### Statistics Monitoring
- Real-time packet and byte counters
- Automatic unit conversion (K/M/G format)
- Per-rule transfer statistics

#### Debug Features
- `/api/debug/raw-iptables`: View raw iptables output
- `/api/debug/stats`: Detailed statistics matching information
- Enhanced logging for troubleshooting

## Security Considerations

### Network Security
- **Minimal Privileges**: Container runs with only required capabilities
- **IP Forwarding**: Properly configured for VPN traffic routing
- **Firewall Rules**: Iptables rules control all network traffic

### Access Control
- **Authentication Required**: All operations require login
- **Session Security**: Secure session management with logout
- **Configuration Protection**: Sensitive data properly protected

### VPN Security
- **Key Management**: Private keys generated securely and not exposed
- **Peer Isolation**: Each peer gets unique IP and key pair
- **Traffic Encryption**: All VPN traffic encrypted with WireGuard protocol

## Troubleshooting

### Common Issues

#### Container Won't Start
- **Check Capabilities**: Ensure NET_ADMIN and SYS_MODULE are added
- **Kernel Modules**: Verify WireGuard modules available on host
- **Permissions**: Check volume mount permissions

#### WireGuard Not Working
- **Port Conflicts**: Ensure UDP port 51820 is available
- **IP Forwarding**: Verify sysctls are properly set
- **Firewall Rules**: Check host firewall allows UDP traffic

#### Statistics Not Updating
- **Rule Matching**: Use debug endpoints to check rule parsing
- **Statistics Format**: Verify iptables statistics enabled
- **Logging**: Check container logs for parsing errors

### Debug Commands

```bash
# Check container logs
docker logs iptablesui-wireguard

# Check WireGuard status
docker exec iptablesui-wireguard wg show

# Check iptables rules
docker exec iptablesui-wireguard iptables -L -v -n

# Test web interface health
curl -f http://localhost:8080/login
```

### Log Analysis
- **Web Access**: Monitor login attempts and API calls
- **Rule Changes**: Track iptables rule modifications
- **WireGuard Events**: Monitor VPN connection events
- **Error Detection**: Automatic error logging and reporting

## Advanced Configuration

### Custom Networks
- Configure custom Docker networks for isolation
- Set up multiple VPN networks for different user groups
- Implement network segmentation with iptables rules

### Integration
- **Monitoring Systems**: Export metrics for Prometheus/Grafana
- **Automation**: Use API endpoints for automation scripts
- **Backup**: Regular backup of rules.json and WireGuard configs

### Performance Tuning
- **Resource Limits**: Set appropriate CPU/memory limits
- **Network Optimization**: Configure MTU and other network parameters
- **Rule Optimization**: Organize rules for optimal performance

## API Reference

### Authentication
- `POST /login`: User authentication
- `GET /logout`: User logout

### Iptables Management
- `GET /api/rules`: List all rules
- `POST /api/rules`: Add new rule
- `DELETE /api/rules/<id>`: Delete rule
- `POST /api/rules/<id>/up`: Move rule up
- `POST /api/rules/<id>/down`: Move rule down

### WireGuard Management
- `GET /api/wireguard/status`: Server status
- `POST /api/wireguard/start`: Start server
- `POST /api/wireguard/stop`: Stop server
- `GET /api/wireguard/peers`: List peers
- `POST /api/wireguard/peers`: Add peer
- `DELETE /api/wireguard/peers/<key>`: Remove peer

### Debug Endpoints
- `GET /api/debug/raw-iptables`: Raw iptables output
- `GET /api/debug/stats`: Statistics debugging info

## License

[Add your license information here]

## Contributing

[Add contribution guidelines here]

## Support

[Add support information here]
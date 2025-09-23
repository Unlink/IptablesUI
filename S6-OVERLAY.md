# S6 Overlay Service Management

This container uses [S6 Overlay](https://github.com/just-containers/s6-overlay) for robust service management instead of a custom entrypoint script.

## Service Architecture

The container runs three services in dependency order:

```
1. networking-setup (oneshot)  → Configure IP forwarding, sysctls
2. wireguard-setup (oneshot)   → Start WireGuard if configured  
3. iptablesui (longrun)        → Main Flask web application
```

## Services Description

### 1. networking-setup
- **Type**: Oneshot (runs once at startup)
- **Purpose**: Configure networking settings required for WireGuard VPN
- **Actions**:
  - Enable IP forwarding (`net.ipv4.ip_forward=1`)
  - Set source validation mark (`net.ipv4.conf.all.src_valid_mark=1`)
  - Disable reverse path filtering for VPN traffic

### 2. wireguard-setup  
- **Type**: Oneshot (runs once after networking-setup)
- **Purpose**: Initialize WireGuard VPN server if configured
- **Actions**:
  - Check for existing WireGuard configuration (`/etc/wireguard/wg0.conf`)
  - Validate configuration syntax
  - Start WireGuard interface if config is valid
  - Load saved iptables rules from application data

### 3. iptablesui
- **Type**: Longrun (persistent service)
- **Purpose**: Main Flask web application
- **Actions**:
  - Start the Python Flask web server on port 8080
  - Handle web interface for iptables and WireGuard management
  - Auto-restart on failure

## Service Dependencies

```
networking-setup (base)
    ↓
wireguard-setup (depends on networking-setup)
    ↓  
iptablesui (depends on wireguard-setup)
```

## Advantages of S6 Overlay

### ✅ **Proper Process Management**
- No zombie processes
- Proper signal handling
- Automatic restart of failed services
- Graceful shutdown sequence

### ✅ **Service Dependencies** 
- Guaranteed startup order
- Services wait for dependencies
- Parallel execution where possible

### ✅ **Logging & Monitoring**
- Built-in logging for all services
- Service status monitoring
- Health checks and restart policies

### ✅ **Production Ready**
- Battle-tested in many Docker images
- Handles edge cases (PID 1 problem, signal handling)
- Proper resource cleanup

## Service Files Location

```
/etc/s6-overlay/s6-rc.d/
├── networking-setup/
│   ├── type (oneshot)
│   └── up (script)
├── wireguard-setup/
│   ├── type (oneshot) 
│   ├── dependencies.d/networking-setup
│   └── up (script)
└── iptablesui/
    ├── type (longrun)
    ├── dependencies.d/wireguard-setup
    ├── run (main service script)
    └── finish (cleanup script)
```

## Environment Variables

S6 Overlay respects these environment variables:

- `S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0` - Don't timeout waiting for services
- `S6_VERBOSITY=1` - Control logging verbosity
- `S6_BEHAVIOUR_IF_STAGE2_FAILS=2` - Exit container if init fails

## Troubleshooting

### View Service Logs
```bash
# All services
docker logs iptablesui-wireguard

# Specific service (if needed)
docker exec iptablesui-wireguard s6-svc -u /run/service/iptablesui
```

### Check Service Status
```bash
docker exec iptablesui-wireguard s6-svstat /run/service/*
```

### Manual Service Control
```bash
# Restart Flask app
docker exec iptablesui-wireguard s6-svc -r /run/service/iptablesui

# Stop service
docker exec iptablesui-wireguard s6-svc -d /run/service/iptablesui
```

## Benefits vs Custom Entrypoint

| Aspect | Custom Script | S6 Overlay |
|--------|---------------|------------|
| Process Management | Manual | Automatic |
| Service Dependencies | Script logic | Built-in |
| Failure Handling | Custom code | Robust framework |
| Signal Handling | Manual | Proper PID 1 handling |
| Logging | Custom | Standardized |
| Restart Policies | Manual | Configurable |
| Production Ready | Depends on implementation | Battle-tested |

This makes the container much more reliable and production-ready! 🚀
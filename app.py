#!/usr/bin/env python3
"""
IptablesUI - Web GUI for managing iptables firewall rules
"""

import os
import json
import subprocess
import glob
import configparser
import re
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import subprocess
import re
import os
import json
import ipaddress
import secrets
import base64
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Template helper functions
def format_bytes(bytes_value):
    """Format bytes to human readable format"""
    # Handle None, empty string, or non-numeric values
    if not bytes_value or bytes_value == 0:
        return '0 B'
    
    try:
        bytes_value = float(bytes_value)
    except (TypeError, ValueError):
        return '0 B'
    
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.1f} TB"

def format_datetime(datetime_str):
    """Format datetime string to readable format"""
    if not datetime_str:
        return 'Unknown'
    
    try:
        dt = datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M')
    except:
        return datetime_str

# Register template filters manually
app.jinja_env.filters['format_bytes'] = format_bytes
app.jinja_env.filters['format_datetime'] = format_datetime

print(f"DEBUG: Registered filters: {list(app.jinja_env.filters.keys())}")
print(f"DEBUG: format_bytes filter: {app.jinja_env.filters.get('format_bytes')}")

# Configuration
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('ADMIN_PASS', 'password')
RULES_FILE = 'rules.json'
WG_CONFIG_DIR = '/etc/wireguard'
WG_INTERFACE = 'wg0'

def generate_wg_keys():
    """Generate WireGuard private and public key pair"""
    try:
        # Generate private key
        private_result = subprocess.run(['wg', 'genkey'], capture_output=True, text=True, check=True)
        private_key = private_result.stdout.strip()
        
        # Generate public key from private key
        public_result = subprocess.run(['wg', 'pubkey'], input=private_key, 
                                     capture_output=True, text=True, check=True)
        public_key = public_result.stdout.strip()
        
        return private_key, public_key
    except subprocess.CalledProcessError as e:
        print(f"Error generating WireGuard keys: {e}")
        return None, None

def get_wg_server_config():
    """Get current WireGuard server configuration"""
    config_file = f"{WG_CONFIG_DIR}/{WG_INTERFACE}.conf"
    
    if not os.path.exists(config_file):
        return None
        
    try:
        with open(config_file, 'r') as f:
            content = f.read()
            
        config = {
            'interface': WG_INTERFACE,
            'private_key': '',
            'listen_port': 51820,
            'address': '',
            'peers': []
        }
        
        lines = content.split('\n')
        current_section = None
        current_peer = None
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            if line == '[Interface]':
                current_section = 'interface'
                continue
            elif line == '[Peer]':
                if current_peer:
                    config['peers'].append(current_peer)
                current_peer = {
                    'public_key': '',
                    'allowed_ips': '',
                    'endpoint': '',
                    'persistent_keepalive': None
                }
                current_section = 'peer'
                continue
                
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if current_section == 'interface':
                    if key.lower() == 'privatekey':
                        config['private_key'] = value
                    elif key.lower() == 'listenport':
                        config['listen_port'] = int(value)
                    elif key.lower() == 'address':
                        config['address'] = value
                elif current_section == 'peer' and current_peer:
                    if key.lower() == 'publickey':
                        current_peer['public_key'] = value
                    elif key.lower() == 'allowedips':
                        current_peer['allowed_ips'] = value
                    elif key.lower() == 'endpoint':
                        current_peer['endpoint'] = value
                    elif key.lower() == 'persistentkeepalive':
                        current_peer['persistent_keepalive'] = int(value)
        
        # Add last peer if exists
        if current_peer:
            config['peers'].append(current_peer)
            
        return config
        
    except Exception as e:
        print(f"Error reading WireGuard config: {e}")
        return None

def save_wg_server_config(config):
    """Save WireGuard server configuration"""
    config_file = f"{WG_CONFIG_DIR}/{WG_INTERFACE}.conf"
    
    try:
        # Create config directory if it doesn't exist
        os.makedirs(WG_CONFIG_DIR, exist_ok=True)
        
        content = "[Interface]\n"
        content += f"PrivateKey = {config['private_key']}\n"
        content += f"Address = {config['address']}\n"
        content += f"ListenPort = {config['listen_port']}\n"
        content += "SaveConfig = true\n\n"
        
        for peer in config.get('peers', []):
            content += "[Peer]\n"
            content += f"PublicKey = {peer['public_key']}\n"
            content += f"AllowedIPs = {peer['allowed_ips']}\n"
            if peer.get('endpoint'):
                content += f"Endpoint = {peer['endpoint']}\n"
            if peer.get('persistent_keepalive'):
                content += f"PersistentKeepalive = {peer['persistent_keepalive']}\n"
            content += "\n"
        
        with open(config_file, 'w') as f:
            f.write(content)
        
        # Set proper permissions
        os.chmod(config_file, 0o600)
        return True
        
    except Exception as e:
        print(f"Error saving WireGuard config: {e}")
        return False

def start_wg_interface():
    """Start WireGuard interface"""
    try:
        # Stop interface if running
        subprocess.run(['wg-quick', 'down', WG_INTERFACE], 
                      capture_output=True, text=True)
        
        # Start interface
        result = subprocess.run(['wg-quick', 'up', WG_INTERFACE], 
                              capture_output=True, text=True, check=True)
        return True, "WireGuard interface started successfully"
    except subprocess.CalledProcessError as e:
        return False, f"Failed to start WireGuard: {e.stderr}"

def stop_wg_interface():
    """Stop WireGuard interface"""
    try:
        result = subprocess.run(['wg-quick', 'down', WG_INTERFACE], 
                              capture_output=True, text=True, check=True)
        return True, "WireGuard interface stopped successfully"
    except subprocess.CalledProcessError as e:
        return False, f"Failed to stop WireGuard: {e.stderr}"

def restart_wg_interface():
    """Restart WireGuard interface"""
    stop_success, stop_msg = stop_wg_interface()
    if stop_success or "is not a WireGuard interface" in stop_msg:
        return start_wg_interface()
    return False, stop_msg

def get_next_peer_ip(server_address):
    """Get next available IP address for new peer"""
    try:
        network = ipaddress.IPv4Network(server_address, strict=False)
        
        # Get existing peer IPs
        config = get_wg_server_config()
        used_ips = {str(network.network_address), str(network.broadcast_address)}
        
        if config and config.get('address'):
            # Add server IP
            server_ip = config['address'].split('/')[0]
            used_ips.add(server_ip)
            
            # Add peer IPs
            for peer in config.get('peers', []):
                for allowed_ip in peer.get('allowed_ips', '').split(','):
                    ip = allowed_ip.strip().split('/')[0]
                    used_ips.add(ip)
        
        # Find first available IP
        for ip in network.hosts():
            if str(ip) not in used_ips:
                return f"{ip}/{network.prefixlen}"
                
        return None
    except Exception as e:
        print(f"Error getting next peer IP: {e}")
        return None

def generate_peer_config(peer_name, server_config):
    """Generate client configuration for peer"""
    private_key, public_key = generate_wg_keys()
    if not private_key or not public_key:
        return None, None
        
    # Get next available IP
    peer_ip = get_next_peer_ip(server_config.get('address', '10.0.0.1/24'))
    if not peer_ip:
        return None, None
    
    # Generate server public key from private key
    try:
        server_public_result = subprocess.run(['wg', 'pubkey'], 
                                            input=server_config['private_key'], 
                                            capture_output=True, text=True, check=True)
        server_public_key = server_public_result.stdout.strip()
    except subprocess.CalledProcessError:
        return None, None
    
    peer_config = f"""[Interface]
PrivateKey = {private_key}
Address = {peer_ip}
DNS = 8.8.8.8

[Peer]
PublicKey = {server_public_key}
AllowedIPs = 0.0.0.0/0
Endpoint = YOUR_SERVER_IP:{server_config.get('listen_port', 51820)}
PersistentKeepalive = 25
"""
    
    peer_data = {
        'name': peer_name,
        'public_key': public_key,
        'private_key': private_key,
        'allowed_ips': peer_ip,
        'config': peer_config
    }
    
    return peer_data, public_key

def load_rules_config():
    """Load rules configuration from JSON file"""
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, 'r') as f:
                data = json.load(f)
                
            # Validate that data is a dictionary
            if isinstance(data, dict):
                return data
            elif isinstance(data, list):
                print(f"WARNING: rules.json contains list instead of dict, converting...")
                return {"rules": data, "last_updated": None, "auto_apply": True, "backup_original": True}
            else:
                print(f"WARNING: rules.json contains unexpected data type: {type(data)}, resetting...")
                return {"rules": [], "last_updated": None, "auto_apply": True, "backup_original": True}
                
        except Exception as e:
            print(f"Error loading rules config: {e}")
            return {"rules": [], "last_updated": None, "auto_apply": True, "backup_original": True}
    return {"rules": [], "last_updated": None, "auto_apply": True, "backup_original": True}

def save_rules_config(config):
    """Save rules configuration to JSON file"""
    try:
        config['last_updated'] = datetime.now().isoformat()
        with open(RULES_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving rules config: {e}")
        return False

def get_all_iptables_rules():
    """Get all current iptables rules from the system"""
    all_rules = []
    
    try:
        # Get rules with line numbers for easier management
        for chain in ['INPUT', 'FORWARD', 'OUTPUT']:
            result = subprocess.run(['iptables', '-L', chain, '-n', '--line-numbers'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for i, line in enumerate(lines):
                    if i < 2:  # Skip header lines
                        continue
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            # Generate a basic hash for the rule
                            rule_data = {
                                'chain': chain,
                                'action': parts[1] if len(parts) > 1 else '',
                                'protocol': parts[2] if len(parts) > 2 and parts[2] != 'all' else '',
                                'source_ip': parts[4] if len(parts) > 4 and parts[4] != '0.0.0.0/0' else '',
                                'destination_ip': parts[5] if len(parts) > 5 and parts[5] != '0.0.0.0/0' else ''
                            }
                            
                            rule = {
                                'chain': chain,
                                'line_number': int(parts[0]) if parts[0].isdigit() else 0,
                                'action': parts[1] if len(parts) > 1 else '',
                                'protocol': parts[2] if len(parts) > 2 and parts[2] != 'all' else '',
                                'source_ip': parts[4] if len(parts) > 4 and parts[4] != '0.0.0.0/0' else '',
                                'destination_ip': parts[5] if len(parts) > 5 and parts[5] != '0.0.0.0/0' else '',
                                'options': ' '.join(parts[6:]) if len(parts) > 6 else '',
                                'raw_rule': line.strip(),
                                'managed_by_app': False,  # Will be updated if found in config
                                'rule_hash': hash(f"{rule_data['chain']}-{rule_data['action']}-{rule_data['protocol']}-{rule_data['source_ip']}-{rule_data['destination_ip']}")
                            }
                            all_rules.append(rule)
    except Exception as e:
        print(f"Error getting iptables rules: {e}")
    
    return all_rules

def sync_rules_with_system():
    """Sync stored rules with current system state"""
    try:
        config = load_rules_config()
        print(f"DEBUG: loaded config type: {type(config)}, content: {config}")
        
        # Double-check config is a dictionary
        if not isinstance(config, dict):
            print(f"ERROR: config is not a dict, it's {type(config)}")
            config = {"rules": [], "last_updated": None, "auto_apply": True, "backup_original": True}
            
        system_rules = get_all_iptables_rules()
        
        # Mark rules that are managed by the app
        app_rule_hashes = set()
        rules_list = config.get('rules', [])
        
        if not isinstance(rules_list, list):
            print(f"WARNING: rules is not a list, it's {type(rules_list)}")
            rules_list = []
            
        for rule in rules_list:
            if isinstance(rule, dict) and 'rule_hash' in rule:
                app_rule_hashes.add(rule['rule_hash'])
        
        # Update system rules to show which are managed by app
        for rule in system_rules:
            rule_hash = hash(f"{rule['chain']}-{rule['action']}-{rule.get('protocol', '')}-{rule.get('source_ip', '')}-{rule.get('destination_ip', '')}")
            rule['rule_hash'] = rule_hash
            if rule_hash in app_rule_hashes:
                rule['managed_by_app'] = True
        
        return system_rules
        
    except Exception as e:
        print(f"ERROR in sync_rules_with_system: {e}")
        return get_all_iptables_rules()  # Fallback to just system rules

def apply_saved_rules():
    """Apply all saved rules to the system"""
    config = load_rules_config()
    applied_count = 0
    errors = []
    
    for rule in config.get('rules', []):
        try:
            # Build iptables command from rule
            cmd = ['iptables', '-A', rule['chain']]
            
            if rule.get('protocol'):
                cmd.extend(['-p', rule['protocol']])
            if rule.get('source_ip') and rule['source_ip'] != '0.0.0.0/0':
                cmd.extend(['-s', rule['source_ip']])
            if rule.get('destination_ip') and rule['destination_ip'] != '0.0.0.0/0':
                cmd.extend(['-d', rule['destination_ip']])
            if rule.get('port'):
                cmd.extend(['--dport', str(rule['port'])])
            
            cmd.extend(['-j', rule['action']])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                applied_count += 1
            else:
                errors.append(f"Failed to apply rule: {' '.join(cmd)} - {result.stderr}")
                
        except Exception as e:
            errors.append(f"Error applying rule {rule}: {e}")
    
    return applied_count, errors

def get_wireguard_status():
    """Get WireGuard interface status and active connections"""
    status_info = {
        'interface_up': False,
        'active_peers': [],
        'server_ip': None,
        'interface_name': None
    }
    
    try:
        # First, detect WireGuard interface
        wg_interfaces = []
        
        # Try to find any WireGuard interface
        result = subprocess.run(['wg'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            # Parse interface names from wg output
            for line in result.stdout.split('\n'):
                if line.startswith('interface:'):
                    interface_name = line.split('interface: ')[1].strip()
                    wg_interfaces.append(interface_name)
        
        # If no interfaces found with wg, try common names
        if not wg_interfaces:
            for iface in ['wg0', 'wg1', 'wg-server', 'wireguard']:
                result = subprocess.run(
                    ['ip', 'addr', 'show', iface], 
                    capture_output=True, 
                    text=True
                )
                if result.returncode == 0:
                    wg_interfaces.append(iface)
                    break
        
        if not wg_interfaces:
            return status_info
            
        # Use first found interface
        wg_interface = wg_interfaces[0]
        status_info['interface_name'] = wg_interface
        
        # Check if interface exists and get IP
        result = subprocess.run(
            ['ip', 'addr', 'show', wg_interface], 
            capture_output=True, 
            text=True
        )
        if result.returncode == 0:
            status_info['interface_up'] = True
            # Extract server IP
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', line)
                    if ip_match:
                        status_info['server_ip'] = ip_match.group(1)
        
        # Get active peer connections
        result = subprocess.run(
            ['wg', 'show', wg_interface], 
            capture_output=True, 
            text=True
        )
        if result.returncode == 0:
            current_peer = None
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('peer:'):
                    if current_peer:
                        status_info['active_peers'].append(current_peer)
                    # Extract public key after "peer: "
                    public_key = (
                        line.split('peer: ')[1] 
                        if 'peer: ' in line 
                        else line.split()[1]
                    )
                    current_peer = {
                        'public_key': public_key[:8] + '...', 
                        'full_key': public_key
                    }
                elif current_peer and line.startswith('allowed ips:'):
                    current_peer['allowed_ips'] = line.split('allowed ips: ')[1]
                elif current_peer and line.startswith('endpoint:'):
                    current_peer['endpoint'] = line.split('endpoint: ')[1]
                elif current_peer and line.startswith('latest handshake:'):
                    handshake = line.split('latest handshake: ')[1]
                    current_peer['last_handshake'] = handshake
                    # Consider peer active if handshake is recent (less than 5 min ago)
                    current_peer['is_active'] = (
                        'minute' in handshake or 'second' in handshake
                    )
                elif current_peer and line.startswith('transfer:'):
                    current_peer['transfer'] = line.split('transfer: ')[1]
            
            if current_peer:
                status_info['active_peers'].append(current_peer)
                
    except Exception as e:
        print(f"Error getting WireGuard status: {e}")
        status_info['error'] = str(e)
    
    return status_info

def login_required(f):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == ADMIN_USER and password == ADMIN_PASS:
            session['logged_in'] = True
            flash('Successfully logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout"""
    session.pop('logged_in', None)
    flash('Successfully logged out!', 'success')
    return redirect(url_for('login'))

@app.route('/wireguard')
@login_required
def wireguard():
    return render_template('wireguard.html')

@app.route('/')
@login_required
def dashboard():
    """Dashboard - show all iptables rules (both app-managed and existing)"""
    # Get all current rules from system
    all_rules = sync_rules_with_system()
    rules_stats = get_iptables_statistics()
    wg_status = get_wireguard_status()
    
    # Debug output
    print(f"DEBUG: Found {len(rules_stats)} iptables statistics")
    print(f"DEBUG: Found {len(all_rules)} total rules in system")
    
    enhanced_rules = []
    
    for rule in all_rules:
        # Find matching statistics for this rule
        matching_stats = None
        print(f"DEBUG: Looking for stats for rule: chain={rule.get('chain')}, action={rule.get('action')}, protocol={rule.get('protocol', '')}, source={rule.get('source_ip', '')}")
        
        for stat in rules_stats:
            print(f"DEBUG: Comparing with stat: chain={stat['chain']}, target={stat['target']}, protocol={stat['protocol']}, source={stat['source']}")
            
            # Normalize protocol comparison
            rule_protocol = rule.get('protocol', '') or ''
            stat_protocol = stat['protocol'] if stat['protocol'] != 'all' else ''
            
            # Normalize source IP comparison
            rule_source = rule.get('source_ip', '') or ''
            stat_source = stat['source'] or ''
            
            # More flexible matching - try exact match first, then partial
            chain_match = stat['chain'] == rule.get('chain')
            action_match = stat['target'] == rule.get('action')
            protocol_match = stat_protocol == rule_protocol or (not rule_protocol and not stat_protocol)
            source_match = (not rule_source or stat_source == rule_source or 
                          stat_source == '0.0.0.0/0' or rule_source == '0.0.0.0/0')
            
            print(f"DEBUG: Match results - chain:{chain_match}, action:{action_match}, protocol:{protocol_match}, source:{source_match}")
            
            if chain_match and action_match and protocol_match and source_match:
                matching_stats = stat
                print(f"DEBUG: ✅ MATCHED rule {rule.get('chain')}/{rule.get('action')} with stats: packets={stat['packets']}, bytes={stat['bytes']}")
                break
        
        if not matching_stats:
            print(f"DEBUG: ❌ NO MATCH found for rule {rule.get('chain')}/{rule.get('action')}")
        
        enhanced_rule = rule.copy()
        if matching_stats:
            enhanced_rule.update({
                'packets': matching_stats['packets'],
                'bytes': matching_stats['bytes']
            })
        else:
            enhanced_rule.update({
                'packets': 0,
                'bytes': 0
            })
        
        enhanced_rules.append(enhanced_rule)
    
    # Sort rules by chain and then by line number (iptables order)
    def sort_rule_key(rule):
        # Priority order: INPUT first, then FORWARD, then OUTPUT
        chain_priority = {'INPUT': 1, 'FORWARD': 2, 'OUTPUT': 3}
        
        chain = rule.get('chain', 'ZZZ')  # Unknown chains go to end
        line_number = rule.get('line_number', 999)  # Unknown line numbers go to end
        
        return (
            chain_priority.get(chain, 99),  # Chain priority first
            line_number  # Then by line number (iptables order)
        )
    
    enhanced_rules.sort(key=sort_rule_key)
    
    return render_template('dashboard.html', 
                         rules=get_current_rules(),  # Keep for backward compatibility
                         enhanced_rules=enhanced_rules,
                         rules_stats=rules_stats,
                         wg_status=wg_status)

@app.route('/add-rule', methods=['GET', 'POST'])
@login_required
def add_rule():
    """Add new iptables rule"""
    if request.method == 'POST':
        chain = request.form['chain']
        protocol = request.form['protocol']
        source_ip = request.form.get('source_ip', '')
        dest_ip = request.form.get('dest_ip', '')
        port = request.form.get('port', '')
        action = request.form['action']
        comment = request.form.get('comment', '').strip()
        
        # Create rule with comment and initial packet count
        rule_data = {
            'chain': chain,
            'protocol': protocol,
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'port': port,
            'action': action,
            'comment': comment,
            'created_at': datetime.now().isoformat(),
            'packets': 0,
            'bytes': 0
        }
        
        # Apply rule to iptables
        result = apply_iptables_rule(rule_data)
        if isinstance(result, tuple):
            success, error_msg = result
            if success:
                # Save to JSON
                save_rule_to_json(rule_data)
                flash('Rule added successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash(f'Failed to add rule: {error_msg}', 'error')
        elif result:
            # Backward compatibility - if it returns just boolean True
            save_rule_to_json(rule_data)
            flash('Rule added successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Failed to add rule: Unknown error', 'error')
    
    return render_template('add_rule.html', 
                         wg_status=get_wireguard_status())

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Settings page - manage rules JSON file"""
    if request.method == 'POST':
        if 'export' in request.form:
            # Export rules
            rules = load_rules_from_json()
            return render_template('settings.html', export_data=json.dumps(rules, indent=2))
        elif 'import' in request.form:
            # Import rules
            import_data = request.form['import_data']
            try:
                rules = json.loads(import_data)
                save_rules_to_json(rules)
                # Apply all rules
                apply_all_rules()
                flash('Rules imported and applied successfully!', 'success')
            except json.JSONDecodeError:
                flash('Invalid JSON format!', 'error')
            except Exception as e:
                flash(f'Error importing rules: {str(e)}', 'error')
        elif 'clear' in request.form:
            # Clear all rules
            clear_all_rules()
            flash('All rules cleared!', 'success')
    
    rules_count = len(load_rules_from_json())
    return render_template('settings.html', rules_count=rules_count)

@app.route('/api/iptables/statistics')
@login_required
def api_iptables_statistics():
    """API endpoint to get iptables statistics"""
    stats = get_iptables_statistics()
    return {
        'statistics': stats,
        'success': True
    }

@app.route('/api/rule/delete/<int:rule_index>', methods=['DELETE'])
@login_required
def api_delete_rule(rule_index):
    """API endpoint to delete a rule"""
    try:
        saved_rules = load_rules_from_json()
        
        if rule_index < 0 or rule_index >= len(saved_rules):
            return {'success': False, 'error': 'Rule index out of range'}, 400
        
        rule_to_delete = saved_rules[rule_index]
        
        # Try to remove from iptables (construct delete command)
        delete_success = delete_iptables_rule(rule_to_delete)
        
        if delete_success:
            # Remove from saved rules
            saved_rules.pop(rule_index)
            save_rules_to_json(saved_rules)
            return {'success': True, 'message': 'Rule deleted successfully'}
        else:
            return (
                {'success': False, 'error': 'Failed to delete rule from iptables'}, 
                500
            )
            
    except Exception as e:
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/debug/wireguard')
@login_required
def debug_wireguard():
    """Debug endpoint to see raw WireGuard output"""
    import subprocess
    debug_info = {}


    try:
        # Check interface
        result = subprocess.run(['ip', 'addr', 'show', 'wg0'], 
                              capture_output=True, text=True, timeout=10)
        debug_info['ip_addr_show'] = {
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
    except Exception as e:
        debug_info['ip_addr_show'] = {'error': str(e)}
    
    try:
        # Check wg show
        result = subprocess.run(['wg', 'show', 'wg0'], 
                              capture_output=True, text=True, timeout=10)
        debug_info['wg_show'] = {
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
    except Exception as e:
        debug_info['wg_show'] = {'error': str(e)}
    
    try:
        # Also try wg without interface
        result = subprocess.run(['wg'], 
                              capture_output=True, text=True, timeout=10)
        debug_info['wg_all'] = {
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
    except Exception as e:
        debug_info['wg_all'] = {'error': str(e)}
    
    # Get parsed status
    debug_info['parsed_status'] = get_wireguard_status()
    
    return debug_info

def get_current_rules():
    """Get current iptables rules"""
    try:
        result = subprocess.run(
            ['iptables', '-S'], 
            capture_output=True, 
            text=True, 
            check=True
        )
        rules = []
        for line in result.stdout.strip().split('\n'):
            if line.strip() and not line.startswith('-P'):  # Skip policy lines
                rules.append(line.strip())
        return rules
    except subprocess.CalledProcessError as e:
        print(f"Error getting iptables rules: {e}")
        return []

def parse_iptables_size(size_str):
    """Parse iptables size string (e.g., '1414K', '487K', '123M') to bytes"""
    if not size_str or size_str == '0':
        return 0
    
    # Remove any whitespace
    size_str = size_str.strip()
    
    # If it's just a number, return it
    if size_str.isdigit():
        return int(size_str)
    
    # Parse with suffix
    multipliers = {
        'K': 1024,
        'M': 1024 * 1024,
        'G': 1024 * 1024 * 1024,
        'T': 1024 * 1024 * 1024 * 1024
    }
    
    try:
        if size_str[-1] in multipliers:
            number = float(size_str[:-1])
            return int(number * multipliers[size_str[-1]])
        else:
            return int(float(size_str))
    except (ValueError, IndexError):
        print(f"Warning: Could not parse size '{size_str}', defaulting to 0")
        return 0

def get_iptables_statistics():
    """Get iptables rules with packet and byte counters"""
    try:
        result = subprocess.run(['iptables', '-L', '-n', '-v'], 
                              capture_output=True, text=True, check=True)
        
        print(f"DEBUG: Raw iptables -nvL output:")
        print(result.stdout)
        print("=" * 50)
        
        rules_stats = []
        current_chain = None
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Chain header
            if line.startswith('Chain '):
                current_chain = line.split()[1]
                print(f"DEBUG: Found chain: {current_chain}")
                continue
                
            # Skip column headers
            if line.startswith('pkts') or line.startswith('target'):
                continue
                
            # Parse rule line with stats
            if current_chain and line:
                parts = line.split()
                print(f"DEBUG: Parsing line: {line}")
                print(f"DEBUG: Split parts: {parts}")
                
                if len(parts) >= 6:
                    try:
                        rule_stat = {
                            'chain': current_chain,
                            'packets': parse_iptables_size(parts[0]),
                            'bytes': parse_iptables_size(parts[1]),
                            'target': parts[2] if len(parts) > 2 else '',
                            'prot': parts[3] if len(parts) > 3 else '',  # Keep as 'prot' for compatibility
                            'protocol': parts[3] if len(parts) > 3 else '',  # Also add as 'protocol'
                            'opt': parts[4] if len(parts) > 4 else '',
                            'in': parts[5] if len(parts) > 5 else '',
                            'out': parts[6] if len(parts) > 6 else '',
                            'source': parts[7] if len(parts) > 7 else '',
                            'destination': parts[8] if len(parts) > 8 else '',
                            'comment': extract_comment_from_rule_line(' '.join(parts)) if len(parts) > 8 else ''
                        }
                        print(f"DEBUG: Created rule_stat: {rule_stat}")
                        rules_stats.append(rule_stat)
                    except (ValueError, IndexError) as e:
                        print(f"DEBUG: Error parsing line '{line}': {e}")
                        continue
                        
        print(f"DEBUG: Total parsed rules_stats: {len(rules_stats)}")        
        return rules_stats
    except subprocess.CalledProcessError as e:
        print(f"Error getting iptables statistics: {e}")
        return []

def extract_comment_from_rule_line(rule_line):
    """Extract comment from iptables rule line"""
    if '/* ' in rule_line and ' */' in rule_line:
        start = rule_line.find('/* ') + 3
        end = rule_line.find(' */')
        if start < end:
            return rule_line[start:end]
    return ''

def apply_iptables_rule(rule_data):
    """Apply a single iptables rule"""
    try:
        # Check if iptables is available
        try:
            subprocess.run(
                ['iptables', '--version'], 
                capture_output=True, 
                check=True, 
                timeout=5
            )
        except (
            subprocess.CalledProcessError, 
            FileNotFoundError, 
            subprocess.TimeoutExpired
        ):
            return (
                False, 
                "iptables is not available. Make sure you're running in a "
                "container with NET_ADMIN capability."
            )
        
        cmd = ['iptables', '-A', rule_data['chain']]
        
        if rule_data['protocol']:
            cmd.extend(['-p', rule_data['protocol']])
        
        if rule_data['source_ip']:
            # Validate IP/CIDR format
            source_ip = rule_data['source_ip'].strip()
            if source_ip and not validate_ip_address(source_ip):
                return False, f"Invalid source IP format: {source_ip}"
            cmd.extend(['-s', source_ip])
        
        if rule_data['dest_ip']:
            # Validate IP/CIDR format
            dest_ip = rule_data['dest_ip'].strip()
            if dest_ip and not validate_ip_address(dest_ip):
                return False, f"Invalid destination IP format: {dest_ip}"
            cmd.extend(['-d', dest_ip])
        
        if rule_data['port'] and rule_data['protocol'] in ['tcp', 'udp']:
            port = rule_data['port'].strip()
            if port and not validate_port(port):
                return False, f"Invalid port format: {port}"
            cmd.extend(['--dport', port])
        
        # Add comment if provided (iptables comment module)
        if rule_data.get('comment'):
            comment = rule_data['comment'][:255]  # iptables comment limit
            cmd.extend(['-m', 'comment', '--comment', comment])
        
        cmd.extend(['-j', rule_data['action']])
        
        # Log the command for debugging
        print(f"Executing iptables command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True, 
            timeout=10
        )
        print(f"Applied rule successfully: {' '.join(cmd)}")
        return True, "Rule applied successfully"
        
    except ValueError as e:
        print(f"Validation error: {e}")
        return False, str(e)
    except subprocess.TimeoutExpired:
        error_msg = "iptables command timed out"
        print(f"Error applying rule: {error_msg}")
        return False, error_msg
    except subprocess.CalledProcessError as e:
        error_msg = f"iptables command failed (exit code {e.returncode})"
        if e.stderr:
            error_msg += f": {e.stderr.strip()}"
        else:
            # Common iptables error codes
            if e.returncode == 1:
                error_msg += ": General error or invalid argument"
            elif e.returncode == 2:
                error_msg += ": Invalid command syntax"
            elif e.returncode == 3:
                error_msg += ": Kernel version doesn't support iptables"
            elif e.returncode == 4:
                error_msg += ": Invalid IP address, port, or target specification"
                error_msg += "\nHint: Check if destination IP is a network address (ends with .0) - use CIDR notation like 192.168.160.0/24 instead"
        
        print(f"Error applying rule: {error_msg}")
        print(f"Command that failed: {' '.join(cmd)}")
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(f"Error applying rule: {error_msg}")
        return False, error_msg

def validate_ip_address(ip_str):
    """Validate IP address or CIDR notation"""
    if not ip_str:
        return True
    
    try:
        import ipaddress
        # Try to parse as IP address or network
        if '/' in ip_str:
            ipaddress.ip_network(ip_str, strict=False)
        else:
            ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def validate_port(port_str):
    """Validate port number or range"""
    if not port_str:
        return True
    
    try:
        if ':' in port_str:
            # Port range
            start, end = port_str.split(':')
            start_port = int(start) if start else 1
            end_port = int(end) if end else 65535
            return 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port
        else:
            # Single port
            port = int(port_str)
            return 1 <= port <= 65535
    except (ValueError, AttributeError):
        return False

def delete_iptables_rule(rule_data):
    """Delete a single iptables rule"""
    try:
        # Check if iptables is available
        try:
            subprocess.run(['iptables', '--version'], capture_output=True, check=True, timeout=5)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            print("iptables is not available")
            return False
        
        # Construct delete command (replace -A with -D)
        cmd = ['iptables', '-D', rule_data['chain']]
        
        if rule_data['protocol']:
            cmd.extend(['-p', rule_data['protocol']])
        
        if rule_data['source_ip']:
            source_ip = rule_data['source_ip'].strip()
            if source_ip:
                cmd.extend(['-s', source_ip])
        
        if rule_data['dest_ip']:
            dest_ip = rule_data['dest_ip'].strip()
            if dest_ip:
                cmd.extend(['-d', dest_ip])
        
        if rule_data['port'] and rule_data['protocol'] in ['tcp', 'udp']:
            port = rule_data['port'].strip()
            if port:
                cmd.extend(['--dport', port])
        
        # Add comment if provided
        if rule_data.get('comment'):
            comment = rule_data['comment'][:255]
            cmd.extend(['-m', 'comment', '--comment', comment])
        
        cmd.extend(['-j', rule_data['action']])
        
        # Log the command for debugging
        print(f"Executing iptables delete command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True, 
            timeout=10
        )
        print(f"Deleted rule successfully: {' '.join(cmd)}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"Error deleting rule (may not exist): {e}")
        # Don't fail if rule doesn't exist - it might have been manually deleted
        return True
    except Exception as e:
        print(f"Error deleting rule: {e}")
        return False

def save_rule_to_json(rule_data):
    """Save a single rule to JSON file"""
    rules = load_rules_from_json()
    rules.append(rule_data)
    save_rules_to_json(rules)

def load_rules_from_json():
    """Load rules from JSON file (legacy compatibility function)"""
    try:
        config = load_rules_config()  # Use the new config loader
        if isinstance(config, dict):
            return config.get('rules', [])
        elif isinstance(config, list):
            return config  # Old format compatibility
        else:
            return []
    except Exception as e:
        print(f"Error loading rules from JSON: {e}")
        return []

def save_rules_to_json(rules):
    """Save rules to JSON file (legacy compatibility function)"""
    try:
        # Load current config to preserve other settings
        config = load_rules_config()
        config['rules'] = rules
        save_rules_config(config)
        print(f"Saved {len(rules)} rules to {RULES_FILE}")
    except Exception as e:
        print(f"Error saving rules to JSON: {e}")

def apply_all_rules():
    """Apply all rules from JSON file"""
    rules = load_rules_from_json()
    success_count = 0
    failed_rules = []
    
    for rule in rules:
        result = apply_iptables_rule(rule)
        if isinstance(result, tuple):
            success, error_msg = result
            if success:
                success_count += 1
            else:
                failed_rules.append(f"Rule {rule}: {error_msg}")
        elif result:
            success_count += 1
        else:
            failed_rules.append(f"Rule {rule}: Unknown error")
    
    print(f"Applied {success_count}/{len(rules)} rules from JSON")
    if failed_rules:
        for failed in failed_rules:
            print(f"Failed: {failed}")
    
    return success_count, failed_rules

def clear_all_rules():
    """Clear all iptables rules and JSON file"""
    try:
        # Flush all chains
        subprocess.run(['iptables', '-F'], check=True)
        subprocess.run(['iptables', '-X'], check=True)  # Delete custom chains
        
        # Clear JSON file
        save_rules_to_json([])
        print("Cleared all iptables rules and JSON file")
    except subprocess.CalledProcessError as e:
        print(f"Error clearing rules: {e}")

def initialize_app():
    """Initialize application - load and apply rules on startup"""
    print("Initializing IptablesUI...")
    apply_all_rules()
    print("IptablesUI initialized successfully")

@app.route('/api/debug/raw-iptables')
@login_required
def debug_raw_iptables():
    """Debug endpoint to see raw iptables output"""
    try:
        result = subprocess.run(['iptables', '-L', '-n', '-v'], 
                              capture_output=True, text=True, check=True)
        
        # Also get without verbose for comparison
        result_simple = subprocess.run(['iptables', '-L', '-n', '--line-numbers'], 
                                     capture_output=True, text=True, check=True)
        
        return {
            'iptables_verbose': result.stdout,
            'iptables_simple': result_simple.stdout,
            'parsed_stats': get_iptables_statistics(),
            'all_rules': get_all_iptables_rules(),
            'synced_rules': sync_rules_with_system()
        }
    except Exception as e:
        return {'error': str(e)}

@app.route('/api/debug/stats')
@login_required  
def debug_stats():
    """Debug endpoint to diagnose statistics matching"""
    rules_stats = get_iptables_statistics()
    saved_rules = load_rules_from_json()
    
    debug_info = {
        'rules_stats': rules_stats,
        'saved_rules': saved_rules,
        'matching_attempts': []
    }
    
    # Debug matching logic
    for saved_rule in saved_rules:
        matching_info = {
            'saved_rule': saved_rule,
            'matches': []
        }
        
        for stat in rules_stats:
            match_result = {
                'stat': stat,
                'chain_match': stat['chain'] == saved_rule.get('chain'),
                'target_match': stat['target'] == saved_rule.get('action'),
                'protocol_match': stat['protocol'] == saved_rule.get('protocol', ''),
                'source_match': stat['source'] == saved_rule.get('source_ip', ''),
                'overall_match': (
                    stat['chain'] == saved_rule.get('chain') and
                    stat['target'] == saved_rule.get('action') and
                    stat['protocol'] == saved_rule.get('protocol', '')
                )
            }
            matching_info['matches'].append(match_result)
        
        debug_info['matching_attempts'].append(matching_info)
    
    return debug_info

@app.route('/api/debug/parse-test')
@login_required  
def debug_parse_test():
    """Debug endpoint to test size parsing"""
    test_values = ['1414K', '487K', '660', '0', '1.5M', '2G', '123']
    results = {}
    
    for value in test_values:
        parsed = parse_iptables_size(value)
        results[value] = {
            'parsed': parsed,
            'formatted': format_bytes(parsed)
        }
    
    return {
        'test_results': results,
        'current_iptables_output': get_iptables_statistics()
    }

@app.route('/api/rules/save-all', methods=['POST'])
@login_required
def save_all_rules():
    """Save all current system rules to config file"""
    try:
        # Use sync_rules_with_system to get rules with proper hash generation
        all_rules = sync_rules_with_system()
        config = load_rules_config()
        
        # Convert system rules to our format
        converted_rules = []
        for rule in all_rules:
            # Generate hash if it doesn't exist
            if 'rule_hash' not in rule:
                rule_hash = hash(f"{rule['chain']}-{rule['action']}-{rule.get('protocol', '')}-{rule.get('source_ip', '')}-{rule.get('destination_ip', '')}")
            else:
                rule_hash = rule['rule_hash']
                
            converted_rule = {
                'chain': rule['chain'],
                'action': rule['action'],
                'protocol': rule.get('protocol', ''),
                'source_ip': rule.get('source_ip', ''),
                'destination_ip': rule.get('destination_ip', ''),
                'port': '',  # Extract from options if needed
                'comment': f"System rule (line {rule.get('line_number', 'unknown')})",
                'rule_hash': rule_hash,
                'managed_by_app': rule.get('managed_by_app', False),
                'line_number': rule.get('line_number'),
                'created_at': datetime.now().isoformat()
            }
            converted_rules.append(converted_rule)
        
        config['rules'] = converted_rules
        if save_rules_config(config):
            return jsonify({
                'success': True, 
                'message': f'Saved {len(converted_rules)} rules to configuration',
                'rules_count': len(converted_rules)
            })
        else:
            return jsonify({'success': False, 'message': 'Failed to save configuration'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error saving rules: {str(e)}'})

@app.route('/api/rules/delete/<int:line_number>/<chain>', methods=['POST'])
@login_required
def delete_system_rule(line_number, chain):
    """Delete a specific system rule by line number and chain"""
    try:
        # Delete from iptables
        cmd = ['iptables', '-D', chain, str(line_number)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            # Also remove from saved config if it exists
            config = load_rules_config()
            original_count = len(config.get('rules', []))
            config['rules'] = [r for r in config.get('rules', []) 
                             if not (r.get('chain') == chain and r.get('line_number') == line_number)]
            save_rules_config(config)
            
            return jsonify({
                'success': True, 
                'message': f'Rule deleted from {chain} chain line {line_number}',
                'rules_removed_from_config': original_count - len(config.get('rules', []))
            })
        else:
            return jsonify({
                'success': False, 
                'message': f'Failed to delete rule: {result.stderr}'
            })
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error deleting rule: {str(e)}'})

@app.route('/api/rules/apply-saved', methods=['POST'])
@login_required
def apply_saved_rules_api():
    """Apply all saved rules from configuration"""
    try:
        applied_count, errors = apply_saved_rules()
        
        if errors:
            return jsonify({
                'success': False,
                'message': f'Applied {applied_count} rules with {len(errors)} errors',
                'applied_count': applied_count,
                'errors': errors
            })
        else:
            return jsonify({
                'success': True,
                'message': f'Successfully applied {applied_count} saved rules',
                'applied_count': applied_count
            })
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error applying saved rules: {str(e)}'})

@app.route('/api/rules/move-up/<int:line_number>/<chain>', methods=['POST'])
@login_required
def move_rule_up(line_number, chain):
    """Move a rule up (higher priority) in the iptables chain"""
    if line_number <= 1:
        return jsonify({'success': False, 'message': 'Rule is already at the top'})
    
    try:
        # Get current rules to find the rule to move
        all_rules = get_all_iptables_rules()
        target_rule = None
        
        for rule in all_rules:
            if rule['chain'] == chain and rule['line_number'] == line_number:
                target_rule = rule
                break
        
        if not target_rule:
            return jsonify({'success': False, 'message': 'Rule not found'})
        
        # Delete the rule from its current position
        delete_cmd = ['iptables', '-D', chain, str(line_number)]
        delete_result = subprocess.run(delete_cmd, capture_output=True, text=True, timeout=10)
        
        if delete_result.returncode != 0:
            return jsonify({'success': False, 'message': f'Failed to remove rule: {delete_result.stderr}'})
        
        # Insert the rule at the new position (line_number - 1)
        new_position = line_number - 1
        insert_cmd = ['iptables', '-I', chain, str(new_position)]
        
        # Reconstruct rule parameters
        if target_rule.get('protocol'):
            insert_cmd.extend(['-p', target_rule['protocol']])
        if target_rule.get('source_ip') and target_rule['source_ip'] != '0.0.0.0/0':
            insert_cmd.extend(['-s', target_rule['source_ip']])
        if target_rule.get('destination_ip') and target_rule['destination_ip'] != '0.0.0.0/0':
            insert_cmd.extend(['-d', target_rule['destination_ip']])
        
        # Add additional options from raw rule if available
        if target_rule.get('options'):
            # Parse options carefully - this is simplified
            options = target_rule['options'].split()
            insert_cmd.extend(options)
        
        insert_cmd.extend(['-j', target_rule['action']])
        
        insert_result = subprocess.run(insert_cmd, capture_output=True, text=True, timeout=10)
        
        if insert_result.returncode == 0:
            return jsonify({
                'success': True, 
                'message': f'Rule moved up from line {line_number} to {new_position}',
                'new_position': new_position
            })
        else:
            return jsonify({'success': False, 'message': f'Failed to insert rule: {insert_result.stderr}'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error moving rule up: {str(e)}'})

@app.route('/api/rules/move-down/<int:line_number>/<chain>', methods=['POST'])
@login_required
def move_rule_down(line_number, chain):
    """Move a rule down (lower priority) in the iptables chain"""
    try:
        # Get current rules to check if move is possible
        all_rules = get_all_iptables_rules()
        chain_rules = [r for r in all_rules if r['chain'] == chain]
        max_line = max([r['line_number'] for r in chain_rules]) if chain_rules else 0
        
        if line_number >= max_line:
            return jsonify({'success': False, 'message': 'Rule is already at the bottom'})
        
        target_rule = None
        for rule in all_rules:
            if rule['chain'] == chain and rule['line_number'] == line_number:
                target_rule = rule
                break
        
        if not target_rule:
            return jsonify({'success': False, 'message': 'Rule not found'})
        
        # Delete the rule from its current position
        delete_cmd = ['iptables', '-D', chain, str(line_number)]
        delete_result = subprocess.run(delete_cmd, capture_output=True, text=True, timeout=10)
        
        if delete_result.returncode != 0:
            return jsonify({'success': False, 'message': f'Failed to remove rule: {delete_result.stderr}'})
        
        # Insert the rule at the new position (line_number + 1)
        # Note: After deletion, the line numbers shift, so we insert at line_number + 1
        new_position = line_number + 1
        insert_cmd = ['iptables', '-I', chain, str(new_position)]
        
        # Reconstruct rule parameters
        if target_rule.get('protocol'):
            insert_cmd.extend(['-p', target_rule['protocol']])
        if target_rule.get('source_ip') and target_rule['source_ip'] != '0.0.0.0/0':
            insert_cmd.extend(['-s', target_rule['source_ip']])
        if target_rule.get('destination_ip') and target_rule['destination_ip'] != '0.0.0.0/0':
            insert_cmd.extend(['-d', target_rule['destination_ip']])
        
        # Add additional options from raw rule if available
        if target_rule.get('options'):
            options = target_rule['options'].split()
            insert_cmd.extend(options)
        
        insert_cmd.extend(['-j', target_rule['action']])
        
        insert_result = subprocess.run(insert_cmd, capture_output=True, text=True, timeout=10)
        
        if insert_result.returncode == 0:
            return jsonify({
                'success': True, 
                'message': f'Rule moved down from line {line_number} to {new_position}',
                'new_position': new_position
            })
        else:
            return jsonify({'success': False, 'message': f'Failed to insert rule: {insert_result.stderr}'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error moving rule down: {str(e)}'})

@app.route('/api/wireguard/status')
@login_required
def wg_status():
    """Get WireGuard server status"""
    try:
        # Check if interface is running
        result = subprocess.run(['wg', 'show', WG_INTERFACE], 
                              capture_output=True, text=True)
        
        is_running = result.returncode == 0
        config = get_wg_server_config()
        
        status = {
            'running': is_running,
            'interface': WG_INTERFACE,
            'config_exists': config is not None
        }
        
        if config:
            status['listen_port'] = config.get('listen_port', 51820)
            status['address'] = config.get('address', '')
            status['peer_count'] = len(config.get('peers', []))
        
        if is_running:
            # Get peer connection status
            peers_info = []
            lines = result.stdout.split('\n')
            current_peer = None
            
            for line in lines:
                line = line.strip()
                if line.startswith('peer:'):
                    if current_peer:
                        peers_info.append(current_peer)
                    current_peer = {
                        'public_key': line.split(': ', 1)[1],
                        'endpoint': None,
                        'allowed_ips': None,
                        'latest_handshake': None,
                        'transfer_rx': 0,
                        'transfer_tx': 0
                    }
                elif line.startswith('endpoint:') and current_peer:
                    current_peer['endpoint'] = line.split(': ', 1)[1]
                elif line.startswith('allowed ips:') and current_peer:
                    current_peer['allowed_ips'] = line.split(': ', 1)[1]
                elif line.startswith('latest handshake:') and current_peer:
                    current_peer['latest_handshake'] = line.split(': ', 1)[1]
                elif line.startswith('transfer:') and current_peer:
                    transfer_parts = line.split(': ', 1)[1].split(', ')
                    if len(transfer_parts) >= 2:
                        current_peer['transfer_rx'] = transfer_parts[0]
                        current_peer['transfer_tx'] = transfer_parts[1]
            
            if current_peer:
                peers_info.append(current_peer)
                
            status['active_peers'] = peers_info
        
        return jsonify(status)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/wireguard/config', methods=['GET', 'POST'])
@login_required
def wg_config():
    """Get or update WireGuard server configuration"""
    if request.method == 'GET':
        config = get_wg_server_config()
        if config:
            # Don't send private key to client
            config_safe = config.copy()
            config_safe['private_key'] = '***hidden***'
            return jsonify(config_safe)
        else:
            return jsonify({'error': 'No configuration found'}), 404
    
    elif request.method == 'POST':
        data = request.get_json()
        
        # Validate required fields
        if not data.get('address') or not data.get('listen_port'):
            return jsonify({'error': 'Address and listen port are required'}), 400
        
        # Get existing config or create new
        config = get_wg_server_config() or {
            'interface': WG_INTERFACE,
            'peers': []
        }
        
        # Generate new private key if none exists
        if not config.get('private_key'):
            private_key, _ = generate_wg_keys()
            if not private_key:
                return jsonify({'error': 'Failed to generate keys'}), 500
            config['private_key'] = private_key
        
        # Update configuration
        config['address'] = data['address']
        config['listen_port'] = int(data['listen_port'])
        
        # Save configuration
        if save_wg_server_config(config):
            return jsonify({'message': 'Configuration saved successfully'})
        else:
            return jsonify({'error': 'Failed to save configuration'}), 500

@app.route('/api/wireguard/start', methods=['POST'])
@login_required
def wg_start():
    """Start WireGuard interface"""
    success, message = start_wg_interface()
    if success:
        return jsonify({'message': message})
    else:
        return jsonify({'error': message}), 500

@app.route('/api/wireguard/stop', methods=['POST'])
@login_required
def wg_stop():
    """Stop WireGuard interface"""
    success, message = stop_wg_interface()
    if success:
        return jsonify({'message': message})
    else:
        return jsonify({'error': message}), 500

@app.route('/api/wireguard/restart', methods=['POST'])
@login_required
def wg_restart():
    """Restart WireGuard interface"""
    success, message = restart_wg_interface()
    if success:
        return jsonify({'message': message})
    else:
        return jsonify({'error': message}), 500

@app.route('/api/wireguard/peers', methods=['GET', 'POST'])
@login_required
def wg_peers():
    """Get all peers or add new peer"""
    if request.method == 'GET':
        config = get_wg_server_config()
        if config:
            return jsonify({'peers': config.get('peers', [])})
        else:
            return jsonify({'peers': []})
    
    elif request.method == 'POST':
        data = request.get_json()
        peer_name = data.get('name', '')
        
        if not peer_name:
            return jsonify({'error': 'Peer name is required'}), 400
        
        # Get current server config
        server_config = get_wg_server_config()
        if not server_config:
            return jsonify({'error': 'Server configuration not found'}), 404
        
        # Generate peer configuration
        peer_data, public_key = generate_peer_config(peer_name, server_config)
        if not peer_data:
            return jsonify({'error': 'Failed to generate peer configuration'}), 500
        
        # Add peer to server config
        new_peer = {
            'public_key': public_key,
            'allowed_ips': peer_data['allowed_ips'],
            'endpoint': '',
            'persistent_keepalive': 25
        }
        
        server_config['peers'].append(new_peer)
        
        # Save updated server configuration
        if save_wg_server_config(server_config):
            # Restart interface to apply changes
            restart_wg_interface()
            
            return jsonify({
                'message': 'Peer added successfully',
                'peer': peer_data
            })
        else:
            return jsonify({'error': 'Failed to save server configuration'}), 500

@app.route('/api/wireguard/peers/<public_key>', methods=['DELETE'])
@login_required
def wg_delete_peer(public_key):
    """Delete peer"""
    config = get_wg_server_config()
    if not config:
        return jsonify({'error': 'Server configuration not found'}), 404
    
    # Find and remove peer
    original_count = len(config.get('peers', []))
    config['peers'] = [p for p in config.get('peers', []) if p.get('public_key') != public_key]
    
    if len(config['peers']) == original_count:
        return jsonify({'error': 'Peer not found'}), 404
    
    # Save updated configuration
    if save_wg_server_config(config):
        # Restart interface to apply changes
        restart_wg_interface()
        return jsonify({'message': 'Peer deleted successfully'})
    else:
        return jsonify({'error': 'Failed to save configuration'}), 500

@app.route('/api/wireguard/peers/<public_key>/config')
@login_required
def wg_peer_config(public_key):
    """Get peer configuration file"""
    config = get_wg_server_config()
    if not config:
        return jsonify({'error': 'Server configuration not found'}), 404
    
    # Find peer
    peer = None
    for p in config.get('peers', []):
        if p.get('public_key') == public_key:
            peer = p
            break
    
    if not peer:
        return jsonify({'error': 'Peer not found'}), 404
    
    # Generate client config (this would need the peer's private key, 
    # which we don't store for security reasons)
    # For now, return the peer's server-side config
    return jsonify({
        'public_key': peer['public_key'],
        'allowed_ips': peer['allowed_ips'],
        'note': 'Client configuration requires the peer private key which is not stored on server'
    })

if __name__ == '__main__':
    print("🚀 Initializing IptablesUI with WireGuard Server...")
    initialize_app()
    
    # Apply saved rules if auto_apply is enabled
    config = load_rules_config()
    if config.get('auto_apply', True):
        print("📋 Applying saved iptables rules...")
        applied_count, errors = apply_saved_rules()
        print(f"✅ Applied {applied_count} saved iptables rules")
        if errors:
            print(f"❌ Errors: {errors}")
    
    # Check for existing WireGuard configuration and start if available
    print("🔍 Checking WireGuard configuration...")
    wg_config = get_wg_server_config()
    if wg_config and wg_config.get('address') and wg_config.get('private_key'):
        print(f"📡 Found WireGuard config for {wg_config['address']} on port {wg_config.get('listen_port', 51820)}")
        print(f"👥 Configured peers: {len(wg_config.get('peers', []))}")
        
        # Try to start WireGuard interface (will be handled by entrypoint script)
        try:
            result = subprocess.run(['wg', 'show', WG_INTERFACE], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ WireGuard interface {WG_INTERFACE} is running")
            else:
                print(f"⏸️ WireGuard interface {WG_INTERFACE} not started (will be available via web UI)")
        except Exception as e:
            print(f"⚠️ Could not check WireGuard status: {e}")
    else:
        print("📝 No WireGuard configuration found - configure via web interface")
    
    print("🌐 Starting web server...")
    print("📱 Web Interface will be available at: http://localhost:8080")
    print("🔐 Default credentials: admin / change_me_please")
    print("🔧 Configure WireGuard server in the WireGuard tab")
    
    app.run(host='0.0.0.0', port=8080, debug=False)

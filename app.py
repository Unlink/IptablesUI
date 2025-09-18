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
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Configuration
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('ADMIN_PASS', 'password')
RULES_FILE = 'rules.json'

# WireGuard configuration paths
WG_CONFIG_PATHS = [
    '/config/wg0.conf',  # LinuxServer WireGuard container path
    '/etc/wireguard/wg0.conf',  # Standard WireGuard path
    '/config/wg_confs/wg0.conf',  # Alternative LinuxServer path
]

def get_wireguard_peers():
    """Get WireGuard peer information from config files"""
    peers = []
    
    # Try to find WireGuard config file
    config_file = None
    for path in WG_CONFIG_PATHS:
        if os.path.exists(path):
            config_file = path
            break
    
    if not config_file:
        return peers
    
    try:
        with open(config_file, 'r') as f:
            content = f.read()
        
        # Parse WireGuard config manually (configparser doesn't handle WG format well)
        current_peer = {}
        server_info = {}
        
        for line in content.split('\n'):
            line = line.strip()
            
            if line.startswith('[Interface]'):
                current_section = 'interface'
                continue
            elif line.startswith('[Peer]'):
                if current_peer:  # Save previous peer
                    peers.append(current_peer.copy())
                current_peer = {}
                current_section = 'peer'
                continue
            
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if current_section == 'interface':
                    if key == 'Address':
                        server_info['server_network'] = value
                elif current_section == 'peer':
                    if key == 'PublicKey':
                        current_peer['public_key'] = value[:8] + '...'  # Show only first 8 chars
                    elif key == 'AllowedIPs':
                        current_peer['allowed_ips'] = value
                    elif key == 'Endpoint':
                        current_peer['endpoint'] = value
                    elif key == '#' or key.startswith('#'):
                        # Handle comments as peer names
                        current_peer['name'] = line[1:].strip()
        
        # Add last peer
        if current_peer:
            peers.append(current_peer)
        
        # Add server info to each peer for reference
        for peer in peers:
            peer['server_network'] = server_info.get('server_network', 'Unknown')
            
    except Exception as e:
        print(f"Error reading WireGuard config: {e}")
    
    return peers

def get_wireguard_status():
    """Get WireGuard interface status and active connections"""
    status_info = {
        'interface_up': False,
        'active_peers': [],
        'server_ip': None
    }
    
    try:
        # Check if wg0 interface exists
        result = subprocess.run(['ip', 'addr', 'show', 'wg0'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            status_info['interface_up'] = True
            # Extract server IP
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', line)
                    if ip_match:
                        status_info['server_ip'] = ip_match.group(1)
        
        # Get active peer connections
        result = subprocess.run(['wg', 'show', 'wg0'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            current_peer = None
            for line in result.stdout.split('\n'):
                if line.startswith('peer:'):
                    if current_peer:
                        status_info['active_peers'].append(current_peer)
                    current_peer = {'public_key': line.split(': ')[1][:8] + '...'}
                elif current_peer and 'allowed ips:' in line:
                    current_peer['allowed_ips'] = line.split(': ')[1]
                elif current_peer and 'latest handshake:' in line:
                    current_peer['last_handshake'] = line.split(': ')[1]
                elif current_peer and 'transfer:' in line:
                    current_peer['transfer'] = line.split(': ')[1]
            
            if current_peer:
                status_info['active_peers'].append(current_peer)
                
    except Exception as e:
        print(f"Error getting WireGuard status: {e}")
    
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

@app.route('/')
@login_required
def dashboard():
    """Dashboard - show current iptables rules"""
    rules = get_current_rules()
    wg_peers = get_wireguard_peers()
    wg_status = get_wireguard_status()
    return render_template('dashboard.html', 
                         rules=rules, 
                         wg_peers=wg_peers, 
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
        
        # Create rule
        rule_data = {
            'chain': chain,
            'protocol': protocol,
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'port': port,
            'action': action
        }
        
        # Apply rule to iptables
        if apply_iptables_rule(rule_data):
            # Save to JSON
            save_rule_to_json(rule_data)
            flash('Rule added successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Failed to add rule!', 'error')
    
    return render_template('add_rule.html', 
                         wg_peers=get_wireguard_peers(), 
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

@app.route('/api/wireguard/peers')
@login_required
def api_wireguard_peers():
    """API endpoint to get WireGuard peers information"""
    peers = get_wireguard_peers()
    status = get_wireguard_status()
    return {
        'peers': peers,
        'status': status,
        'success': True
    }

@app.route('/api/wireguard/status')
@login_required
def api_wireguard_status():
    """API endpoint to get WireGuard status"""
    status = get_wireguard_status()
    return {
        'status': status,
        'success': True
    }

def get_current_rules():
    """Get current iptables rules"""
    try:
        result = subprocess.run(['iptables', '-S'], capture_output=True, text=True, check=True)
        rules = []
        for line in result.stdout.strip().split('\n'):
            if line.strip() and not line.startswith('-P'):  # Skip policy lines
                rules.append(line.strip())
        return rules
    except subprocess.CalledProcessError as e:
        print(f"Error getting iptables rules: {e}")
        return []

def apply_iptables_rule(rule_data):
    """Apply a single iptables rule"""
    try:
        cmd = ['iptables', '-A', rule_data['chain']]
        
        if rule_data['protocol']:
            cmd.extend(['-p', rule_data['protocol']])
        
        if rule_data['source_ip']:
            cmd.extend(['-s', rule_data['source_ip']])
        
        if rule_data['dest_ip']:
            cmd.extend(['-d', rule_data['dest_ip']])
        
        if rule_data['port'] and rule_data['protocol'] in ['tcp', 'udp']:
            cmd.extend(['--dport', rule_data['port']])
        
        cmd.extend(['-j', rule_data['action']])
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"Applied rule: {' '.join(cmd)}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error applying rule: {e}")
        return False

def save_rule_to_json(rule_data):
    """Save a single rule to JSON file"""
    rules = load_rules_from_json()
    rules.append(rule_data)
    save_rules_to_json(rules)

def load_rules_from_json():
    """Load rules from JSON file"""
    try:
        if os.path.exists(RULES_FILE):
            with open(RULES_FILE, 'r') as f:
                return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error loading rules from JSON: {e}")
    return []

def save_rules_to_json(rules):
    """Save rules to JSON file"""
    try:
        with open(RULES_FILE, 'w') as f:
            json.dump(rules, f, indent=2)
        print(f"Saved {len(rules)} rules to {RULES_FILE}")
    except IOError as e:
        print(f"Error saving rules to JSON: {e}")

def apply_all_rules():
    """Apply all rules from JSON file"""
    rules = load_rules_from_json()
    success_count = 0
    for rule in rules:
        if apply_iptables_rule(rule):
            success_count += 1
    print(f"Applied {success_count}/{len(rules)} rules from JSON")

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

if __name__ == '__main__':
    initialize_app()
    app.run(host='0.0.0.0', port=8080, debug=False)
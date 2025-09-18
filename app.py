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
from flask import Flask, render_template, request, redirect, url_for, flash, session

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

# Configuration
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('ADMIN_PASS', 'password')
RULES_FILE = 'rules.json'

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

@app.route('/')
@login_required
def dashboard():
    """Dashboard - show current iptables rules"""
    rules = get_current_rules()
    rules_stats = get_iptables_statistics()
    wg_status = get_wireguard_status()
    
    # Merge saved rules with current statistics
    saved_rules = load_rules_from_json()
    enhanced_rules = []
    
    for saved_rule in saved_rules:
        # Find matching statistics for this rule
        matching_stats = None
        for stat in rules_stats:
            if (stat['chain'] == saved_rule.get('chain') and
                stat['target'] == saved_rule.get('action') and
                stat['protocol'] == saved_rule.get('protocol', '')):
                matching_stats = stat
                break
        
        enhanced_rule = saved_rule.copy()
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
    
    return render_template('dashboard.html', 
                         rules=rules,
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

@app.route('/api/wireguard/peers')
@login_required
def api_wireguard_peers():
    """API endpoint to get WireGuard peers information"""
    status = get_wireguard_status()
    return {
        'peers': status.get('active_peers', []),
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

def get_iptables_statistics():
    """Get iptables rules with packet and byte counters"""
    try:
        result = subprocess.run(['iptables', '-L', '-n', '-v'], 
                              capture_output=True, text=True, check=True)
        
        rules_stats = []
        current_chain = None
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Chain header
            if line.startswith('Chain '):
                current_chain = line.split()[1]
                continue
                
            # Skip column headers
            if line.startswith('pkts') or line.startswith('target'):
                continue
                
            # Parse rule line with stats
            if current_chain and line:
                parts = line.split()
                if len(parts) >= 6:
                    try:
                        rule_stat = {
                            'chain': current_chain,
                            'packets': int(parts[0]) if parts[0].isdigit() else 0,
                            'bytes': int(parts[1]) if parts[1].isdigit() else 0,
                            'target': parts[2] if len(parts) > 2 else '',
                            'protocol': parts[3] if len(parts) > 3 else '',
                            'source': parts[7] if len(parts) > 7 else '',
                            'destination': parts[8] if len(parts) > 8 else '',
                            'comment': extract_comment_from_rule_line(' '.join(parts))
                        }
                        rules_stats.append(rule_stat)
                    except (ValueError, IndexError):
                        continue
                        
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

if __name__ == '__main__':
    initialize_app()
    app.run(host='0.0.0.0', port=8080, debug=False)

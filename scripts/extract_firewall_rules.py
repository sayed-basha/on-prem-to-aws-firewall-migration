#!/usr/bin/env python3
import subprocess
import json
import os
import pwd
import re
import ipaddress  # For CIDR normalization

def normalize_cidr(cidr_str):
    """Normalize CIDR to proper network address"""
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
        return str(network)
    except Exception as e:
        print(f"Warning: Could not normalize CIDR '{cidr_str}': {e}")
        return cidr_str  # Return as-is if can't normalize

def parse_rich_rule(rich_rule):
    """Parse firewalld rich rule to extract port, protocol, and source"""
    
    result = {
        'port': None,
        'protocol': None,
        'source': '0.0.0.0/0',
        'action': 'accept'
    }
    
    # Extract source address
    source_match = re.search(r'source address="([^"]+)"', rich_rule)
    if source_match:
        raw_cidr = source_match.group(1)
        result['source'] = normalize_cidr(raw_cidr)  # ← Normalize here
        result['original_source'] = raw_cidr  # Keep original for description
    
    # Extract port
    port_match = re.search(r'port port="(\d+)"', rich_rule)
    if port_match:
        result['port'] = int(port_match.group(1))
    
    # Extract protocol
    protocol_match = re.search(r'protocol="([^"]+)"', rich_rule)
    if protocol_match:
        result['protocol'] = protocol_match.group(1)
    
    # Extract action
    if 'reject' in rich_rule:
        result['action'] = 'reject'
    elif 'drop' in rich_rule:
        result['action'] = 'drop'
    
    return result

def get_firewall_rules():
    """Extract firewall rules from firewalld"""
    
    # Get active zones
    zones = subprocess.check_output(['firewall-cmd', '--get-active-zones']).decode()
    
    # Get rules for default zone
    services = subprocess.check_output(['firewall-cmd', '--list-services']).decode().strip().split()
    ports = subprocess.check_output(['firewall-cmd', '--list-ports']).decode().strip().split()
    
    # Get rich rules
    rich_rules_output = subprocess.check_output(['firewall-cmd', '--list-rich-rules']).decode().strip()
    rich_rules = [rule for rule in rich_rules_output.split('\n') if rule.strip()]
    
    rules = {
        'services': services,
        'ports': ports,
        'rich_rules': rich_rules,
        'security_group_rules': []
    }
    
    # Convert to AWS Security Group format
    service_port_map = {
        'http': {'port': 80, 'protocol': 'tcp'},
        'https': {'port': 443, 'protocol': 'tcp'},
        'ssh': {'port': 22, 'protocol': 'tcp'}
    }
    
    # Track ports handled by rich rules
    rich_rule_ports = set()
    
    # Add rich rules FIRST
    for rich_rule in rich_rules:
        parsed = parse_rich_rule(rich_rule)
        
        if parsed['port'] and parsed['protocol'] and parsed['action'] == 'accept':
            rich_rule_ports.add((parsed['port'], parsed['protocol']))
            
            # Use normalized CIDR for both IP and description
            normalized_cidr = parsed['source']
            
            rules['security_group_rules'].append({
                'IpProtocol': parsed['protocol'],
                'FromPort': parsed['port'],
                'ToPort': parsed['port'],
                'IpRanges': [{
                    'CidrIp': normalized_cidr,  # ← Normalized CIDR
                    'Description': f'Rich rule: {parsed["protocol"]}/{parsed["port"]} from {normalized_cidr}'  # ← Use normalized in description too
                }]
            })
            
            # Show what was normalized if different
            if 'original_source' in parsed and parsed['original_source'] != normalized_cidr:
                print(f"Normalized {parsed['original_source']} → {normalized_cidr}")
    
    # Add service rules (skip if covered by rich rules)
    for service in services:
        if service in service_port_map:
            port = service_port_map[service]['port']
            protocol = service_port_map[service]['protocol']
            
            if (port, protocol) in rich_rule_ports:
                print(f"Skipping service '{service}' - covered by rich rule")
                continue
            
            rules['security_group_rules'].append({
                'IpProtocol': protocol,
                'FromPort': port,
                'ToPort': port,
                'IpRanges': [{
                    'CidrIp': '0.0.0.0/0',
                    'Description': f'Rule for {service}'
                }]
            })
    
    # Handle custom ports
    for port in ports:
        port_num, protocol = port.split('/')
        port_num = int(port_num)
        
        if (port_num, protocol) in rich_rule_ports:
            print(f"Skipping port '{port}' - covered by rich rule")
            continue
        
        rules['security_group_rules'].append({
            'IpProtocol': protocol,
            'FromPort': port_num,
            'ToPort': port_num,
            'IpRanges': [{
                'CidrIp': '0.0.0.0/0',
                'Description': f'Custom port {port}'
            }]
        })
    
    return rules

if __name__ == '__main__':
    rules = get_firewall_rules()
    print(json.dumps(rules, indent=2))
    
    OUTPUT_DIR = '/home/basha/FW-duplicate-learn'
    
    if os.environ.get('SUDO_USER'):
        real_user = os.environ['SUDO_USER']
        user_info = pwd.getpwnam(real_user)
        uid = user_info.pw_uid
        gid = user_info.pw_gid
        output_dir = OUTPUT_DIR.replace('~', user_info.pw_dir)
    else:
        real_user = os.getenv('USER')
        uid = os.getuid()
        gid = os.getgid()
        output_dir = os.path.expanduser(OUTPUT_DIR)
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        if os.environ.get('SUDO_USER'):
            os.chown(output_dir, uid, gid)
        print(f"Created directory: {output_dir}")
    
    output_file = os.path.join(output_dir, 'firewall_rules.json')
    
    with open(output_file, 'w') as f:
        json.dump(rules, f, indent=2)
    
    if os.environ.get('SUDO_USER'):
        os.chown(output_file, uid, gid)
        print(f"File ownership set to: {real_user}")
    
    print(f"\n Rules saved to: {output_file}")
    print(f" Total rules: {len(rules['security_group_rules'])}")
    print(f" File owner: {real_user}")
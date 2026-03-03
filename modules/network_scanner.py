import nmap
import socket
import requests
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
from datetime import datetime
import sqlite3
import csv

class NetworkVulnerabilityScanner:
    def __init__(self, config):
        self.nm = nmap.PortScanner()
        self.config = config
        self.vulnerability_db = self.load_vulnerability_db()
        
    def load_vulnerability_db(self):
        """Load vulnerability database"""
        vuln_db = {
            'ports': {
                21: ['FTP', 'Weak credentials, anonymous login'],
                22: ['SSH', 'Weak passwords, outdated versions'],
                23: ['Telnet', 'Unencrypted communication'],
                25: ['SMTP', 'Open relay, spam'],
                53: ['DNS', 'DNS poisoning, amplification attacks'],
                80: ['HTTP', 'Web vulnerabilities, XSS, SQLi'],
                110: ['POP3', 'Unencrypted credentials'],
                139: ['NetBIOS', 'SMB exploits'],
                143: ['IMAP', 'Unencrypted credentials'],
                443: ['HTTPS', 'SSL/TLS vulnerabilities'],
                445: ['SMB', 'EternalBlue, ransomware'],
                3306: ['MySQL', 'Default credentials, SQL injection'],
                3389: ['RDP', 'BlueKeep, brute force attacks'],
                5900: ['VNC', 'Weak authentication'],
                8080: ['HTTP-Proxy', 'Web vulnerabilities']
            },
            'services': {
                'Apache': ['CVE-2021-41773', 'CVE-2021-42013'],
                'Nginx': ['CVE-2021-23017'],
                'OpenSSH': ['CVE-2020-15778'],
                'SMB': ['CVE-2017-0144', 'CVE-2017-0145'],
                'MySQL': ['CVE-2012-2122']
            }
        }
        return vuln_db
    
    def scan_single_host(self, target, ports=None):
        """Scan a single host for open ports and services"""
        if ports is None:
            ports = self.config.ALLOWED_SCAN_PORTS
        
        print(f"Scanning {target} on ports {ports}...")
        
        try:
            # Nmap scan
            scan_result = self.nm.scan(target, ports, arguments=f'-sV -T4 --max-retries 2')
            
            if target not in scan_result['scan']:
                return {'error': 'Host not found or not responding'}
            
            host_info = scan_result['scan'][target]
            results = {
                'target': target,
                'hostname': host_info.get('hostnames', [{}])[0].get('name', ''),
                'status': host_info['status']['state'],
                'protocols': {}
            }
            
            # Process open ports
            for proto in host_info.get('tcp', {}):
                port_info = host_info['tcp'][proto]
                
                if port_info['state'] == 'open':
                    service = port_info.get('name', 'unknown')
                    version = port_info.get('version', '')
                    product = port_info.get('product', '')
                    
                    # Check for known vulnerabilities
                    vulnerabilities = self.check_vulnerabilities(proto, service, product, version)
                    
                    results['protocols'][proto] = {
                        'service': service,
                        'product': product,
                        'version': version,
                        'state': port_info['state'],
                        'vulnerabilities': vulnerabilities,
                        'risk_level': self.assess_risk(proto, service, vulnerabilities)
                    }
            
            # OS detection
            if 'osmatch' in host_info:
                results['os_guess'] = host_info['osmatch'][0]['name'] if host_info['osmatch'] else 'Unknown'
            
            return results
            
        except Exception as e:
            return {'error': str(e), 'target': target}
    
    def check_vulnerabilities(self, port, service, product, version):
        """Check for known vulnerabilities"""
        vulnerabilities = []
        
        # Check port-based vulnerabilities
        if port in self.vulnerability_db['ports']:
            vuln_info = self.vulnerability_db['ports'][port]
            vulnerabilities.append({
                'type': 'Port-based',
                'port': port,
                'service': vuln_info[0],
                'description': vuln_info[1]
            })
        
        # Check service-based vulnerabilities
        for svc_name, cves in self.vulnerability_db['services'].items():
            if svc_name.lower() in product.lower() or svc_name.lower() in service.lower():
                for cve in cves:
                    vulnerabilities.append({
                        'type': 'Service-based',
                        'cve': cve,
                        'service': svc_name
                    })
        
        # Check for default/weak credentials
        weak_auth_services = ['ftp', 'telnet', 'ssh', 'vnc', 'rdp', 'mysql']
        if any(svc in service.lower() for svc in weak_auth_services):
            vulnerabilities.append({
                'type': 'Authentication',
                'risk': 'Weak/default credentials possible'
            })
        
        return vulnerabilities
    
    def assess_risk(self, port, service, vulnerabilities):
        """Assess risk level based on port and vulnerabilities"""
        risk_score = 0
        
        # High-risk ports
        high_risk_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 445, 3389, 5900]
        if port in high_risk_ports:
            risk_score += 30
        
        # Vulnerability count
        risk_score += len(vulnerabilities) * 15
        
        # Specific high-risk services
        high_risk_services = ['ftp', 'telnet', 'vnc', 'rdp', 'smb']
        if any(hrs in service.lower() for hrs in high_risk_services):
            risk_score += 25
        
        # Determine risk level
        if risk_score >= 60:
            return 'Critical'
        elif risk_score >= 40:
            return 'High'
        elif risk_score >= 20:
            return 'Medium'
        else:
            return 'Low'
    
    def scan_network_range(self, network_range):
        """Scan an entire network range"""
        results = []
        
        try:
            # Generate IP list from CIDR
            network = ipaddress.ip_network(network_range, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
            
            print(f"Scanning {len(ip_list)} hosts in {network_range}...")
            
            # Use ThreadPoolExecutor for parallel scanning
            with ThreadPoolExecutor(max_workers=self.config.MAX_THREADS) as executor:
                future_to_ip = {executor.submit(self.scan_single_host, ip): ip for ip in ip_list}
                
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        results.append({'target': ip, 'error': str(e)})
            
            return results
            
        except Exception as e:
            return [{'error': f'Network scan failed: {str(e)}'}]
    
    def generate_report(self, scan_results, output_format='json'):
        """Generate scan report in various formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if output_format == 'json':
            filename = f'scan_report_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(scan_results, f, indent=2)
        
        elif output_format == 'csv':
            filename = f'scan_report_{timestamp}.csv'
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Target', 'Status', 'Open Ports', 'Risk Level'])
                
                for result in scan_results:
                    if 'error' not in result:
                        open_ports = ', '.join([str(p) for p in result['protocols'].keys()])
                        risk_levels = [v['risk_level'] for v in result['protocols'].values()]
                        max_risk = max(risk_levels, key=lambda x: ['Low', 'Medium', 'High', 'Critical'].index(x)) if risk_levels else 'Low'
                        
                        writer.writerow([
                            result['target'],
                            result['status'],
                            open_ports,
                            max_risk
                        ])
        
        return filename
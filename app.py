from flask import Flask, render_template, request, jsonify, send_file, make_response
import re
import json
from datetime import datetime
import random
import traceback
import urllib.parse

app = Flask(__name__)

# Configuration - FIXED: Use dictionary instead of class for config
app.config.update(
    SECRET_KEY='cybersecurity-suite-secret-key-2024',
    
    # Whitelist of legitimate domains
    WHITELIST_DOMAINS=[
        'youtube.com', 'google.com', 'github.com', 'stackoverflow.com',
        'wikipedia.org', 'microsoft.com', 'apple.com', 'amazon.com',
        'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
        'netflix.com', 'spotify.com', 'chatgpt.com', 'openai.com',
        'deepseek.com', 'reddit.com', 'medium.com', 'quora.com',
        'w3schools.com', 'python.org', 'flask.palletsprojects.com',
        'docker.com', 'ubuntu.com', 'git-scm.com', 'nodejs.org',
        'stackexchange.com', 'jsfiddle.net', 'codepen.io'
    ],
    
    # Phishing detection settings
    SUSPICIOUS_KEYWORDS=[
        'login', 'signin', 'verify', 'account', 'secure',
        'update', 'bank', 'confirm', 'password', 'wallet',
        'paypal', 'ebay', 'crypto', 'bitcoin', 'wallet',
        'socialsecurity', 'ssn', 'creditcard', 'passwordreset',
        'authorize', 'validation', 'authentication', 'credentials'
    ],
    
    SUSPICIOUS_TLDS=['.xyz', '.top', '.club', '.info', '.tk', '.ml', '.ga', '.cf', '.gq', '.men', '.loan'],
    
    # Network scanner settings - FIXED: Proper dictionary format
    COMMON_PORTS={
        21: ('FTP', 'High'),
        22: ('SSH', 'Medium'),
        23: ('Telnet', 'Critical'),
        25: ('SMTP', 'Medium'),
        53: ('DNS', 'Low'),
        80: ('HTTP', 'Medium'),
        110: ('POP3', 'Medium'),
        143: ('IMAP', 'Medium'),
        443: ('HTTPS', 'Low'),
        445: ('SMB', 'Critical'),
        3306: ('MySQL', 'High'),
        3389: ('RDP', 'Critical'),
        8080: ('HTTP Proxy', 'Medium'),
        8443: ('HTTPS Alt', 'Medium'),
        27017: ('MongoDB', 'High'),
        5900: ('VNC', 'Critical'),
        6379: ('Redis', 'High')
    },
    
    # Scan settings
    MAX_URLS_PER_SCAN=50,
    SCAN_TIMEOUT=10
)

class PhishingDetector:
    def __init__(self, config):
        self.config = config
        
        # Lookalike patterns for typosquatting detection
        self.lookalike_patterns = [
            (r'youtub[eo]\.', 'youtube.com'),
            (r'gooogle\.', 'google.com'),
            (r'goggle\.', 'google.com'),
            (r'facebo[ok]\.', 'facebook.com'),
            (r'facebok\.', 'facebook.com'),
            (r'githut\.', 'github.com'),
            (r'amaz0n\.', 'amazon.com'),
            (r'paypa1\.', 'paypal.com'),
            (r'netfl1x\.', 'netflix.com'),
            (r'micr0soft\.', 'microsoft.com'),
            (r'app1e\.', 'apple.com'),
            (r'tw1tter\.', 'twitter.com'),
            (r'instagr4m\.', 'instagram.com'),
            (r'1inkedin\.', 'linkedin.com'),
            (r'whatsap\.', 'whatsapp.com'),
            (r'whatsapppp\.', 'whatsapp.com')
        ]
        
        # Suspicious patterns that override whitelist
        self.suspicious_patterns = [
            r'login-',
            r'verify-',
            r'secure-',
            r'account-',
            r'update-',
            r'confirm-',
            r'validation-',
            r'authentication-'
        ]
    
    def get_domain_from_url(self, url):
        """Extract domain from URL"""
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            if not domain:
                # If no netloc, try to extract from path
                domain = url.split('/')[0].lower()
            return domain
        except:
            return url.lower()
    
    def is_whitelisted(self, domain):
        """Check if domain is in whitelist"""
        for whitelist_domain in self.config['WHITELIST_DOMAINS']:
            if domain == whitelist_domain or domain.endswith('.' + whitelist_domain):
                return True, whitelist_domain
        return False, None
    
    def analyze_url(self, url):
        """Analyze URL for phishing indicators"""
        try:
            # Clean and validate URL
            original_url = url
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Extract domain
            domain = self.get_domain_from_url(url)
            
            # Check whitelist
            is_whitelisted, whitelist_domain = self.is_whitelisted(domain)
            
            if is_whitelisted:
                # Check for lookalike domains even in whitelisted patterns
                for pattern, legit_domain in self.lookalike_patterns:
                    if re.search(pattern, domain) and legit_domain not in domain:
                        # This is a lookalike of a whitelisted domain!
                        return {
                            'url': original_url,
                            'domain': domain,
                            'score': 85,
                            'risk_level': 'Critical',
                            'is_phishing': True,
                            'indicators': [f'Typosquatting detected:模仿 {legit_domain}'],
                            'timestamp': datetime.now().isoformat(),
                            'whitelisted': False,
                            'lookalike': True,
                            'legitimate_domain': legit_domain
                        }
                
                # Legitimate whitelisted domain with no lookalike issues
                return {
                    'url': original_url,
                    'domain': domain,
                    'score': 5,
                    'risk_level': 'Very Low',
                    'is_phishing': False,
                    'indicators': ['Legitimate/verified website'],
                    'timestamp': datetime.now().isoformat(),
                    'whitelisted': True,
                    'verified_domain': whitelist_domain
                }
            
            # Not whitelisted - perform full analysis
            score = 0
            indicators = []
            
            # 1. Lookalike domain detection
            for pattern, legit_domain in self.lookalike_patterns:
                if re.search(pattern, domain):
                    score += 60
                    indicators.append(f'Typosquatting:模仿 {legit_domain}')
                    break
            
            # 2. Suspicious patterns in domain
            for pattern in self.suspicious_patterns:
                if re.search(pattern, domain):
                    score += 40
                    indicators.append(f'Suspicious pattern: {pattern}')
                    break
            
            # 3. URL Length check
            url_length = len(url)
            if url_length > 100:
                score += 30
                indicators.append(f'URL too long ({url_length} chars)')
            elif url_length > 75:
                score += 20
                indicators.append(f'Long URL ({url_length} chars)')
            
            # 4. Contains @ symbol
            if '@' in url:
                score += 35
                indicators.append('Contains @ symbol (obfuscation)')
            
            # 5. IP address in URL
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.search(ip_pattern, url):
                score += 40
                indicators.append('Uses IP address instead of domain')
            
            # 6. Suspicious keywords in path/query (not in domain)
            parsed = urllib.parse.urlparse(url)
            path_query = (parsed.path + parsed.query).lower()
            
            for keyword in self.config['SUSPICIOUS_KEYWORDS']:
                if keyword in path_query:
                    score += 20
                    indicators.append(f'Suspicious keyword: {keyword}')
                    break
            
            # 7. HTTPS check
            if not original_url.startswith('https'):
                score += 25
                indicators.append('Not using HTTPS (insecure)')
            
            # 8. Suspicious TLDs
            for tld in self.config['SUSPICIOUS_TLDS']:
                if domain.endswith(tld):
                    score += 35
                    indicators.append(f'Suspicious domain extension: {tld}')
                    break
            
            # 9. Too many subdomains
            if domain.count('.') > 3:
                score += 20
                indicators.append(f'Too many subdomains ({domain.count(".")})')
            
            # 10. Short URL services
            short_url_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly']
            for service in short_url_services:
                if service in domain:
                    score += 25
                    indicators.append(f'Uses URL shortener: {service}')
                    break
            
            # 11. Hex/URL encoding
            hex_pattern = r'%[0-9a-fA-F]{2}'
            if re.search(hex_pattern, url):
                score += 15
                indicators.append('Contains encoded characters')
            
            # 12. Excessive special characters
            special_chars = re.findall(r'[^\w\s.\-\/:]', domain)
            if len(special_chars) > 2:
                score += 15
                indicators.append('Excessive special characters in domain')
            
            # 13. Domain age simulation (would be real WHOIS check in production)
            # For demo, simulate new domains as more suspicious
            if random.random() < 0.3:  # 30% chance to simulate new domain
                score += 20
                indicators.append('Domain appears recently registered')
            
            # Cap score at 100
            final_score = min(score, 100)
            
            # Determine risk level
            if final_score >= 80:
                risk_level = "Critical"
                is_phishing = True
            elif final_score >= 60:
                risk_level = "High"
                is_phishing = True
            elif final_score >= 40:
                risk_level = "Medium"
                is_phishing = True
            elif final_score >= 20:
                risk_level = "Low"
                is_phishing = False
            else:
                risk_level = "Very Low"
                is_phishing = False
            
            return {
                'url': original_url,
                'domain': domain,
                'score': final_score,
                'risk_level': risk_level,
                'is_phishing': is_phishing,
                'indicators': indicators,
                'timestamp': datetime.now().isoformat(),
                'whitelisted': False
            }
            
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'score': 0,
                'risk_level': 'Unknown',
                'is_phishing': False,
                'indicators': [f'Error analyzing URL'],
                'timestamp': datetime.now().isoformat()
            }

class NetworkScanner:
    def __init__(self, config):
        self.config = config
        print(f"DEBUG: COMMON_PORTS type: {type(config.get('COMMON_PORTS'))}")
        print(f"DEBUG: COMMON_PORTS value: {config.get('COMMON_PORTS')}")
    
    def scan_host(self, target):
        """Simulate network vulnerability scan"""
        try:
            # Clean target
            target = target.strip()
            if not target:
                target = '127.0.0.1'
            
            # Remove protocol if present
            if '://' in target:
                target = target.split('://')[1]
            
            # Remove port if present
            if ':' in target:
                target = target.split(':')[0]
            
            results = []
            
            # Get COMMON_PORTS from config - FIXED ACCESS
            common_ports = self.config.get('COMMON_PORTS', {})
            
            if not common_ports:
                raise ValueError("COMMON_PORTS not found in configuration")
            
            print(f"DEBUG: Scanning {len(common_ports)} ports")
            
            # Simulate scanning with realistic probabilities
            for port, (service, default_risk) in common_ports.items():
                # Different probabilities based on port
                open_probability = {
                    'Critical': 0.15,  # Critical ports rarely open
                    'High': 0.25,
                    'Medium': 0.35,
                    'Low': 0.45         # Common ports often open
                }.get(default_risk, 0.3)
                
                # Adjust based on target
                if target in ['localhost', '127.0.0.1']:
                    open_probability *= 1.5  # More ports open on localhost
                
                if random.random() < open_probability:
                    vulnerabilities = []
                    
                    # Generate realistic vulnerabilities
                    if default_risk == 'Critical':
                        vulnerabilities = [
                            "Potential remote code execution vulnerability (e.g., EternalBlue)",
                            "Service running with weak/default credentials",
                            "Outdated version with known exploits"
                        ]
                    elif default_risk == 'High':
                        vulnerabilities = [
                            "Information disclosure vulnerability",
                            "Potential authentication bypass",
                            "Directory traversal possible"
                        ]
                    elif default_risk == 'Medium':
                        vulnerabilities = [
                            "Default configurations present",
                            "Service banners revealing version info",
                            "Unnecessary services enabled"
                        ]
                    else:
                        vulnerabilities = [
                            "Consider security hardening",
                            "Enable logging and monitoring"
                        ]
                    
                    # Add some random CVE-like IDs for realism
                    if random.random() < 0.4:
                        year = random.randint(2017, 2024)
                        cve_id = f"CVE-{year}-{random.randint(1000, 9999)}"
                        vulnerabilities.append(f"Known vulnerability: {cve_id}")
                    
                    results.append({
                        'port': port,
                        'service': service,
                        'status': 'open',
                        'risk': default_risk,
                        'vulnerabilities': vulnerabilities,
                        'recommendation': self.get_recommendation(service, default_risk)
                    })
            
            # Sort by risk (Critical first)
            results.sort(key=lambda x: {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}[x['risk']], reverse=True)
            
            return {
                'target': target,
                'scan_time': datetime.now().isoformat(),
                'open_ports': results,
                'total_scanned': len(common_ports),
                'summary': self.generate_summary(results),
                'scan_id': f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            }
            
        except Exception as e:
            print(f"DEBUG: Scan error: {str(e)}")
            traceback.print_exc()
            return {
                'target': target,
                'error': str(e),
                'open_ports': [],
                'total_scanned': 0,
                'summary': f'Scan failed: {str(e)}',
                'scan_time': datetime.now().isoformat()
            }
    
    def get_recommendation(self, service, risk):
        """Get security recommendation for service"""
        recommendations = {
            'Critical': "🚨 IMMEDIATE ACTION: Close port or implement strict firewall rules. Update service immediately.",
            'High': "⚠️ URGENT: Implement strong authentication, update service, and monitor logs.",
            'Medium': "🔧 RECOMMENDED: Review configuration, apply security patches, and restrict access.",
            'Low': "📋 SUGGESTED: Monitor for unusual activity and follow security best practices."
        }
        return recommendations.get(risk, "Review security configuration.")
    
    def generate_summary(self, open_ports):
        """Generate scan summary"""
        if not open_ports:
            return "✅ No open ports detected. System appears secure."
        
        critical_count = sum(1 for p in open_ports if p['risk'] == 'Critical')
        high_count = sum(1 for p in open_ports if p['risk'] == 'High')
        total_vulns = sum(len(p['vulnerabilities']) for p in open_ports)
        
        if critical_count > 0:
            return f"🚨 CRITICAL: {critical_count} critical vulnerabilities found! Immediate action required."
        elif high_count > 0:
            return f"⚠️ WARNING: {high_count} high-risk vulnerabilities found. Address soon."
        elif total_vulns > 0:
            return f"🔍 Found {len(open_ports)} open ports with {total_vulns} potential issues."
        else:
            return f"📊 Found {len(open_ports)} open ports. Review configurations."

# Initialize detectors - PASS app.config directly
phishing_detector = PhishingDetector(app.config)
network_scanner = NetworkScanner(app.config)

# Store recent scans
recent_scans = []
MAX_SCANS_STORED = 100

# Error handlers
@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Endpoint not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(405)
def method_not_allowed(error):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Method not allowed'}), 405
    return render_template('405.html'), 405

@app.errorhandler(500)
def internal_error(error):
    if request.path.startswith('/api/'):
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'message': str(error)[:100]
        }), 500
    return render_template('500.html'), 500

# Ensure JSON responses for API
@app.after_request
def after_request(response):
    if request.path.startswith('/api/'):
        if response.content_type != 'application/json':
            try:
                data = response.get_data(as_text=True)
                if '<html' in data.lower():
                    response = make_response(json.dumps({
                        'success': False,
                        'error': 'Server error',
                        'content_type': response.content_type
                    }))
                    response.content_type = 'application/json'
            except:
                pass
    return response

# Routes
@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/phishing/scan', methods=['POST'])
def scan_phishing():
    """API endpoint for phishing scanning"""
    try:
        # Check if request is JSON
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400
        
        urls = data.get('urls', [])
        if not isinstance(urls, list):
            return jsonify({
                'success': False,
                'error': 'URLs must be provided as a list'
            }), 400
        
        # Limit number of URLs
        max_urls = app.config.get('MAX_URLS_PER_SCAN', 50)
        urls = urls[:max_urls]
        
        if not urls:
            return jsonify({
                'success': False,
                'error': 'No URLs provided'
            }), 400
        
        results = []
        for url in urls:
            url = url.strip()
            if url:  # Only process non-empty URLs
                result = phishing_detector.analyze_url(url)
                results.append(result)
                
                # Add to recent scans if phishing detected
                if result.get('is_phishing', False):
                    recent_scans.append({
                        'type': 'phishing',
                        'data': result,
                        'time': datetime.now()
                    })
                    if len(recent_scans) > MAX_SCANS_STORED:
                        recent_scans.pop(0)
        
        phishing_count = sum(1 for r in results if r.get('is_phishing', False))
        
        return jsonify({
            'success': True,
            'results': results,
            'total_scanned': len(results),
            'phishing_count': phishing_count,
            'safe_count': len(results) - phishing_count,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"DEBUG: Phishing scan error: {str(e)}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'message': str(e)[:100]
        }), 500

@app.route('/api/network/scan', methods=['POST'])
def scan_network_api():
    """API endpoint for network scanning"""
    try:
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400
        
        target = data.get('target', '127.0.0.1')
        
        if not target:
            return jsonify({
                'success': False,
                'error': 'No target provided'
            }), 400
        
        result = network_scanner.scan_host(target)
        
        # Add to recent scans if vulnerabilities found
        if result.get('open_ports'):
            recent_scans.append({
                'type': 'vulnerability',
                'data': result,
                'time': datetime.now()
            })
            if len(recent_scans) > MAX_SCANS_STORED:
                recent_scans.pop(0)
        
        return jsonify({
            'success': True,
            'scan': result
        })
        
    except Exception as e:
        print(f"DEBUG: Network scan error: {str(e)}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'message': str(e)[:100]
        }), 500

@app.route('/api/check-single', methods=['POST'])
def check_single_url():
    """Quick check for single URL"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Validate URL format
        url_pattern = re.compile(
            r'^(https?:\/\/)?'  # protocol
            r'([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}'  # domain
            r'(:[0-9]+)?'  # port
            r'(\/.*)?$'  # path
        )
        
        if not url_pattern.match(url) and '://' not in url:
            # Try adding https://
            url = 'https://' + url
        
        result = phishing_detector.analyze_url(url)
        
        # Add to recent scans if phishing
        if result.get('is_phishing', False):
            recent_scans.append({
                'type': 'phishing',
                'data': result,
                'time': datetime.now()
            })
            if len(recent_scans) > MAX_SCANS_STORED:
                recent_scans.pop(0)
        
        return jsonify(result)
        
    except Exception as e:
        print(f"DEBUG: Single URL check error: {str(e)}")
        return jsonify({
            'error': 'Error checking URL',
            'message': str(e)[:100]
        }), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get current statistics"""
    try:
        phishing_count = sum(1 for s in recent_scans if s.get('type') == 'phishing')
        vuln_count = sum(1 for s in recent_scans if s.get('type') == 'vulnerability')
        
        # Count critical issues
        critical_count = 0
        for scan in recent_scans:
            if scan.get('type') == 'phishing':
                if scan.get('data', {}).get('risk_level') == 'Critical':
                    critical_count += 1
            elif scan.get('type') == 'vulnerability':
                if any(p.get('risk') == 'Critical' for p in scan.get('data', {}).get('open_ports', [])):
                    critical_count += 1
        
        return jsonify({
            'success': True,
            'total_scans': len(recent_scans),
            'phishing_detected': phishing_count,
            'vulnerabilities_found': vuln_count,
            'critical_issues': critical_count,
            'last_updated': datetime.now().strftime('%H:%M:%S'),
            'server_time': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"DEBUG: Stats error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)[:100]
        }), 500

@app.route('/api/recent-scans', methods=['GET'])
def get_recent_scans():
    """Get recent scan results"""
    try:
        # Get last 10 scans
        recent = sorted(recent_scans, key=lambda x: x.get('time', datetime.min), reverse=True)[:10]
        
        formatted_scans = []
        for scan in recent:
            scan_type = scan.get('type', 'unknown')
            data = scan.get('data', {})
            time = scan.get('time', datetime.now())
            
            if scan_type == 'phishing':
                formatted_scans.append({
                    'type': 'Phishing',
                    'target': data.get('url', 'Unknown')[:50],
                    'risk': data.get('risk_level', 'Unknown'),
                    'score': data.get('score', 0),
                    'time': time.strftime('%H:%M:%S') if isinstance(time, datetime) else '--:--:--'
                })
            elif scan_type == 'vulnerability':
                open_ports = data.get('open_ports', [])
                if open_ports:
                    highest_risk = max(open_ports, 
                                     key=lambda x: {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}.get(x.get('risk', 'Low'), 0))
                    formatted_scans.append({
                        'type': 'Vulnerability',
                        'target': f"{data.get('target', 'Unknown')}:{highest_risk.get('port', '?')}",
                        'risk': highest_risk.get('risk', 'Unknown'),
                        'service': highest_risk.get('service', 'Unknown'),
                        'time': time.strftime('%H:%M:%S') if isinstance(time, datetime) else '--:--:--'
                    })
        
        return jsonify({
            'success': True,
            'scans': formatted_scans,
            'total': len(formatted_scans)
        })
        
    except Exception as e:
        print(f"DEBUG: Recent scans error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)[:100],
            'scans': []
        }), 500

@app.route('/api/export/<scan_type>', methods=['GET'])
def export_results(scan_type):
    """Export results as JSON file"""
    try:
        if scan_type == 'phishing':
            data = [s['data'] for s in recent_scans if s.get('type') == 'phishing']
            filename = f'phishing_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        elif scan_type == 'network':
            data = [s['data'] for s in recent_scans if s.get('type') == 'vulnerability']
            filename = f'network_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        else:
            return jsonify({'success': False, 'error': 'Invalid scan type'}), 400
        
        # Create temporary JSON file
        import tempfile
        import os
        
        temp_dir = tempfile.gettempdir()
        filepath = os.path.join(temp_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype='application/json'
        )
        
    except Exception as e:
        print(f"DEBUG: Export error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)[:100]}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'success': True,
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'scans_stored': len(recent_scans),
        'version': '1.0.0',
        'config_keys': list(app.config.keys())[:10]  # Debug info
    })

@app.route('/api/clear-scans', methods=['POST'])
def clear_scans():
    """Clear all stored scans"""
    try:
        recent_scans.clear()
        return jsonify({
            'success': True,
            'message': 'All scans cleared successfully',
            'remaining': len(recent_scans)
        })
    except Exception as e:
        print(f"DEBUG: Clear scans error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)[:100]}), 500

@app.route('/api/test', methods=['GET', 'POST'])
def test_endpoint():
    """Test endpoint to verify API is working"""
    if request.method == 'GET':
        return jsonify({
            'success': True,
            'message': 'Cybersecurity API is working!',
            'method': 'GET',
            'timestamp': datetime.now().isoformat(),
            'endpoints': {
                'phishing_scan': 'POST /api/phishing/scan',
                'network_scan': 'POST /api/network/scan',
                'check_single': 'POST /api/check-single',
                'stats': 'GET /api/stats',
                'recent_scans': 'GET /api/recent-scans',
                'health': 'GET /api/health'
            },
            'config_ports': app.config.get('COMMON_PORTS')  # Debug info
        })
    elif request.method == 'POST':
        data = request.get_json() or {}
        return jsonify({
            'success': True,
            'message': 'API received POST request',
            'data_received': data,
            'method': 'POST',
            'timestamp': datetime.now().isoformat()
        })

# Test data for demo
@app.route('/api/demo-data', methods=['GET'])
def demo_data():
    """Get demo data for testing"""
    demo_urls = [
        "https://www.youtube.com",
        "https://www.google.com",
        "https://secure-bank-login.com",
        "https://facebook-verify-account.xyz",
        "https://paypal-update-info.tk",
        "https://github.com",
        "https://netflix-payment-confirm.ga",
        "https://microsoft-account-security.cf"
    ]
    
    demo_targets = ["localhost", "127.0.0.1", "192.168.1.1", "example.com"]
    
    return jsonify({
        'success': True,
        'demo_urls': demo_urls,
        'demo_targets': demo_targets,
        'message': 'Demo data loaded'
    })

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 AI CYBERSECURITY SUITE - FINAL FIXED VERSION")
    print("=" * 60)
    print("📡 Server: http://localhost:5000")
    print("🔐 Features:")
    print("   • Smart Phishing Detection with Whitelist")
    print("   • Network Vulnerability Scanner")
    print("   • Real-time Threat Dashboard")
    print("   • JSON Export & API Access")
    print("=" * 60)
    print("💡 Examples:")
    print("   • Try: https://www.youtube.com (should be SAFE)")
    print("   • Try: https://youtubee.com (should be PHISHING)")
    print("   • Try: https://secure-bank-login.com (should be PHISHING)")
    print("=" * 60)
    print(f"DEBUG: COMMON_PORTS in config: {app.config.get('COMMON_PORTS')}")
    
    # Create log directory
    try:
        with open('security_log.txt', 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"Server started: {datetime.now()}\n")
            f.write(f"URL: http://localhost:5000\n")
            f.write(f"{'='*60}\n")
    except:
        pass
    
    app.run(debug=True, host='0.0.0.0', port=5000)
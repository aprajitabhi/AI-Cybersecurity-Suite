import re
import tldextract
import whois
import requests
import socket
import dns.resolver
from urllib.parse import urlparse
import pandas as pd
import numpy as np
from datetime import datetime
import joblib
import nltk
from nltk.tokenize import word_tokenize
from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings('ignore')

class PhishingDetector:
    def __init__(self, model_path=None):
        self.model = None
        if model_path:
            self.load_model(model_path)
        
        # Features for ML model
        self.feature_names = [
            'url_length', 'num_dots', 'num_hyphens', 'num_at', 'num_ques', 
            'num_and', 'num_excl', 'num_tilde', 'num_hash', 'num_percent',
            'num_slash', 'num_equal', 'has_https', 'has_ip', 'domain_len',
            'path_len', 'subdomain_len', 'has_suspicious_words', 'tld_len',
            'age_days', 'has_whois', 'dns_records', 'redirect_count'
        ]
    
    def load_model(self, model_path):
        """Load trained ML model"""
        try:
            self.model = joblib.load(model_path)
            print(f"Model loaded from {model_path}")
        except:
            print("Could not load model. Using rule-based detection.")
    
    def extract_url_features(self, url):
        """Extract features from URL for ML prediction"""
        features = {}
        
        # Basic URL features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_at'] = url.count('@')
        features['num_ques'] = url.count('?')
        features['num_and'] = url.count('&')
        features['num_excl'] = url.count('!')
        features['num_tilde'] = url.count('~')
        features['num_hash'] = url.count('#')
        features['num_percent'] = url.count('%')
        features['num_slash'] = url.count('/')
        features['num_equal'] = url.count('=')
        
        # Protocol features
        features['has_https'] = 1 if url.startswith('https') else 0
        
        # IP address in URL
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features['has_ip'] = 1 if re.search(ip_pattern, url) else 0
        
        # Domain features
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
        
        features['domain_len'] = len(domain)
        features['path_len'] = len(parsed.path)
        
        # Subdomain features
        subdomain_count = domain.count('.')
        features['subdomain_len'] = subdomain_count
        
        # TLD features
        extracted = tldextract.extract(url)
        features['tld_len'] = len(extracted.suffix)
        
        # Suspicious words
        suspicious_words = ['login', 'signin', 'verify', 'account', 'secure',
                           'update', 'banking', 'confirm', 'password', 'wallet']
        features['has_suspicious_words'] = sum(
            1 for word in suspicious_words if word in url.lower()
        )
        
        return features
    
    def get_whois_info(self, domain):
        """Get WHOIS information for domain"""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                return age_days, True
        except:
            pass
        return 0, False
    
    def check_dns_records(self, domain):
        """Check DNS records for domain"""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return len(answers) > 0
        except:
            return False
    
    def analyze_content(self, html_content):
        """Analyze HTML content for phishing indicators"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        indicators = {
            'has_form': len(soup.find_all('form')) > 0,
            'has_password_field': len(soup.find_all('input', {'type': 'password'})) > 0,
            'has_external_scripts': len(soup.find_all('script', src=True)) > 0,
            'has_iframes': len(soup.find_all('iframe')) > 0,
            'form_action_external': False
        }
        
        # Check if form actions point to external domains
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if action and ('http://' in action or 'https://' in action):
                indicators['form_action_external'] = True
        
        return indicators
    
    def predict_phishing(self, url, html_content=None):
        """Predict if URL is phishing using ML and rule-based methods"""
        results = {
            'url': url,
            'is_phishing': False,
            'confidence': 0.0,
            'features': {},
            'indicators': [],
            'risk_score': 0
        }
        
        # Extract features
        url_features = self.extract_url_features(url)
        results['features'] = url_features
        
        # Rule-based checks
        indicators = []
        
        # Check for known phishing domains
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
        
        # Rule 1: URL length
        if len(url) > 75:
            indicators.append("URL is unusually long")
            results['risk_score'] += 20
        
        # Rule 2: Contains IP address
        if url_features['has_ip']:
            indicators.append("URL contains IP address instead of domain name")
            results['risk_score'] += 30
        
        # Rule 3: Multiple subdomains
        if url_features['subdomain_len'] > 3:
            indicators.append("URL has multiple subdomains")
            results['risk_score'] += 15
        
        # Rule 4: Suspicious TLD
        suspicious_tlds = ['.xyz', '.top', '.club', '.info', '.tk', '.ml', '.ga', '.cf']
        if any(tld in url for tld in suspicious_tlds):
            indicators.append("URL uses suspicious TLD")
            results['risk_score'] += 25
        
        # Rule 5: HTTPS check
        if not url_features['has_https']:
            indicators.append("URL doesn't use HTTPS")
            results['risk_score'] += 10
        
        # ML prediction if model is available
        if self.model:
            features_df = pd.DataFrame([url_features])[self.feature_names]
            prediction = self.model.predict(features_df)[0]
            probability = self.model.predict_proba(features_df)[0]
            
            results['is_phishing'] = bool(prediction)
            results['confidence'] = float(max(probability))
            
            if prediction:
                results['risk_score'] += int(probability[1] * 100)
        
        # Check WHOIS
        try:
            age_days, has_whois = self.get_whois_info(domain)
            if age_days < 30:
                indicators.append(f"Domain is very new ({age_days} days old)")
                results['risk_score'] += 20
        except:
            pass
        
        # Content analysis if HTML provided
        if html_content:
            content_indicators = self.analyze_content(html_content)
            if content_indicators['has_password_field'] and content_indicators['form_action_external']:
                indicators.append("Login form submits to external domain")
                results['risk_score'] += 40
        
        results['indicators'] = indicators
        
        # Final determination
        if results['risk_score'] >= 50 or results['is_phishing']:
            results['is_phishing'] = True
        
        return results
    
    def check_multiple_urls(self, urls):
        """Check multiple URLs in batch"""
        results = []
        for url in urls:
            try:
                result = self.predict_phishing(url)
                results.append(result)
            except Exception as e:
                results.append({
                    'url': url,
                    'error': str(e),
                    'is_phishing': None
                })
        return results
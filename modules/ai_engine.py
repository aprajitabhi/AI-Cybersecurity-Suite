import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import joblib
import pickle
import json
from datetime import datetime, timedelta

class AIThreatEngine:
    def __init__(self):
        self.phishing_model = None
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.threat_intelligence = self.load_threat_intelligence()
    
    def load_threat_intelligence(self):
        """Load threat intelligence feeds"""
        # In production, this would connect to external threat feeds
        return {
            'malicious_ips': [],
            'suspicious_domains': [],
            'attack_patterns': []
        }
    
    def train_phishing_model(self, data_path=None):
        """Train phishing detection model"""
        # Example dataset (in production, use real phishing/legitimate URLs)
        # Format: [features], label (1=phishing, 0=legitimate)
        
        # Create sample data for demonstration
        np.random.seed(42)
        n_samples = 1000
        
        # Generate synthetic features
        X = np.random.randn(n_samples, 23)
        
        # Create labels (simulate phishing patterns)
        y = np.zeros(n_samples)
        
        # Simulate phishing patterns
        phishing_indices = np.random.choice(n_samples, size=200, replace=False)
        X[phishing_indices, 0] += 3  # Longer URLs
        X[phishing_indices, 1] += 2  # More dots
        X[phishing_indices, 13] = 1  # Has IP
        y[phishing_indices] = 1
        
        # Train model
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest
        self.phishing_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        self.phishing_model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.phishing_model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"Model trained with accuracy: {accuracy:.2f}")
        print(classification_report(y_test, y_pred))
        
        # Save model
        joblib.dump(self.phishing_model, 'models/phishing_model.pkl')
        joblib.dump(self.scaler, 'models/scaler.pkl')
        
        return accuracy
    
    def train_anomaly_detector(self, network_data):
        """Train anomaly detection model for network traffic"""
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        
        # Assuming network_data is a DataFrame with features
        scaled_data = self.scaler.fit_transform(network_data)
        self.anomaly_detector.fit(scaled_data)
        
        joblib.dump(self.anomaly_detector, 'models/anomaly_detector.pkl')
        
        return self.anomaly_detector
    
    def detect_anomalies(self, network_features):
        """Detect anomalies in network traffic"""
        if self.anomaly_detector is None:
            return []
        
        scaled_features = self.scaler.transform([network_features])
        prediction = self.anomaly_detector.predict(scaled_features)
        
        return prediction[0] == -1  # -1 indicates anomaly
    
    def correlate_threats(self, phishing_results, scan_results):
        """Correlate findings from different modules"""
        threats = []
        
        # Combine phishing and vulnerability data
        for phishing in phishing_results:
            if phishing.get('is_phishing', False):
                threats.append({
                    'type': 'Phishing',
                    'target': phishing['url'],
                    'risk_score': phishing['risk_score'],
                    'timestamp': datetime.now()
                })
        
        for scan in scan_results:
            if 'protocols' in scan:
                for port, info in scan['protocols'].items():
                    if info['risk_level'] in ['High', 'Critical']:
                        threats.append({
                            'type': 'Vulnerability',
                            'target': scan['target'],
                            'port': port,
                            'service': info['service'],
                            'risk_level': info['risk_level'],
                            'timestamp': datetime.now()
                        })
        
        # Sort by risk
        threats.sort(key=lambda x: x.get('risk_score', 0) if 'risk_score' in x else 
                    {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}[x.get('risk_level', 'Low')],
                    reverse=True)
        
        return threats
    
    def generate_threat_report(self, threats):
        """Generate comprehensive threat report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_threats': len(threats),
            'critical_threats': len([t for t in threats if t.get('risk_level') == 'Critical' or t.get('risk_score', 0) >= 70]),
            'threats_by_type': {},
            'detailed_threats': threats
        }
        
        # Count by type
        for threat in threats:
            threat_type = threat['type']
            report['threats_by_type'][threat_type] = report['threats_by_type'].get(threat_type, 0) + 1
        
        return report
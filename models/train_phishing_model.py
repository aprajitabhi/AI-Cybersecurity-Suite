import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

def train_phishing_model():
    """Train a phishing detection model"""
    
    # Create sample dataset (replace with real data in production)
    np.random.seed(42)
    n_samples = 2000
    
    # Feature names (23 features)
    feature_names = [
        'url_length', 'num_dots', 'num_hyphens', 'num_at', 'num_ques', 
        'num_and', 'num_excl', 'num_tilde', 'num_hash', 'num_percent',
        'num_slash', 'num_equal', 'has_https', 'has_ip', 'domain_len',
        'path_len', 'subdomain_len', 'has_suspicious_words', 'tld_len',
        'age_days', 'has_whois', 'dns_records', 'redirect_count'
    ]
    
    # Generate synthetic data
    X = np.random.randn(n_samples, len(feature_names))
    
    # Create labels (20% phishing)
    y = np.zeros(n_samples)
    phishing_indices = np.random.choice(n_samples, size=int(n_samples * 0.2), replace=False)
    
    # Make phishing URLs different
    X[phishing_indices, 0] += np.random.uniform(2, 4, len(phishing_indices))  # Longer URLs
    X[phishing_indices, 1] += np.random.uniform(1, 3, len(phishing_indices))  # More dots
    X[phishing_indices, 13] = 1  # Has IP
    X[phishing_indices, 17] += np.random.uniform(1, 3, len(phishing_indices))  # Suspicious words
    y[phishing_indices] = 1
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train model
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        class_weight='balanced',
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)
    
    print("Model Evaluation:")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.3f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\nTop 10 Important Features:")
    print(feature_importance.head(10))
    
    # Save model
    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/phishing_model.pkl')
    
    # Save feature names for reference
    joblib.dump(feature_names, 'models/feature_names.pkl')
    
    print("\nModel saved to 'models/phishing_model.pkl'")
    
    return model, feature_importance

if __name__ == '__main__':
    model, feature_importance = train_phishing_model()
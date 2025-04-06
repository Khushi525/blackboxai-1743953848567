import re
import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from joblib import dump, load

# Initialize model
model = None

def load_model():
    """Load or train the model"""
    global model
    model_path = 'data/model.joblib'
    data_path = 'data/malicious_phish.csv'
    
    if os.path.exists(model_path):
        model = load(model_path)
    elif os.path.exists(data_path):
        train_model()
    else:
        print("Warning: No training data found. Using placeholder predictions.")

def train_model():
    """Train and save the model"""
    global model
    try:
        data = pd.read_csv('data/malicious_phish.csv')
        data['is_malicious'] = data['type'] != 'benign'
        
        # Extract features
        X = data['url'].apply(extract_features).tolist()
        y = data['is_malicious']
        
        # Train model
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
        model = RandomForestClassifier()
        model.fit(X_train, y_train)
        
        # Save model
        dump(model, 'data/model.joblib')
        print("Model trained and saved successfully")
    except Exception as e:
        print(f"Error training model: {str(e)}")

def predict_url(url):
    """Predict if a URL is malicious and its threat level"""
    if not model:
        load_model()
    
    features = extract_features(url)
    prediction = model.predict([features])[0]
    proba = model.predict_proba([features])[0][1]
    
    if prediction:
        if proba > 0.8:
            threat_level = 'high'
        elif proba > 0.5:
            threat_level = 'medium'
        else:
            threat_level = 'low'
        return 'malicious', threat_level
    return 'safe', 'low'

def extract_features(url):
    """Extract features from URL for prediction"""
    features = {
        'length': len(url),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_underscores': url.count('_'),
        'num_slashes': url.count('/'),
        'num_questionmarks': url.count('?'),
        'num_equals': url.count('='),
        'num_ats': url.count('@'),
        'has_https': 1 if url.startswith('https://') else 0,
        'has_ip': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', url) else 0,
        'shortened': 1 if any(x in url for x in ['bit.ly', 'goo.gl', 'tinyurl']) else 0
    }
    return list(features.values())

# Load the model when this module is imported
load_model()
import re
from joblib import load
import os
import random

# Placeholder for the actual model (will be implemented after training)
model = None

def load_model():
    """Load the trained model from file"""
    global model
    model_path = 'data/model.joblib'
    if os.path.exists(model_path):
        model = load(model_path)
    else:
        print("Warning: No trained model found. Using placeholder predictions.")

def predict_url(url):
    """Predict if a URL is malicious and its threat level"""
    # If we have a real model, use it
    if model:
        features = extract_features(url)
        prediction = model.predict([features])[0]
        proba = model.predict_proba([features])[0][1]
    else:
        # Placeholder logic until we train the actual model
        prediction = random.random() > 0.7  # 30% chance of being malicious
        proba = random.random()  # Random probability

    # Determine threat level based on probability
    if prediction:
        if proba > 0.8:
            threat_level = 'high'
        elif proba > 0.5:
            threat_level = 'medium'
        else:
            threat_level = 'low'
        return 'malicious', threat_level
    else:
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
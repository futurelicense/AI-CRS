import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os
import time
import random
from datetime import datetime, timedelta

def train_threat_classifier():
    """
    Train a simple text classifier for threat descriptions.
    
    Returns:
        tuple: (vectorizer, model) The trained model and its vectorizer
    """
    # Create some example training data
    # In a real implementation, this would be replaced with actual historical data
    training_data = [
        {"text": "Failed login attempts from multiple locations", "category": "Unauthorized Access"},
        {"text": "Malware detected on workstation", "category": "Malware"},
        {"text": "Data exfiltration to unknown IP", "category": "Data Breach"},
        {"text": "Phishing email with malicious attachment", "category": "Phishing"},
        {"text": "Ransomware outbreak with encrypted files", "category": "Ransomware"},
        {"text": "DDoS attack against web server", "category": "DDoS"},
        {"text": "Suspicious activity from privileged account", "category": "Insider Threat"},
        {"text": "SQL injection attempt on web application", "category": "Web Attack"},
        {"text": "Brute force attack against SSH", "category": "Unauthorized Access"},
        {"text": "Trojan detected in email attachment", "category": "Malware"},
        {"text": "Sensitive customer data accessed by unauthorized user", "category": "Data Breach"},
        {"text": "Email containing fraudulent invoice link", "category": "Phishing"},
        {"text": "File encryption detected on multiple systems", "category": "Ransomware"},
        {"text": "High volume of traffic targeting API endpoint", "category": "DDoS"},
        {"text": "Unusual data access pattern from employee", "category": "Insider Threat"},
        {"text": "Cross-site scripting attack on customer portal", "category": "Web Attack"},
        {"text": "Unusual authentication from foreign country", "category": "Unauthorized Access"},
        {"text": "Backdoor installation detected", "category": "Malware"},
        {"text": "Unauthorized access to HR database", "category": "Data Breach"},
        {"text": "CEO impersonation email requesting wire transfer", "category": "Phishing"},
        {"text": "Bitcoin payment demanded for file decryption", "category": "Ransomware"},
        {"text": "Network flood from botnet", "category": "DDoS"},
        {"text": "Confidential documents downloaded after hours", "category": "Insider Threat"},
        {"text": "Command injection detected in web logs", "category": "Web Attack"},
        {"text": "Multiple failed 2FA attempts", "category": "Unauthorized Access"},
        {"text": "Fileless malware detected in memory", "category": "Malware"},
        {"text": "Customer credit card data leaked", "category": "Data Breach"},
        {"text": "Fake password reset email campaign", "category": "Phishing"},
        {"text": "System locked with ransom note", "category": "Ransomware"},
        {"text": "Service unavailable due to traffic spike", "category": "DDoS"},
        {"text": "Privileged account sharing detected", "category": "Insider Threat"},
        {"text": "Remote file inclusion attempt", "category": "Web Attack"}
    ]
    
    # Convert to DataFrame
    df = pd.DataFrame(training_data)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        df['text'], df['category'], test_size=0.2, random_state=42
    )
    
    # Create and train the vectorizer
    vectorizer = CountVectorizer()
    X_train_vec = vectorizer.fit_transform(X_train)
    
    # Train the model
    model = MultinomialNB()
    model.fit(X_train_vec, y_train)
    
    # Evaluate the model
    X_test_vec = vectorizer.transform(X_test)
    y_pred = model.predict(X_test_vec)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"Threat classifier trained with accuracy: {accuracy:.2f}")
    return vectorizer, model

def classify_threat(text, vectorizer=None, model=None):
    """
    Classify a threat description using a trained model or dummy logic.
    
    Args:
        text (str): The threat description text
        vectorizer: The CountVectorizer for the model (optional)
        model: The trained classification model (optional)
        
    Returns:
        dict: Classification results including category and confidence
    """
    # If model and vectorizer are provided, use them
    if model is not None and vectorizer is not None:
        # Transform the text and predict
        text_vec = vectorizer.transform([text])
        category = model.predict(text_vec)[0]
        
        # Get confidence scores (probabilities)
        proba = model.predict_proba(text_vec)[0]
        confidence = proba[list(model.classes_).index(category)]
        
    else:
        # Fallback to keyword-based classification
        text_lower = text.lower()
        
        # Define keywords for each category
        categories = {
            'Unauthorized Access': ['login', 'access', 'credential', 'authentication', 'password'],
            'Malware': ['malware', 'virus', 'trojan', 'worm', 'backdoor'],
            'Data Breach': ['breach', 'exfiltration', 'leak', 'data', 'sensitive'],
            'Phishing': ['phishing', 'email', 'link', 'attachment', 'social engineering'],
            'Ransomware': ['ransomware', 'encrypt', 'bitcoin', 'payment', 'ransom'],
            'DDoS': ['ddos', 'traffic', 'flood', 'service', 'availability'],
            'Insider Threat': ['insider', 'employee', 'privileged', 'internal', 'abuse'],
            'Web Attack': ['injection', 'xss', 'sql', 'web', 'application']
        }
        
        # Count matches for each category
        category_matches = {}
        for cat, keywords in categories.items():
            matches = sum(1 for keyword in keywords if keyword in text_lower)
            category_matches[cat] = matches
        
        # Select category with most keyword matches
        if sum(category_matches.values()) > 0:
            category = max(category_matches, key=category_matches.get)
            # Calculate confidence based on proportion of matches
            total_matches = sum(category_matches.values())
            confidence = category_matches[category] / total_matches if total_matches > 0 else 0.5
            confidence = min(0.95, max(0.6, confidence))  # Keep between 0.6 and 0.95
        else:
            # Default if no matches
            category = 'Unknown'
            confidence = 0.5
    
    # Add timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    return {
        'category': category,
        'confidence': round(confidence, 2),
        'timestamp': timestamp
    }

def predict_future_threats(historical_data, days=30):
    """
    Predict future threats based on historical data.
    
    Args:
        historical_data (pd.DataFrame): DataFrame of historical threat data
        days (int): Number of days to predict ahead
        
    Returns:
        pd.DataFrame: DataFrame of predicted threats
    """
    # Ensure timestamp column is datetime
    historical_data = historical_data.copy()
    if 'timestamp' in historical_data.columns:
        historical_data['timestamp'] = pd.to_datetime(historical_data['timestamp'])
    
    # Get the frequency of each threat category
    if 'category' in historical_data.columns:
        category_counts = historical_data['category'].value_counts().to_dict()
    else:
        # Default categories if not present
        category_counts = {
            'Malware': 5,
            'Phishing': 4,
            'DDoS': 3,
            'Unauthorized Access': 3,
            'Data Breach': 2,
            'Ransomware': 2
        }
    
    # Get severity distribution
    if 'severity' in historical_data.columns:
        severity_counts = historical_data['severity'].value_counts().to_dict()
    else:
        # Default severity distribution
        severity_counts = {
            'High': 5,
            'Medium': 8,
            'Critical': 3,
            'Low': 4
        }
    
    # Convert counts to probabilities
    category_total = sum(category_counts.values())
    category_probs = {k: v/category_total for k, v in category_counts.items()}
    
    severity_total = sum(severity_counts.values())
    severity_probs = {k: v/severity_total for k, v in severity_counts.items()}
    
    # Generate predictions
    predictions = []
    start_date = datetime.now()
    
    for day in range(1, days+1):
        prediction_date = start_date + timedelta(days=day)
        
        # Randomly determine number of threats per day (1-5)
        num_threats = random.randint(1, 5)
        
        for i in range(num_threats):
            # Sample category and severity based on historical distributions
            category = random.choices(list(category_probs.keys()), 
                                     weights=list(category_probs.values()))[0]
            severity = random.choices(list(severity_probs.keys()), 
                                     weights=list(severity_probs.values()))[0]
            
            # Generate a confidence level
            confidence = round(random.uniform(0.65, 0.95), 2)
            
            # Create a dummy threat prediction
            prediction = {
                'date': prediction_date.strftime('%Y-%m-%d'),
                'category': category,
                'severity': severity,
                'confidence': confidence,
                'predicted_count': random.randint(1, 10)
            }
            
            predictions.append(prediction)
    
    return pd.DataFrame(predictions)

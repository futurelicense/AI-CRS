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
    Classify a threat description using:
    1. A trained model if provided
    2. Hugging Face API if available
    3. Fallback to keyword-based classification
    
    Args:
        text (str): The threat description text
        vectorizer: The CountVectorizer for the model (optional)
        model: The trained classification model (optional)
        
    Returns:
        dict: Classification results including category and confidence
    """
    import os
    from utils.threat_intelligence import fetch_hugging_face_analysis
    
    # Check if Hugging Face API key is available
    api_key = os.getenv('HUGGINGFACE_API_KEY')
    
    # Option 1: If model and vectorizer are provided, use them
    if model is not None and vectorizer is not None:
        # Transform the text and predict using trained model
        text_vec = vectorizer.transform([text])
        category = model.predict(text_vec)[0]
        
        # Get confidence scores (probabilities)
        proba = model.predict_proba(text_vec)[0]
        confidence = proba[list(model.classes_).index(category)]
        
        model_type = "local_trained_model"
        
    # Option 2: If HuggingFace API key is available, use that for more advanced classification
    elif api_key:
        try:
            # Use zero-shot classification model for flexibility with cyber threats
            huggingface_result = fetch_hugging_face_analysis(
                text, 
                model_name="facebook/bart-large-mnli"  # Zero-shot classification model
            )
            
            # Extract category and confidence from the HuggingFace result
            category = huggingface_result.get('classification', 'Unknown')
            confidence = huggingface_result.get('confidence', 0.5)
            model_type = f"huggingface_{huggingface_result.get('model', 'unknown')}"
            
            # Extract additional insights if available
            additional_insights = {}
            raw_response = huggingface_result.get('raw_response', {})
            
            if isinstance(raw_response, list) and len(raw_response) > 0:
                # For zero-shot models, extract all labels and scores for additional insights
                if 'labels' in raw_response[0] and 'scores' in raw_response[0]:
                    labels = raw_response[0].get('labels', [])
                    scores = raw_response[0].get('scores', [])
                    
                    # Create a mapping of all categories and their scores
                    additional_insights['alternative_categories'] = [
                        {'category': label, 'score': round(float(score), 2)} 
                        for label, score in zip(labels, scores)
                        if label != category  # Skip the primary category
                    ]
            
        except Exception as e:
            print(f"Error using Hugging Face API for threat classification: {str(e)}")
            # Fall back to keyword-based classification
            category, confidence, model_type, additional_insights = _keyword_based_threat_classification(text, return_details=True)
    
    # Option 3: Fallback to keyword-based classification
    else:
        category, confidence, model_type, additional_insights = _keyword_based_threat_classification(text, return_details=True)
    
    # Add timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    result = {
        'category': category,
        'confidence': round(float(confidence), 2),
        'timestamp': timestamp,
        'model': model_type
    }
    
    # Add additional insights if available
    if additional_insights:
        result.update(additional_insights)
        
    # Add threat intelligence recommendations
    result['recommendations'] = get_threat_recommendations(category, text)
        
    return result

def get_threat_recommendations(category, description):
    """
    Generate AI-powered recommendations for addressing the threat.
    
    Args:
        category (str): The threat category
        description (str): The threat description
        
    Returns:
        list: List of recommendations
    """
    # Base recommendations by category
    base_recommendations = {
        'Unauthorized Access': [
            'Implement multi-factor authentication',
            'Review access control policies',
            'Audit user privileges and implement least privilege',
            'Enable login anomaly detection'
        ],
        'Malware': [
            'Update antivirus definitions',
            'Perform full system scan',
            'Isolate affected systems from the network',
            'Review application whitelisting policies'
        ],
        'Data Breach': [
            'Identify and secure compromised data',
            'Notify affected parties as required by regulations',
            'Implement data loss prevention controls',
            'Encrypt sensitive data at rest and in transit'
        ],
        'Phishing': [
            'Conduct employee awareness training',
            'Implement email filtering and authentication',
            'Scan for compromised credentials',
            'Enable URL filtering and web protection'
        ],
        'Ransomware': [
            'Isolate affected systems immediately',
            'Restore from clean backups if available',
            'Scan for encryption backdoors',
            'Implement application control policies'
        ],
        'DDoS': [
            'Engage with DDoS mitigation service',
            'Implement rate limiting at network edge',
            'Configure traffic anomaly detection',
            'Review network architecture for resilience'
        ],
        'Insider Threat': [
            'Review activity logs for anomalous behavior',
            'Implement data access monitoring',
            'Update security training and awareness',
            'Review privileged access management'
        ],
        'Web Attack': [
            'Apply security patches to web applications',
            'Review web application firewall rules',
            'Perform security code review',
            'Implement input validation and sanitization'
        ]
    }
    
    # Get base recommendations for the category
    recommendations = base_recommendations.get(category, [
        'Perform thorough security assessment',
        'Update incident response playbook',
        'Review security controls and architecture',
        'Implement defense in depth strategies'
    ])
    
    # Add context-specific recommendations based on description
    description_lower = description.lower()
    
    # Check for specific indicators in the description to provide targeted recommendations
    if 'cloud' in description_lower or 'aws' in description_lower or 'azure' in description_lower:
        recommendations.append('Review cloud security configuration and access controls')
        
    if 'iot' in description_lower or 'device' in description_lower or 'sensor' in description_lower:
        recommendations.append('Update firmware on IoT devices and implement network segmentation')
        
    if 'credentials' in description_lower or 'password' in description_lower:
        recommendations.append('Force password reset for affected accounts and implement password complexity requirements')
        
    if 'zero-day' in description_lower or 'unpatched' in description_lower or 'vulnerability' in description_lower:
        recommendations.append('Implement virtual patching through WAF or IPS while vendor patch is pending')
    
    return recommendations

def _keyword_based_threat_classification(text, return_details=False):
    """
    Fallback method that uses keyword matching to classify threats.
    
    Args:
        text (str): The text to analyze
        return_details (bool): Whether to return additional details
        
    Returns:
        tuple: (category, confidence, model_type) or (category, confidence, model_type, additional_details)
    """
    text_lower = text.lower()
    
    # Define keywords for each category
    categories = {
        'Unauthorized Access': ['login', 'access', 'credential', 'authentication', 'password', 'unauthorized', 'admin'],
        'Malware': ['malware', 'virus', 'trojan', 'worm', 'backdoor', 'payload', 'executable', 'infection'],
        'Data Breach': ['breach', 'exfiltration', 'leak', 'data', 'sensitive', 'exposure', 'confidential', 'disclosure'],
        'Phishing': ['phishing', 'email', 'link', 'attachment', 'social engineering', 'spear', 'impersonation'],
        'Ransomware': ['ransomware', 'encrypt', 'bitcoin', 'payment', 'ransom', 'crypto', 'locker', 'decrypt'],
        'DDoS': ['ddos', 'traffic', 'flood', 'service', 'availability', 'bandwidth', 'amplification', 'volumetric'],
        'Insider Threat': ['insider', 'employee', 'privileged', 'internal', 'abuse', 'contractor', 'staff'],
        'Web Attack': ['injection', 'xss', 'sql', 'web', 'application', 'site', 'csrf', 'cookies', 'session']
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
    
    if return_details:
        # Create alternative categories by sorting the matches
        sorted_categories = sorted(
            [(cat, matches) for cat, matches in category_matches.items() if matches > 0 and cat != category],
            key=lambda x: x[1],
            reverse=True
        )
        
        additional_insights = {}
        if sorted_categories:
            # Include the top 3 alternative categories if available
            alternative_categories = []
            for cat, matches in sorted_categories[:3]:
                # Calculate a relative confidence score
                alt_confidence = matches / total_matches if total_matches > 0 else 0.3
                alt_confidence = min(0.9, max(0.4, alt_confidence))  # Keep between 0.4 and 0.9
                alternative_categories.append({
                    'category': cat,
                    'score': round(alt_confidence, 2)
                })
            
            if alternative_categories:
                additional_insights['alternative_categories'] = alternative_categories
        
        # Also include the matched keywords as indicators
        matched_keywords = []
        for cat, keywords in categories.items():
            for keyword in keywords:
                if keyword in text_lower:
                    matched_keywords.append(keyword)
        
        if matched_keywords:
            additional_insights['matched_keywords'] = matched_keywords[:5]  # Limit to top 5 keywords
        
        return category, confidence, "keyword_based_classification", additional_insights
    
    return category, confidence, "keyword_based_classification"

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

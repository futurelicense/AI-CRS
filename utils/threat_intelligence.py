import pandas as pd
import numpy as np
import requests
import os
from datetime import datetime
import json
import random
import time

def fetch_hugging_face_analysis(text, model_name="deepset/roberta-base-squad2"):
    """
    Fetch analysis from Hugging Face API for threat text.
    This function connects to the Hugging Face Inference API to analyze threat descriptions
    using transformer models.
    
    Args:
        text (str): The text to analyze
        model_name (str): The Hugging Face model to use
        
    Returns:
        dict: The analysis results
    """
    try:
        # Check if we have the API key
        api_key = os.getenv('HUGGINGFACE_API_KEY')
        
        if api_key:
            # Real API call to Hugging Face
            API_URL = f"https://api-inference.huggingface.co/models/{model_name}"
            headers = {"Authorization": f"Bearer {api_key}"}
            
            # Define the payload based on the model type
            if "squad" in model_name.lower():
                # For question-answering models
                payload = {
                    "inputs": {
                        "question": "What type of cyber threat is this?",
                        "context": text
                    }
                }
            elif "zero-shot-classification" in model_name.lower():
                # For zero-shot classification models
                payload = {
                    "inputs": text,
                    "parameters": {
                        "candidate_labels": ["Malware", "Ransomware", "Phishing", "DDoS", "Data Breach", "APT", "Insider Threat"]
                    }
                }
            else:
                # For text classification/sentiment models
                payload = {"inputs": text}
            
            # Make the API request
            response = requests.post(API_URL, headers=headers, json=payload)
            
            # Process the response based on the model type
            if response.status_code == 200:
                result = response.json()
                
                # Process result based on model type
                if "squad" in model_name.lower():
                    # Extract answer from QA model
                    classification = result.get('answer', 'Unknown')
                    confidence = result.get('score', 0.0)
                elif "zero-shot-classification" in model_name.lower():
                    # Extract best label and score from zero-shot
                    if isinstance(result, list) and len(result) > 0:
                        labels = result[0].get('labels', [])
                        scores = result[0].get('scores', [])
                        if labels and scores:
                            classification = labels[0]
                            confidence = scores[0]
                        else:
                            classification = 'Unknown'
                            confidence = 0.0
                    else:
                        classification = 'Unknown'
                        confidence = 0.0
                else:
                    # For sentiment/text classification models
                    if isinstance(result, list) and len(result) > 0:
                        if isinstance(result[0], dict) and 'label' in result[0]:
                            classification = result[0].get('label', 'Unknown')
                            confidence = result[0].get('score', 0.0)
                        else:
                            classification = 'Unknown'
                            confidence = 0.0
                    else:
                        classification = 'Unknown'
                        confidence = 0.0
                
                return {
                    'classification': classification,
                    'confidence': round(float(confidence), 2),
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'model': model_name,
                    'raw_response': result  # Include raw response for debugging
                }
            else:
                # Handle API error
                error_msg = f"API Error: {response.status_code} - {response.text}"
                print(error_msg)
                
                # Fall back to keyword-based classification
                return _keyword_based_classification(text)
        else:
            # API key not available, use fallback
            print("Hugging Face API key not found, using fallback classification")
            return _keyword_based_classification(text)
                
    except Exception as e:
        print(f"Error with Hugging Face API: {str(e)}")
        # Fall back to keyword-based classification
        return _keyword_based_classification(text)

def _keyword_based_classification(text):
    """
    Fallback method that uses keyword matching to classify threats
    when the Hugging Face API is unavailable.
    
    Args:
        text (str): The text to analyze
        
    Returns:
        dict: The classification results
    """
    # For demo purposes, return keyword-based classification results
    text_lower = text.lower()
    
    # Classify based on keywords in the text
    if any(word in text_lower for word in ['malware', 'virus', 'trojan', 'worm']):
        classification = 'Malware'
        confidence = random.uniform(0.75, 0.95)
    elif any(word in text_lower for word in ['ransomware', 'encrypt', 'ransom', 'bitcoin']):
        classification = 'Ransomware'
        confidence = random.uniform(0.80, 0.98)
    elif any(word in text_lower for word in ['phishing', 'email', 'credential', 'login']):
        classification = 'Phishing'
        confidence = random.uniform(0.70, 0.90)
    elif any(word in text_lower for word in ['ddos', 'denial', 'service', 'traffic']):
        classification = 'DDoS'
        confidence = random.uniform(0.65, 0.85)
    elif any(word in text_lower for word in ['breach', 'leak', 'data', 'exposure']):
        classification = 'Data Breach'
        confidence = random.uniform(0.60, 0.88)
    elif any(word in text_lower for word in ['apt', 'advanced', 'persistent', 'nation']):
        classification = 'APT' 
        confidence = random.uniform(0.70, 0.92)
    elif any(word in text_lower for word in ['insider', 'employee', 'internal']):
        classification = 'Insider Threat'
        confidence = random.uniform(0.65, 0.90)
    else:
        classification = 'Other'
        confidence = random.uniform(0.50, 0.70)
        
    return {
        'classification': classification,
        'confidence': round(confidence, 2),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'model': 'keyword-fallback',
        'note': 'Using fallback keyword-based classification'
    }

def get_threat_intelligence(threat_type=None):
    """
    Get threat intelligence data.
    In a real implementation, this would connect to IBM X-Force or similar API.
    
    Args:
        threat_type (str, optional): Filter to a specific threat type
        
    Returns:
        pd.DataFrame: Threat intelligence data
    """
    # Simulated threat intelligence data
    threat_intel = [
        {
            'id': 1,
            'name': 'EMOTET Botnet Activity',
            'type': 'Malware',
            'description': 'EMOTET botnet activity detected with new command and control servers.',
            'indicators': '45.32.12.34,emotet-loader.xyz,2c7cdead4387fa4a01f1169a1b8cee9e',
            'last_seen': '2023-11-05',
            'threat_level': 'High',
            'recommendations': 'Block listed IPs and domains, scan for indicators of compromise.'
        },
        {
            'id': 2,
            'name': 'Ransomware Campaign',
            'type': 'Ransomware',
            'description': 'New ransomware campaign targeting healthcare organizations via phishing emails.',
            'indicators': 'ransom-secure.xyz,invoice-urgent.pdf,93.114.235.45',
            'last_seen': '2023-11-12',
            'threat_level': 'Critical',
            'recommendations': 'Train users on phishing awareness, implement email filtering rules.'
        },
        {
            'id': 3,
            'name': 'APT29 Activity',
            'type': 'APT',
            'description': 'APT29 targeting government agencies with new spear-phishing techniques.',
            'indicators': 'gov-update.com,policy-document.doc,195.123.221.7',
            'last_seen': '2023-11-08',
            'threat_level': 'Critical',
            'recommendations': 'Implement multi-factor authentication, patch systems, monitor for unusual authentication.'
        },
        {
            'id': 4,
            'name': 'Log4j Exploitation',
            'type': 'Vulnerability',
            'description': 'Ongoing exploitation of Log4j vulnerability (CVE-2021-44228) observed.',
            'indicators': '${jndi:ldap://malicious-log4j.com/payload},8.219.186.60',
            'last_seen': '2023-11-10',
            'threat_level': 'High',
            'recommendations': 'Update Log4j to latest version, implement WAF rules, scan for vulnerable instances.'
        },
        {
            'id': 5,
            'name': 'DDoS Botnet',
            'type': 'DDoS',
            'description': 'New IoT botnet conducting large-scale DDoS attacks against financial institutions.',
            'indicators': '91.234.36.123,botnet-cc.net,UDP port 53413',
            'last_seen': '2023-11-14',
            'threat_level': 'Medium',
            'recommendations': 'Implement DDoS protection services, monitor for unusual network traffic.'
        },
        {
            'id': 6,
            'name': 'Supply Chain Attack',
            'type': 'Supply Chain',
            'description': 'Compromised software updates being used to distribute malware.',
            'indicators': 'update-cdn.net,software-patch-v2.3.exe,3a569f68c8f3d1ec45a263c3ba0a7a34',
            'last_seen': '2023-11-06',
            'threat_level': 'High',
            'recommendations': 'Verify software updates through multiple channels, implement application whitelisting.'
        },
        {
            'id': 7,
            'name': 'Credential Stuffing',
            'type': 'Credential Theft',
            'description': 'Large-scale credential stuffing attacks targeting e-commerce platforms.',
            'indicators': '78.152.43.235,automated-login-patterns,high-volume-requests',
            'last_seen': '2023-11-13',
            'threat_level': 'Medium',
            'recommendations': 'Implement CAPTCHA, rate limiting, and account lockout policies.'
        },
        {
            'id': 8,
            'name': 'Zero-day Exploit',
            'type': 'Vulnerability',
            'description': 'Zero-day vulnerability in popular VPN solution being actively exploited.',
            'indicators': 'unusual-authentication-logs,217.23.14.8,vpn-config-fetch.php',
            'last_seen': '2023-11-11',
            'threat_level': 'Critical',
            'recommendations': 'Apply emergency mitigations, monitor for exploitation indicators, prepare for patch.'
        }
    ]
    
    df = pd.DataFrame(threat_intel)
    
    # Filter by threat type if specified
    if threat_type and threat_type != 'All':
        df = df[df['type'] == threat_type]
        
    return df

def get_mitigation_recommendations(threat_type):
    """
    Get mitigation recommendations for a specific threat type.
    
    Args:
        threat_type (str): The type of threat
        
    Returns:
        list: List of mitigation recommendations
    """
    recommendations = {
        'Malware': [
            'Deploy endpoint protection platforms (EPP) with advanced malware detection capabilities.',
            'Implement application whitelisting to prevent unauthorized programs from executing.',
            'Keep all operating systems and applications patched and updated.',
            'Segment networks to contain potential infections.',
            'Use email security solutions with attachment scanning and sandboxing.'
        ],
        'Ransomware': [
            'Maintain regular, tested backups stored offline or in air-gapped environments.',
            'Implement multi-factor authentication for all remote access and admin accounts.',
            'Restrict user permissions and admin privileges based on the principle of least privilege.',
            'Deploy EDR (Endpoint Detection and Response) solutions for early ransomware detection.',
            'Conduct regular phishing awareness training for all employees.'
        ],
        'Phishing': [
            'Implement email authentication protocols (SPF, DKIM, DMARC).',
            'Use anti-phishing training and simulations for employees.',
            'Deploy email filtering solutions with URL scanning capabilities.',
            'Establish procedures for reporting suspected phishing attempts.',
            'Implement web filtering to block access to known phishing sites.'
        ],
        'DDoS': [
            'Utilize DDoS protection services or anti-DDoS hardware.',
            'Implement rate limiting and traffic analysis tools.',
            'Ensure sufficient bandwidth and server capacity for traffic spikes.',
            'Develop and regularly test a DDoS response plan.',
            'Configure network infrastructure for TCP/SYN cookies and connection timeout adjustments.'
        ],
        'Data Breach': [
            'Implement data encryption for sensitive data both at rest and in transit.',
            'Conduct regular security assessments and penetration testing.',
            'Deploy Data Loss Prevention (DLP) solutions.',
            'Enforce strong access controls and authentication mechanisms.',
            'Develop and test an incident response plan specifically for data breaches.'
        ],
        'APT': [
            'Implement advanced threat protection systems with behavioral analytics.',
            'Conduct threat hunting exercises to proactively identify threats.',
            'Deploy deception technology and honeypots to detect lateral movement.',
            'Implement strict network segmentation with monitored chokepoints.',
            'Establish a security operations center (SOC) for 24/7 monitoring.'
        ],
        'Insider Threat': [
            'Implement user behavior analytics to detect unusual activities.',
            'Establish least privilege access controls and regular access reviews.',
            'Conduct background checks on employees with access to sensitive systems.',
            'Monitor and audit privileged user activities.',
            'Implement data access logging and alerting for sensitive information.'
        ],
        'Web Attack': [
            'Implement a Web Application Firewall (WAF).',
            'Conduct regular security code reviews and vulnerability assessments.',
            'Follow secure coding practices and input validation.',
            'Keep web applications and components updated and patched.',
            'Implement Content Security Policy (CSP) and other security headers.'
        ]
    }
    
    return recommendations.get(threat_type, [
        'Implement defense-in-depth security architecture.',
        'Conduct regular security awareness training for all employees.',
        'Maintain an up-to-date asset inventory and vulnerability management program.',
        'Develop and test incident response plans.',
        'Engage with threat intelligence sources for early warning of emerging threats.'
    ])

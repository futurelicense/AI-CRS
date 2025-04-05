import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import pandas as pd

def calculate_risk_score(severity, likelihood):
    """
    Calculate a risk score based on severity and likelihood.
    
    Args:
        severity (str): The severity level (Critical, High, Medium, Low)
        likelihood (float): The likelihood of the threat (0.0 to 1.0)
        
    Returns:
        float: The calculated risk score (0-100)
    """
    # Convert severity to numerical value
    severity_values = {
        'Critical': 10,
        'High': 7,
        'Medium': 5,
        'Low': 2
    }
    
    severity_value = severity_values.get(severity, 3)
    
    # Calculate risk score (severity * likelihood * 10)
    # This gives a score between 0 and 100
    risk_score = severity_value * likelihood * 10
    
    return round(risk_score, 1)

def prioritize_risks(threat_data, vulnerability_data):
    """
    Prioritize risks by combining threat and vulnerability data.
    
    Args:
        threat_data (pd.DataFrame): DataFrame of threat data
        vulnerability_data (pd.DataFrame): DataFrame of vulnerability data
        
    Returns:
        pd.DataFrame: DataFrame of prioritized risks
    """
    # Create a copy of the dataframes to avoid modifying originals
    threats = threat_data.copy()
    vulnerabilities = vulnerability_data.copy()
    
    # Calculate likelihood based on confidence for threats
    if 'confidence' in threats.columns:
        threats['likelihood'] = threats['confidence']
    else:
        threats['likelihood'] = np.random.uniform(0.5, 0.9, size=len(threats))
    
    # Calculate likelihood for vulnerabilities based on risk_score
    if 'risk_score' in vulnerabilities.columns:
        # Ensure risk_score is numeric
        vulnerabilities['risk_score'] = pd.to_numeric(vulnerabilities['risk_score'], errors='coerce').fillna(5.0)
        
        # Normalize risk_score to 0-1 range for likelihood
        max_risk = vulnerabilities['risk_score'].max()
        vulnerabilities['likelihood'] = vulnerabilities['risk_score'] / (max_risk if max_risk > 0 else 10)
    else:
        vulnerabilities['likelihood'] = np.random.uniform(0.4, 0.8, size=len(vulnerabilities))
    
    # Calculate risk scores
    threats['risk_score'] = threats.apply(lambda x: calculate_risk_score(x['severity'], x['likelihood']), axis=1)
    if 'risk_score' not in vulnerabilities.columns:
        vulnerabilities['risk_score'] = vulnerabilities.apply(lambda x: calculate_risk_score(x['severity'], x['likelihood']), axis=1)
    
    # Convert threats and vulnerabilities to risks
    threat_risks = threats[['id', 'name', 'category', 'severity', 'likelihood', 'risk_score']].copy()
    threat_risks['type'] = 'Threat'
    threat_risks['source'] = threats['source']
    threat_risks['description'] = threats['description']
    
    vuln_risks = vulnerabilities[['id', 'name', 'severity', 'likelihood', 'risk_score']].copy()
    vuln_risks['type'] = 'Vulnerability'
    vuln_risks['category'] = 'Vulnerability'
    vuln_risks['source'] = 'Vulnerability Scanner'
    vuln_risks['description'] = vulnerabilities['description']
    
    # Combine and sort risks by risk_score
    combined_risks = pd.concat([threat_risks, vuln_risks], ignore_index=True)
    combined_risks = combined_risks.sort_values('risk_score', ascending=False).reset_index(drop=True)
    
    return combined_risks

def get_compliance_status():
    """
    Generate compliance status for various frameworks.
    
    Returns:
        dict: Dictionary with compliance framework data
    """
    frameworks = [
        {
            'name': 'NIST Cybersecurity Framework',
            'categories': ['Identify', 'Protect', 'Detect', 'Respond', 'Recover'],
            'overall_compliance': 78,
            'last_assessment': (datetime.now() - timedelta(days=random.randint(10, 60))).strftime('%Y-%m-%d'),
            'critical_findings': random.randint(2, 8),
            'category_scores': {
                'Identify': random.randint(65, 90),
                'Protect': random.randint(70, 95),
                'Detect': random.randint(60, 85),
                'Respond': random.randint(75, 90),
                'Recover': random.randint(70, 85)
            }
        },
        {
            'name': 'ISO 27001',
            'categories': ['Security Policy', 'Organization of Information Security', 'Asset Management', 
                          'Human Resources Security', 'Physical Security', 'Communications Security',
                          'Access Control', 'Information Systems Security'],
            'overall_compliance': 82,
            'last_assessment': (datetime.now() - timedelta(days=random.randint(15, 90))).strftime('%Y-%m-%d'),
            'critical_findings': random.randint(1, 6),
            'category_scores': {
                'Security Policy': random.randint(75, 95),
                'Organization of Information Security': random.randint(70, 90),
                'Asset Management': random.randint(65, 85),
                'Human Resources Security': random.randint(70, 90),
                'Physical Security': random.randint(80, 95),
                'Communications Security': random.randint(75, 90),
                'Access Control': random.randint(70, 90),
                'Information Systems Security': random.randint(65, 85)
            }
        },
        {
            'name': 'GDPR',
            'categories': ['Lawfulness and Transparency', 'Purpose Limitation', 'Data Minimization', 
                          'Accuracy', 'Storage Limitation', 'Integrity and Confidentiality',
                          'Accountability', 'Data Subject Rights'],
            'overall_compliance': 85,
            'last_assessment': (datetime.now() - timedelta(days=random.randint(20, 100))).strftime('%Y-%m-%d'),
            'critical_findings': random.randint(0, 5),
            'category_scores': {
                'Lawfulness and Transparency': random.randint(80, 95),
                'Purpose Limitation': random.randint(75, 90),
                'Data Minimization': random.randint(70, 90),
                'Accuracy': random.randint(75, 95),
                'Storage Limitation': random.randint(70, 85),
                'Integrity and Confidentiality': random.randint(80, 95),
                'Accountability': random.randint(75, 90),
                'Data Subject Rights': random.randint(80, 95)
            }
        },
        {
            'name': 'PCI DSS',
            'categories': ['Build and Maintain Secure Network', 'Protect Cardholder Data', 
                          'Vulnerability Management', 'Access Control', 
                          'Monitor and Test Networks', 'Information Security Policy'],
            'overall_compliance': 88,
            'last_assessment': (datetime.now() - timedelta(days=random.randint(30, 120))).strftime('%Y-%m-%d'),
            'critical_findings': random.randint(0, 4),
            'category_scores': {
                'Build and Maintain Secure Network': random.randint(80, 95),
                'Protect Cardholder Data': random.randint(85, 98),
                'Vulnerability Management': random.randint(75, 90),
                'Access Control': random.randint(80, 95),
                'Monitor and Test Networks': random.randint(70, 90),
                'Information Security Policy': random.randint(80, 95)
            }
        },
        {
            'name': 'HIPAA',
            'categories': ['Privacy Rule', 'Security Rule', 'Breach Notification Rule', 
                          'Risk Analysis', 'Physical Safeguards', 'Technical Safeguards'],
            'overall_compliance': 80,
            'last_assessment': (datetime.now() - timedelta(days=random.randint(25, 110))).strftime('%Y-%m-%d'),
            'critical_findings': random.randint(1, 7),
            'category_scores': {
                'Privacy Rule': random.randint(75, 90),
                'Security Rule': random.randint(70, 90),
                'Breach Notification Rule': random.randint(80, 95),
                'Risk Analysis': random.randint(70, 85),
                'Physical Safeguards': random.randint(75, 95),
                'Technical Safeguards': random.randint(70, 90)
            }
        }
    ]
    
    return frameworks

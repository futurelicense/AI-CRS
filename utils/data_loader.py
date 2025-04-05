import pandas as pd
import os
import json
from datetime import datetime, timedelta
import random

def load_sample_data(data_type):
    """
    Load sample data from CSV files.
    
    Args:
        data_type (str): The type of data to load ('threats', 'vulnerabilities', 'incidents')
        
    Returns:
        pd.DataFrame: DataFrame containing the requested data
    """
    try:
        # Define file paths for different data types
        file_paths = {
            'threats': 'data/sample_threats.csv',
            'vulnerabilities': 'data/sample_vulnerabilities.csv',
            'incidents': 'data/sample_incidents.csv'
        }
        
        # Check if file exists and load it
        if data_type in file_paths and os.path.exists(file_paths[data_type]):
            # Load CSV with proper settings to avoid parsing issues
            if data_type == 'incidents':
                # Use more robust CSV parsing settings for incidents data
                return pd.read_csv(file_paths[data_type], escapechar='\\', quotechar='"', on_bad_lines='skip')
            else:
                df = pd.read_csv(file_paths[data_type])
                
                # Convert risk_score to numeric for vulnerabilities
                if data_type == 'vulnerabilities' and 'risk_score' in df.columns:
                    df['risk_score'] = pd.to_numeric(df['risk_score'], errors='coerce')
                
                # Convert confidence to numeric for threats
                if data_type == 'threats' and 'confidence' in df.columns:
                    df['confidence'] = pd.to_numeric(df['confidence'], errors='coerce')
                    
                return df
        else:
            # If file doesn't exist, create sample data
            if data_type == 'threats':
                return create_sample_threat_data()
            elif data_type == 'vulnerabilities':
                return create_sample_vulnerability_data()
            elif data_type == 'incidents':
                return create_sample_incident_data()
            else:
                raise ValueError(f"Unknown data type: {data_type}")
                
    except Exception as e:
        print(f"Error loading {data_type} data: {str(e)}")
        # Return empty DataFrame with appropriate columns
        if data_type == 'threats':
            return pd.DataFrame(columns=['id', 'name', 'category', 'severity', 'source', 'timestamp', 'description', 'confidence', 'status'])
        elif data_type == 'vulnerabilities':
            return pd.DataFrame(columns=['id', 'name', 'cve_id', 'severity', 'risk_score', 'affected_systems', 'description', 'remediation'])
        elif data_type == 'incidents':
            return pd.DataFrame(columns=['id', 'timestamp', 'type', 'severity', 'source_ip', 'target', 'description', 'status'])
        else:
            return pd.DataFrame()

def create_sample_threat_data():
    """Create structured sample threat data"""
    threat_categories = ['Malware', 'Ransomware', 'Phishing', 'DDoS', 'Data Breach', 'Insider Threat', 'APT']
    severity_levels = ['Critical', 'High', 'Medium', 'Low']
    sources = ['OSINT', 'Threat Intelligence', 'IDS/IPS', 'SIEM', 'Endpoint Protection']
    statuses = ['Active', 'Mitigated', 'Investigating', 'False Positive']
    
    threats = []
    # Generate 50 sample threats
    for i in range(1, 51):
        timestamp = (datetime.now() - timedelta(days=random.randint(0, 30), 
                                               hours=random.randint(0, 23), 
                                               minutes=random.randint(0, 59))).strftime('%Y-%m-%d %H:%M:%S')
        
        category = random.choice(threat_categories)
        severity = random.choice(severity_levels)
        confidence = round(random.uniform(0.5, 0.99), 2)
        
        # Create more descriptive names based on category
        name_prefixes = {
            'Malware': ['Trojan', 'Worm', 'Spyware', 'Adware'],
            'Ransomware': ['Crypto', 'Locker', 'Wiper', 'Encoder'],
            'Phishing': ['Email', 'SMS', 'Voice', 'Website'],
            'DDoS': ['Volumetric', 'Protocol', 'Application', 'Amplification'],
            'Data Breach': ['Database', 'Cloud', 'Storage', 'Credentials'],
            'Insider Threat': ['Employee', 'Contractor', 'Privileged', 'Account'],
            'APT': ['Nation-state', 'Sophisticated', 'Targeted', 'Persistent']
        }
        
        name_prefix = random.choice(name_prefixes.get(category, ['Generic']))
        name_suffix = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(random.randint(3, 5)))
        name = f"{name_prefix} {category} {name_suffix}"
        
        # Create more descriptive threat descriptions
        descriptions = {
            'Malware': f"Detected {name_prefix.lower()} malware attempting to establish C2 communication.",
            'Ransomware': f"Potential {name_prefix.lower()} ransomware activity detected with file encryption attempts.",
            'Phishing': f"{name_prefix} phishing campaign targeting corporate credentials.",
            'DDoS': f"{name_prefix} DDoS attack targeting web services.",
            'Data Breach': f"Potential data exfiltration from {name_prefix.lower()} systems.",
            'Insider Threat': f"Suspicious activity from {name_prefix.lower()} account with elevated privileges.",
            'APT': f"{name_prefix} advanced persistent threat with evidence of lateral movement."
        }
        
        description = descriptions.get(category, f"Potential {category.lower()} threat detected.")
        
        threats.append({
            'id': i,
            'name': name,
            'category': category,
            'severity': severity,
            'source': random.choice(sources),
            'timestamp': timestamp,
            'description': description,
            'confidence': confidence,
            'status': random.choice(statuses)
        })
    
    return pd.DataFrame(threats)

def create_sample_vulnerability_data():
    """Create structured sample vulnerability data"""
    severity_levels = ['Critical', 'High', 'Medium', 'Low']
    systems = ['Web Server', 'Database', 'Authentication System', 'API Gateway', 
              'Load Balancer', 'Firewall', 'Employee Workstations', 'Payment Processing',
              'Customer Portal', 'Email Server', 'File Storage', 'DNS Server']
    
    vulnerabilities = []
    # Generate 40 sample vulnerabilities
    for i in range(1, 41):
        severity = random.choice(severity_levels)
        # Risk score based on severity
        risk_score_ranges = {
            'Critical': (8.0, 10.0),
            'High': (6.0, 7.9),
            'Medium': (4.0, 5.9),
            'Low': (1.0, 3.9)
        }
        risk_score = round(random.uniform(*risk_score_ranges[severity]), 1)
        
        # Generate a CVE ID
        year = random.randint(2018, 2023)
        cve_number = random.randint(1000, 99999)
        cve_id = f"CVE-{year}-{cve_number}"
        
        # Create vulnerability names and descriptions based on common cybersecurity issues
        vuln_types = [
            {
                'name': 'SQL Injection',
                'description': 'Application fails to properly sanitize user inputs, allowing SQL injection attacks.',
                'remediation': 'Implement proper input validation and parameterized queries.'
            },
            {
                'name': 'Cross-Site Scripting (XSS)',
                'description': 'Web application allows injection of malicious scripts that execute in users\' browsers.',
                'remediation': 'Implement content security policy and proper output encoding.'
            },
            {
                'name': 'Broken Authentication',
                'description': 'Authentication mechanisms are improperly implemented, allowing credential stuffing.',
                'remediation': 'Implement multi-factor authentication and account lockout policies.'
            },
            {
                'name': 'Sensitive Data Exposure',
                'description': 'Application transmits or stores sensitive data without proper encryption.',
                'remediation': 'Implement encryption for data at rest and in transit.'
            },
            {
                'name': 'Outdated Software',
                'description': f'System is running an outdated version with known security vulnerabilities.',
                'remediation': 'Update to the latest version and implement regular patching.'
            },
            {
                'name': 'Improper Access Control',
                'description': 'Application fails to restrict access to authorized users only.',
                'remediation': 'Implement proper authorization checks and principle of least privilege.'
            },
            {
                'name': 'Security Misconfiguration',
                'description': 'System has improper security configuration exposing sensitive information.',
                'remediation': 'Follow secure configuration guidelines and conduct regular audits.'
            },
            {
                'name': 'Insecure Deserialization',
                'description': 'Application deserializes data from untrusted sources without verification.',
                'remediation': 'Implement integrity checks and avoid deserialization of untrusted data.'
            }
        ]
        
        vuln_type = random.choice(vuln_types)
        name = vuln_type['name']
        affected_system = random.choice(systems)
        
        description = f"{vuln_type['description']} Affects {affected_system}."
        remediation = vuln_type['remediation']
        
        vulnerabilities.append({
            'id': i,
            'name': name,
            'cve_id': cve_id,
            'severity': severity,
            'risk_score': risk_score,
            'affected_systems': affected_system,
            'description': description,
            'remediation': remediation
        })
    
    return pd.DataFrame(vulnerabilities)

def create_sample_incident_data():
    """Create structured sample incident data"""
    incident_types = ['Malware Infection', 'Unauthorized Access', 'Data Leak', 'Phishing', 'DDoS Attack', 
                      'Ransomware', 'Insider Threat', 'Credential Compromise', 'Web Attack', 'Physical Breach']
    severity_levels = ['Critical', 'High', 'Medium', 'Low']
    statuses = ['Resolved', 'In Progress', 'Investigating', 'Contained', 'Unresolved']
    targets = ['Web Server', 'Database', 'Employee Workstation', 'Email System', 'Customer Portal', 
               'Payment System', 'Active Directory', 'Network Infrastructure', 'Cloud Storage', 'Mobile Device']
    
    incidents = []
    # Generate 30 sample incidents
    for i in range(1, 31):
        incident_type = random.choice(incident_types)
        severity = random.choice(severity_levels)
        target = random.choice(targets)
        
        # Generate a random timestamp within the last 60 days
        days_ago = random.randint(0, 60)
        timestamp = (datetime.now() - timedelta(days=days_ago, 
                                               hours=random.randint(0, 23), 
                                               minutes=random.randint(0, 59))).strftime('%Y-%m-%d %H:%M:%S')
        
        # Generate a random IP address
        source_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        # Create more detailed descriptions based on incident type
        descriptions = {
            'Malware Infection': f"Malware detected on {target}. Antivirus quarantined the threat but further investigation needed.",
            'Unauthorized Access': f"Unauthorized login detected to {target} from unusual location.",
            'Data Leak': f"Sensitive data from {target} potentially exposed to unauthorized parties.",
            'Phishing': f"User reported phishing email that attempted to harvest credentials for {target}.",
            'DDoS Attack': f"Distributed denial of service attack targeting {target}, causing service disruption.",
            'Ransomware': f"Ransomware infection detected on {target}. Systems encrypted and ransom note found.",
            'Insider Threat': f"Suspicious activity detected from privileged user on {target}.",
            'Credential Compromise': f"Multiple failed login attempts followed by successful login to {target}.",
            'Web Attack': f"Web application firewall detected and blocked attack attempt on {target}.",
            'Physical Breach': f"Unauthorized physical access to facility housing {target}."
        }
        
        description = descriptions.get(incident_type, f"Security incident affecting {target}.")
        
        # Status more likely to be resolved for older incidents
        if days_ago > 30:
            status = random.choices(statuses, weights=[0.7, 0.1, 0.1, 0.05, 0.05])[0]
        elif days_ago > 15:
            status = random.choices(statuses, weights=[0.5, 0.2, 0.1, 0.15, 0.05])[0]
        else:
            status = random.choices(statuses, weights=[0.3, 0.3, 0.2, 0.15, 0.05])[0]
        
        incidents.append({
            'id': i,
            'timestamp': timestamp,
            'type': incident_type,
            'severity': severity,
            'source_ip': source_ip,
            'target': target,
            'description': description,
            'status': status
        })
    
    # Sort by timestamp, most recent first
    incidents_df = pd.DataFrame(incidents)
    incidents_df['timestamp'] = pd.to_datetime(incidents_df['timestamp'])
    return incidents_df.sort_values('timestamp', ascending=False).reset_index(drop=True)

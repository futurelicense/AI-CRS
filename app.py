import streamlit as st
import os
import pandas as pd
from utils.data_loader import load_sample_data
from utils.visualization import plot_threat_overview

# Configure the app
st.set_page_config(
    page_title="AI-Powered Cyber Risk Assessment System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Function to load uploaded CSV data
def process_uploaded_data(uploaded_file, data_type):
    try:
        # Read the uploaded CSV file
        df = pd.read_csv(uploaded_file)
        
        # Basic validation based on data type
        if data_type == 'threats':
            required_columns = ['id', 'name', 'category', 'severity', 'source', 'timestamp', 'description', 'confidence', 'status']
        elif data_type == 'vulnerabilities':
            required_columns = ['id', 'name', 'cve_id', 'severity', 'risk_score', 'affected_systems', 'description', 'remediation']
        elif data_type == 'incidents':
            required_columns = ['id', 'timestamp', 'type', 'severity', 'source_ip', 'target', 'description', 'status']
        else:
            return None, f"Unknown data type: {data_type}"
        
        # Check if required columns exist
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return None, f"Missing required columns: {', '.join(missing_columns)}"
            
        # If it's vulnerability data, ensure risk_score is numeric
        if data_type == 'vulnerabilities' and 'risk_score' in df.columns:
            df['risk_score'] = pd.to_numeric(df['risk_score'], errors='coerce')
            
        return df, None
    except Exception as e:
        return None, f"Error processing uploaded file: {str(e)}"

# Initialize session state variables if they don't exist
if 'threat_data' not in st.session_state:
    st.session_state.threat_data = load_sample_data('threats')
if 'vulnerability_data' not in st.session_state:
    st.session_state.vulnerability_data = load_sample_data('vulnerabilities')
if 'incident_data' not in st.session_state:
    st.session_state.incident_data = load_sample_data('incidents')

# Main application header
st.title("🛡️ AI-Powered Cyber Risk Assessment System")

# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio(
    "Select a page",
    ["Dashboard", "Data Management", "Threat Analysis", "Vulnerability Scanner", "Risk Prioritization", "Compliance Status"]
)

# Main content based on page selection
if page == "Dashboard":
    st.header("Cybersecurity Risk Dashboard")
    
    # Dashboard metrics row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="Active Threats", value=len(st.session_state.threat_data), delta="5%")
    with col2:
        st.metric(label="Critical Vulnerabilities", value=sum(st.session_state.vulnerability_data['severity'] == 'Critical'), delta="-2%")
    with col3:
        st.metric(label="Overall Risk Score", value="76/100", delta="-4%")
    with col4:
        st.metric(label="Compliance Rate", value="82%", delta="3%")
    
    # Overview section
    st.subheader("Threat Overview")
    st.plotly_chart(plot_threat_overview(st.session_state.threat_data), use_container_width=True)
    
    # Split the dashboard into two columns for additional visualizations
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Recent Incidents")
        recent_incidents = st.session_state.incident_data.head(5)
        st.dataframe(recent_incidents[['timestamp', 'type', 'severity', 'status']], use_container_width=True)
    
    with col2:
        st.subheader("Top Vulnerabilities")
        top_vulnerabilities = st.session_state.vulnerability_data.sort_values('risk_score', ascending=False).head(5)
        st.dataframe(top_vulnerabilities[['name', 'severity', 'risk_score', 'affected_systems']], use_container_width=True)

elif page == "Data Management":
    st.header("Data Management")
    st.info("Upload your own CSV data files or use sample data provided by the system.")
    
    # Create tabs for different data types
    data_tabs = st.tabs(["Threats", "Vulnerabilities", "Incidents"])
    
    with data_tabs[0]:  # Threats tab
        st.subheader("Threat Data")
        
        # Show current data summary
        st.write(f"Current dataset: {len(st.session_state.threat_data)} records")
        
        # File uploader for threat data
        uploaded_threat_file = st.file_uploader("Upload Threat Data CSV", type=["csv"], key="threat_uploader")
        
        col1, col2 = st.columns([1, 1])
        with col1:
            if st.button("Process Uploaded Threat Data", key="process_threat"):
                if uploaded_threat_file is not None:
                    with st.spinner("Processing uploaded threat data..."):
                        df, error = process_uploaded_data(uploaded_threat_file, 'threats')
                        if error:
                            st.error(error)
                        else:
                            st.session_state.threat_data = df
                            st.success(f"Successfully loaded {len(df)} threat records!")
                            st.rerun()
                else:
                    st.warning("Please upload a CSV file first.")
                    
        with col2:
            if st.button("Reset to Sample Data", key="reset_threat"):
                st.session_state.threat_data = load_sample_data('threats')
                st.success("Reset to sample threat data!")
                st.rerun()
                
        # Show data preview
        st.subheader("Data Preview")
        st.dataframe(st.session_state.threat_data.head(5), use_container_width=True)
        
        # Download template
        with open("data/sample_threats.csv", "rb") as file:
            st.download_button(
                label="Download Template CSV",
                data=file,
                file_name="threat_template.csv",
                mime="text/csv"
            )
    
    with data_tabs[1]:  # Vulnerabilities tab
        st.subheader("Vulnerability Data")
        
        # Show current data summary
        st.write(f"Current dataset: {len(st.session_state.vulnerability_data)} records")
        
        # File uploader for vulnerability data
        uploaded_vuln_file = st.file_uploader("Upload Vulnerability Data CSV", type=["csv"], key="vuln_uploader")
        
        col1, col2 = st.columns([1, 1])
        with col1:
            if st.button("Process Uploaded Vulnerability Data", key="process_vuln"):
                if uploaded_vuln_file is not None:
                    with st.spinner("Processing uploaded vulnerability data..."):
                        df, error = process_uploaded_data(uploaded_vuln_file, 'vulnerabilities')
                        if error:
                            st.error(error)
                        else:
                            st.session_state.vulnerability_data = df
                            st.success(f"Successfully loaded {len(df)} vulnerability records!")
                            st.rerun()
                else:
                    st.warning("Please upload a CSV file first.")
                    
        with col2:
            if st.button("Reset to Sample Data", key="reset_vuln"):
                st.session_state.vulnerability_data = load_sample_data('vulnerabilities')
                st.success("Reset to sample vulnerability data!")
                st.rerun()
                
        # Show data preview
        st.subheader("Data Preview")
        st.dataframe(st.session_state.vulnerability_data.head(5), use_container_width=True)
        
        # Download template
        with open("data/sample_vulnerabilities.csv", "rb") as file:
            st.download_button(
                label="Download Template CSV",
                data=file,
                file_name="vulnerability_template.csv",
                mime="text/csv"
            )
    
    with data_tabs[2]:  # Incidents tab
        st.subheader("Incident Data")
        
        # Show current data summary
        st.write(f"Current dataset: {len(st.session_state.incident_data)} records")
        
        # File uploader for incident data
        uploaded_incident_file = st.file_uploader("Upload Incident Data CSV", type=["csv"], key="incident_uploader")
        
        col1, col2 = st.columns([1, 1])
        with col1:
            if st.button("Process Uploaded Incident Data", key="process_incident"):
                if uploaded_incident_file is not None:
                    with st.spinner("Processing uploaded incident data..."):
                        df, error = process_uploaded_data(uploaded_incident_file, 'incidents')
                        if error:
                            st.error(error)
                        else:
                            st.session_state.incident_data = df
                            st.success(f"Successfully loaded {len(df)} incident records!")
                            st.rerun()
                else:
                    st.warning("Please upload a CSV file first.")
                    
        with col2:
            if st.button("Reset to Sample Data", key="reset_incident"):
                st.session_state.incident_data = load_sample_data('incidents')
                st.success("Reset to sample incident data!")
                st.rerun()
                
        # Show data preview
        st.subheader("Data Preview")
        st.dataframe(st.session_state.incident_data.head(5), use_container_width=True)
        
        # Download template
        with open("data/sample_incidents.csv", "rb") as file:
            st.download_button(
                label="Download Template CSV",
                data=file,
                file_name="incident_template.csv",
                mime="text/csv"
            )

elif page == "Threat Analysis":
    st.header("Threat Analysis")
    st.info("This page provides detailed analysis of detected threats, including AI-powered classification and recommendations.")
    
    # Import the threat analysis page content
    from pages.threat_analysis import show_threat_analysis
    show_threat_analysis()

elif page == "Vulnerability Scanner":
    st.header("Vulnerability Scanner")
    st.info("This page displays vulnerability scanning results with severity levels and recommended mitigations.")
    
    # Import the vulnerability scanner page content
    from pages.vulnerability_scanner import show_vulnerability_scanner
    show_vulnerability_scanner()

elif page == "Risk Prioritization":
    st.header("Risk Prioritization")
    st.info("This page shows prioritized risks based on severity, impact, and likelihood.")
    
    # Import the risk prioritization page content
    from pages.risk_prioritization import show_risk_prioritization
    show_risk_prioritization()

elif page == "Compliance Status":
    st.header("Compliance Status")
    st.info("This page shows compliance status against various cybersecurity frameworks and regulations.")
    
    # Import the compliance status page content
    from pages.compliance import show_compliance_status
    show_compliance_status()
    
elif page == "API Settings":
    st.header("API Integration Settings")
    st.info("Configure connections to external APIs for enhanced threat intelligence and analysis capabilities.")
    
    # Import the API settings page content
    from pages.api_settings import show_api_settings
    show_api_settings()

# Footer
st.markdown("---")
st.markdown(
    """
    <div style="text-align: center;">
        <p>AI-Powered Cyber Risk Assessment System | v1.0</p>
    </div>
    """,
    unsafe_allow_html=True
)

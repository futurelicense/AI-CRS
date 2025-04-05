import streamlit as st
import os
from utils.data_loader import load_sample_data
from utils.visualization import plot_threat_overview

# Configure the app
st.set_page_config(
    page_title="AI-Powered Cyber Risk Assessment System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

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
    ["Dashboard", "Threat Analysis", "Vulnerability Scanner", "Risk Prioritization", "Compliance Status"]
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

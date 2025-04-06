import streamlit as st
import os

def show_api_settings():
    """Display and manage API settings page content"""
    
    st.title("API Integration Settings")
    st.markdown("""
    Connect your AI-Powered Cyber Risk Assessment System with external API services 
    to enhance threat analysis capabilities.
    """)
    
    # Create tabs for different API integrations
    tab1, tab2, tab3 = st.tabs(["Hugging Face", "Threat Intelligence", "Vulnerability Scanner"])
    
    # Hugging Face API settings
    with tab1:
        st.header("Hugging Face API Integration")
        st.markdown("""
        [Hugging Face](https://huggingface.co) provides state-of-the-art NLP models for advanced threat classification and analysis.
        
        Setting up the Hugging Face API integration will enable:
        - Advanced threat classification with zero-shot learning
        - Enhanced threat context understanding
        - More accurate threat severity assessment
        - Better pattern recognition for new threat types
        """)
        
        # Check for existing key
        huggingface_api_key = os.getenv('HUGGINGFACE_API_KEY')
        
        if huggingface_api_key:
            st.success("✅ Hugging Face API is currently connected.")
            
            # Option to reset the key
            if st.button("Reset Hugging Face API Key"):
                os.environ['HUGGINGFACE_API_KEY'] = ""
                st.warning("Hugging Face API key has been reset. You'll need to enter a new key.")
                st.rerun()
        else:
            st.warning("⚠️ Hugging Face API key is not configured.")
            
            st.markdown("""
            ### How to get a Hugging Face API Key:
            
            1. Create a free account at [Hugging Face](https://huggingface.co/join)
            2. Go to your profile settings
            3. Navigate to the "Access Tokens" section
            4. Create a new token with "read" access
            5. Copy the token and paste it below
            """)
            
            # Input for API key
            new_api_key = st.text_input("Enter Hugging Face API Key", type="password", key="hf_api_key_input")
            
            # Test connection
            col1, col2 = st.columns([1, 2])
            with col1:
                if st.button("Save API Key") and new_api_key:
                    os.environ['HUGGINGFACE_API_KEY'] = new_api_key
                    st.success("API Key saved for this session!")
                    st.rerun()
            
            with col2:
                if st.button("Test Connection") and new_api_key:
                    with st.spinner("Testing connection to Hugging Face API..."):
                        try:
                            import requests
                            
                            # Test with a lightweight model
                            API_URL = "https://api-inference.huggingface.co/models/distilbert-base-uncased"
                            headers = {"Authorization": f"Bearer {new_api_key}"}
                            response = requests.post(API_URL, headers=headers, json={"inputs": "Testing connection"})
                            
                            if response.status_code == 200:
                                st.success("✅ Successfully connected to Hugging Face API!")
                            else:
                                st.error(f"❌ Connection failed. Status code: {response.status_code}")
                                st.code(response.text)
                        except Exception as e:
                            st.error(f"❌ Error connecting to Hugging Face API: {str(e)}")
    
    # Threat Intelligence API settings
    with tab2:
        st.header("Threat Intelligence API Integration")
        st.markdown("""
        Connect to external threat intelligence platforms for real-time threat data feeds.
        
        **Coming Soon:** Integration with:
        - IBM X-Force
        - VirusTotal
        - AlienVault OTX
        - Mandiant
        - CrowdStrike Intelligence
        """)
        
        st.info("This integration is under development and will be available in a future update.")
    
    # Vulnerability Scanner API settings
    with tab3:
        st.header("Vulnerability Scanner API Integration")
        st.markdown("""
        Connect to vulnerability scanning platforms for automated security assessments.
        
        **Coming Soon:** Integration with:
        - Tenable.io
        - Qualys
        - OpenVAS
        - Rapid7 InsightVM
        - Nessus
        """)
        
        st.info("This integration is under development and will be available in a future update.")
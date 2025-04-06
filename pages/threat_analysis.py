import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np
from datetime import datetime, timedelta
import time

from utils.threat_intelligence import fetch_hugging_face_analysis, get_threat_intelligence, get_mitigation_recommendations
from utils.visualization import plot_threat_overview
from utils.ml_models import classify_threat, predict_future_threats

def show_threat_analysis():
    """Display the threat analysis page content"""
    
    # Get data from session state
    threat_data = st.session_state.threat_data
    
    # Create tabs for different threat analysis views
    tab1, tab2, tab3, tab4 = st.tabs(["Threat Overview", "Threat Intelligence", "Threat Classification", "Predictive Analysis"])
    
    with tab1:
        st.subheader("Current Threat Landscape")
        
        # Filter options
        col1, col2 = st.columns([1, 2])
        with col1:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=["Critical", "High", "Medium", "Low"],
                default=["Critical", "High", "Medium", "Low"]
            )
        
        with col2:
            category_filter = st.multiselect(
                "Filter by Category",
                options=sorted(threat_data["category"].unique()),
                default=sorted(threat_data["category"].unique())
            )
        
        # Apply filters
        filtered_threats = threat_data[
            (threat_data["severity"].isin(severity_filter)) & 
            (threat_data["category"].isin(category_filter))
        ]
        
        # Display filtered threats visualization
        if not filtered_threats.empty:
            st.plotly_chart(plot_threat_overview(filtered_threats), use_container_width=True)
            
            # Display threat data in a table with expanders for details
            st.subheader("Threat Details")
            for _, threat in filtered_threats.iterrows():
                with st.expander(f"{threat['name']} ({threat['severity']})"):
                    col1, col2 = st.columns([1, 2])
                    with col1:
                        st.markdown(f"**Category:** {threat['category']}")
                        st.markdown(f"**Severity:** {threat['severity']}")
                        st.markdown(f"**Source:** {threat['source']}")
                        st.markdown(f"**Confidence:** {threat['confidence']}")
                        st.markdown(f"**Status:** {threat['status']}")
                    with col2:
                        st.markdown(f"**Description:**")
                        st.write(threat['description'])
                        st.markdown(f"**Detected:** {threat['timestamp']}")
        else:
            st.warning("No threats match the selected filters.")
    
    with tab2:
        st.subheader("Threat Intelligence")
        
        # Get threat intelligence data
        threat_type = st.selectbox(
            "Select Threat Type",
            ["All"] + sorted(threat_data["category"].unique())
        )
        
        intel_data = get_threat_intelligence(threat_type if threat_type != "All" else None)
        
        if not intel_data.empty:
            # Display threat intelligence in a table
            st.dataframe(
                intel_data[['name', 'type', 'threat_level', 'last_seen']],
                use_container_width=True
            )
            
            # Show detailed intelligence for selected threat
            selected_intel = st.selectbox(
                "Select Threat for Detailed Intelligence",
                intel_data['name']
            )
            
            if selected_intel:
                intel = intel_data[intel_data['name'] == selected_intel].iloc[0]
                
                st.markdown(f"### {intel['name']}")
                st.markdown(f"**Type:** {intel['type']}")
                st.markdown(f"**Threat Level:** {intel['threat_level']}")
                st.markdown(f"**Last Seen:** {intel['last_seen']}")
                
                st.markdown("#### Description")
                st.write(intel['description'])
                
                st.markdown("#### Indicators of Compromise (IoCs)")
                iocs = intel['indicators'].split(',')
                for ioc in iocs:
                    st.code(ioc.strip())
                
                st.markdown("#### Recommended Mitigations")
                recommendations = intel['recommendations'].split('.')
                for rec in recommendations:
                    if rec.strip():
                        st.markdown(f"- {rec.strip()}")
        else:
            st.warning("No threat intelligence data available for the selected type.")
    
    with tab3:
        st.subheader("AI-Powered Threat Classification")
        
        # Check for Hugging Face API Key
        import os
        huggingface_api_key = os.getenv('HUGGINGFACE_API_KEY')
        
        if not huggingface_api_key:
            st.warning("""
            ⚠️ Hugging Face API key not found. Advanced AI models will not be available.
            
            For enhanced threat analysis capabilities, please provide your Hugging Face API key.
            You can get a free API key at [huggingface.co](https://huggingface.co/join).
            
            Once obtained, add it as an environment variable named `HUGGINGFACE_API_KEY`.
            """)
            
            # Provide a secret input for the API key
            new_api_key = st.text_input("Enter Hugging Face API Key", type="password", key="hf_api_key_input")
            
            if new_api_key and st.button("Save API Key"):
                # Store in session state (note: this is temporary for the session)
                os.environ['HUGGINGFACE_API_KEY'] = new_api_key
                st.success("API Key saved for this session! Advanced AI models are now available.")
                st.rerun()
        else:
            st.success("✅ Hugging Face API is connected. Advanced AI models are available for threat classification.")
        
        # Model selection
        model_options = {
            "facebook/bart-large-mnli": "Zero-shot classification (best for new threat types)",
            "deepset/roberta-base-squad2": "Question-answering model (best for detailed analysis)",
            "distilbert-base-uncased-finetuned-sst-2-english": "Sentiment analysis model (best for threat severity)"
        }
        
        selected_model = st.selectbox(
            "Select AI Model",
            options=list(model_options.keys()),
            format_func=lambda x: f"{x} - {model_options[x]}"
        )
        
        # Text input for threat description
        threat_description = st.text_area(
            "Enter threat description or indicator for classification",
            height=100,
            placeholder="Example: Multiple failed login attempts followed by successful authentication from foreign IP address"
        )
        
        col1, col2 = st.columns([1, 3])
        
        with col1:
            if st.button("Classify Threat"):
                if threat_description:
                    with st.spinner("Analyzing threat using AI models..."):
                        # Get Hugging Face analysis with the selected model
                        hugging_face_result = fetch_hugging_face_analysis(threat_description, model_name=selected_model)
                        
                        # Get classifier result which will use Hugging Face if available
                        classifier_result = classify_threat(threat_description)
                        
                        # Store results in session state
                        st.session_state.hugging_face_result = hugging_face_result
                        st.session_state.classifier_result = classifier_result
                        
                        # Determine final classification (prefer Hugging Face if available)
                        if hugging_face_result.get('classification'):
                            final_category = hugging_face_result['classification']
                            final_confidence = hugging_face_result['confidence']
                            final_model = hugging_face_result.get('model', selected_model)
                        else:
                            final_category = classifier_result['category']
                            final_confidence = classifier_result['confidence']
                            final_model = classifier_result.get('model', 'keyword_based_classification')
                        
                        st.session_state.final_category = final_category
                        st.session_state.final_confidence = final_confidence
                        st.session_state.final_model = final_model
                else:
                    st.error("Please enter a threat description for analysis.")
        
        # Display classification results if available
        if 'final_category' in st.session_state:
            st.markdown("### Classification Results")
            
            # Layout with columns
            col1, col2 = st.columns([1, 1])
            
            with col1:
                # Show which model was used
                if 'final_model' in st.session_state:
                    model_name = st.session_state.final_model
                    st.info(f"Analysis performed using: **{model_name}**")
                
                # Display the classification with confidence
                st.markdown(f"**Primary Threat Classification:** {st.session_state.final_category}")
                st.progress(st.session_state.final_confidence)
                st.markdown(f"**Confidence Score:** {st.session_state.final_confidence:.2f}")
                
                # Display timestamp
                if 'hugging_face_result' in st.session_state:
                    st.markdown(f"**Analysis Timestamp:** {st.session_state.hugging_face_result.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
            
            with col2:
                # Show alternative classifications if available
                if 'classifier_result' in st.session_state:
                    classifier_result = st.session_state.classifier_result
                    
                    if 'alternative_categories' in classifier_result:
                        st.markdown("#### Alternative Classifications")
                        st.caption("AI model's secondary classification possibilities")
                        
                        alt_categories = classifier_result['alternative_categories']
                        for alt in alt_categories:
                            cat = alt['category']
                            score = alt['score']
                            
                            # Display each alternative with a smaller progress bar
                            st.markdown(f"**{cat}**")
                            st.progress(score)
                            st.caption(f"Score: {score:.2f}")
                    
                    # Show matched keywords if available
                    if 'matched_keywords' in classifier_result:
                        st.markdown("#### Key Indicators Detected")
                        keywords = classifier_result['matched_keywords']
                        st.write(", ".join([f"`{kw}`" for kw in keywords]))
            
            # Show raw response if available (for debugging)
            if huggingface_api_key and 'hugging_face_result' in st.session_state and 'raw_response' in st.session_state.hugging_face_result:
                with st.expander("View Raw AI Model Response"):
                    st.json(st.session_state.hugging_face_result['raw_response'])
            
            # Get and display mitigation recommendations
            if 'classifier_result' in st.session_state and 'recommendations' in st.session_state.classifier_result:
                recommendations = st.session_state.classifier_result['recommendations']
            else:
                recommendations = get_mitigation_recommendations(st.session_state.final_category)
            
            st.markdown("### AI-Generated Mitigation Recommendations")
            st.caption("Based on threat classification and context analysis")
            
            for idx, rec in enumerate(recommendations):
                st.markdown(f"- {rec}")
    
    with tab4:
        st.subheader("Predictive Threat Analysis")
        
        col1, col2 = st.columns([1, 2])
        
        with col1:
            prediction_days = st.slider(
                "Prediction timeframe (days)",
                min_value=7,
                max_value=90,
                value=30,
                step=7
            )
        
        with col2:
            prediction_categories = st.multiselect(
                "Focus on specific threat categories",
                options=sorted(threat_data["category"].unique()),
                default=None
            )
        
        if st.button("Generate Prediction"):
            with st.spinner("Analyzing historical data and generating prediction..."):
                # Generate predictions
                predictions = predict_future_threats(threat_data, days=prediction_days)
                
                # Filter by selected categories if any
                if prediction_categories:
                    predictions = predictions[predictions['category'].isin(prediction_categories)]
                
                # Store in session state
                st.session_state.threat_predictions = predictions
                
                # Convert date to datetime for plotting
                predictions['date'] = pd.to_datetime(predictions['date'])
        
        # Display prediction results if available
        if 'threat_predictions' in st.session_state:
            predictions = st.session_state.threat_predictions
            
            if not predictions.empty:
                # Create a line chart of predicted threats over time by category
                fig = px.line(
                    predictions.groupby(['date', 'category'])['predicted_count'].sum().reset_index(),
                    x='date',
                    y='predicted_count',
                    color='category',
                    title="Predicted Threat Trends",
                    labels={'date': 'Date', 'predicted_count': 'Predicted Number of Threats', 'category': 'Threat Category'}
                )
                
                fig.update_layout(
                    xaxis_title="Date",
                    yaxis_title="Predicted Threat Count",
                    legend_title="Threat Category",
                    height=400
                )
                
                st.plotly_chart(fig, use_container_width=True)
                
                # Create a pie chart of predicted threat distribution by severity
                severity_counts = predictions.groupby('severity')['predicted_count'].sum().reset_index()
                
                fig = px.pie(
                    severity_counts,
                    values='predicted_count',
                    names='severity',
                    title="Predicted Threat Distribution by Severity",
                    color='severity',
                    color_discrete_map={
                        'Critical': '#d7191c',
                        'High': '#fdae61',
                        'Medium': '#ffffbf',
                        'Low': '#abd9e9'
                    }
                )
                
                st.plotly_chart(fig, use_container_width=True)
                
                # Display the most likely threats in a table
                st.subheader("Highest Confidence Predictions")
                top_predictions = predictions.sort_values('confidence', ascending=False).head(10)
                st.dataframe(
                    top_predictions[['date', 'category', 'severity', 'confidence', 'predicted_count']],
                    use_container_width=True
                )
            else:
                st.warning("No prediction data available for the selected categories.")

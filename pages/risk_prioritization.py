import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import numpy as np
import numbers

from utils.risk_assessment import prioritize_risks, calculate_risk_score
from utils.visualization import plot_risk_matrix
from utils.threat_intelligence import get_mitigation_recommendations

def show_risk_prioritization():
    """Display the risk prioritization page content"""
    
    # Get data from session state
    threat_data = st.session_state.threat_data
    vulnerability_data = st.session_state.vulnerability_data
    
    st.write("Vulnerability data shape:", vulnerability_data.shape)
    st.write(vulnerability_data.head())
    st.write("Unique severities:", vulnerability_data['severity'].unique())
    
    # Create tabs for different risk prioritization views
    tab1, tab2, tab3 = st.tabs(["Risk Matrix", "Top Risks", "Risk Treatment"])
    
    with tab1:
        st.subheader("Risk Prioritization Matrix")
        
        # Combine threats and vulnerabilities for prioritization
        combined_risks = prioritize_risks(threat_data, vulnerability_data)
        
        # Display risk matrix
        st.plotly_chart(plot_risk_matrix(combined_risks), use_container_width=True)
        
        # Display risk zone explanation
        st.info("""
        **Risk Matrix Zones:**
        - **High Risk (Red):** Immediate action required
        - **Medium-High Risk (Orange):** Action required soon
        - **Medium Risk (Yellow):** Action planning needed
        - **Low Risk (Blue):** Monitor and review periodically
        """)
        
        # Risk metrics summary
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            high_risks = len(combined_risks[combined_risks['risk_score'] >= 70])
            st.metric(
                label="High Risks",
                value=high_risks,
                delta="-2" if high_risks > 2 else "0",
                delta_color="inverse"
            )
            
        with col2:
            medium_risks = len(combined_risks[(combined_risks['risk_score'] < 70) & (combined_risks['risk_score'] >= 40)])
            st.metric(
                label="Medium Risks",
                value=medium_risks,
                delta="-5" if medium_risks > 5 else "0",
                delta_color="inverse"
            )
            
        with col3:
            low_risks = len(combined_risks[combined_risks['risk_score'] < 40])
            st.metric(
                label="Low Risks",
                value=low_risks,
                delta="0",
                delta_color="off"
            )
            
        with col4:
            avg_risk = round(combined_risks['risk_score'].mean(), 1)
            st.metric(
                label="Average Risk Score",
                value=avg_risk,
                delta="-2.5" if avg_risk > 50 else "0",
                delta_color="inverse"
            )
        
        # Clean severity column for the bar chart only
        severity_data = vulnerability_data.copy()
        severity_data['severity'] = severity_data['severity'].fillna('').astype(str).str.strip()
        valid_severities = ['Critical', 'High', 'Medium', 'Low']
        severity_data = severity_data[severity_data['severity'].isin(valid_severities)]
        
        # Distribution of vulnerabilities by severity
        severity_counts = severity_data['severity'].value_counts().reindex(valid_severities, fill_value=0).reset_index()
        severity_counts.columns = ['severity', 'count']
        severity_counts = severity_counts[severity_counts['count'] > 0]
        if not severity_counts.empty:
            fig = px.pie(
                severity_counts,
                values='count',
                names='severity',
                title="Risk Distribution by Severity",
                hover_data=['count'],
                labels={'count': 'Number of Risks'}
            )
            fig.update_traces(
                hovertemplate='<b>%{label}</b><br>Number of Risks: %{value}'
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("No valid vulnerability severity data to display.")
    
    with tab2:
        st.subheader("Top Prioritized Risks")
        
        # Calculate combined risks if not already done
        if 'combined_risks' not in locals():
            combined_risks = prioritize_risks(threat_data, vulnerability_data)
        
        # Filter options
        col1, col2 = st.columns(2)
        
        with col1:
            risk_type_filter = st.multiselect(
                "Filter by Risk Type",
                options=["Threat", "Vulnerability"],
                default=["Threat", "Vulnerability"]
            )
        
        with col2:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=["Critical", "High", "Medium", "Low"],
                default=["Critical", "High"]
            )
        
        # Apply filters
        filtered_risks = combined_risks[
            (combined_risks["type"].isin(risk_type_filter)) & 
            (combined_risks["severity"].isin(severity_filter))
        ]
        
        # Sort by risk score
        filtered_risks = filtered_risks.sort_values("risk_score", ascending=False)
        
        # Display top risks
        if not filtered_risks.empty:
            # Create visualization of top risks
            top_n = min(10, len(filtered_risks))
            top_risks = filtered_risks.head(top_n)
            
            fig = px.bar(
                top_risks,
                x="risk_score",
                y="name",
                color="type",
                title=f"Top {top_n} Risks by Risk Score",
                labels={"risk_score": "Risk Score", "name": "Risk Name", "type": "Risk Type"},
                orientation='h',
                color_discrete_map={"Threat": "#636EFA", "Vulnerability": "#EF553B"},
                height=500
            )
            
            fig.update_layout(
                yaxis=dict(autorange="reversed"),
                xaxis_title="Risk Score",
                yaxis_title="Risk Name"
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Display risk details in expandable sections
            st.subheader("Detailed Risk Information")
            for _, risk in filtered_risks.iterrows():
                with st.expander(f"{risk['name']} - Risk Score: {risk['risk_score']:.1f}"):
                    col1, col2 = st.columns([1, 2])
                    
                    with col1:
                        st.markdown(f"**Type:** {risk['type']}")
                        st.markdown(f"**Category:** {risk['category']}")
                        st.markdown(f"**Severity:** {risk['severity']}")
                        st.markdown(f"**Likelihood:** {risk['likelihood']:.2f}")
                        st.markdown(f"**Risk Score:** {risk['risk_score']:.1f}")
                        if 'source' in risk:
                            st.markdown(f"**Source:** {risk['source']}")
                    
                    with col2:
                        st.markdown("**Description:**")
                        st.write(risk['description'])
                        
                        # Show recommended mitigations
                        if risk['type'] == "Threat" and 'category' in risk:
                            st.markdown("**Recommended Mitigations:**")
                            recommendations = get_mitigation_recommendations(risk['category'])
                            for i, rec in enumerate(recommendations[:3]):  # Show top 3 recommendations
                                st.markdown(f"- {rec}")
        else:
            st.warning("No risks match the selected filters.")
        
        # Risk distribution by category
        if not filtered_risks.empty:
            st.subheader("Risk Distribution by Category")
            # Clean category column
            filtered_risks = filtered_risks.copy()
            filtered_risks['category'] = filtered_risks['category'].fillna('').astype(str).str.strip()
            filtered_risks = filtered_risks[filtered_risks['category'] != '']
            # Group by category and sum risk scores
            if not filtered_risks.empty:
                category_risks = filtered_risks.groupby('category')['risk_score'].agg(['mean', 'count']).reset_index()
                category_risks['total_risk'] = category_risks['mean'] * category_risks['count']
                category_risks = category_risks.sort_values('total_risk', ascending=False)
                if not category_risks.empty:
                    fig = px.pie(
                        category_risks,
                        values='total_risk',
                        names='category',
                        title="Risk Distribution by Category",
                        hover_data=['count', 'mean'],
                        labels={'total_risk': 'Total Risk Score', 'count': 'Number of Risks', 'mean': 'Average Risk Score'}
                    )
                    fig.update_traces(
                        hovertemplate='<b>%{label}</b><br>Total Risk: %{value:.1f}<br>Count: %{customdata[0]}<br>Avg Score: %{customdata[1]:.1f}'
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.warning("No valid risk categories to display.")
            else:
                st.warning("No valid risk categories to display.")
        else:
            st.warning("No valid risk categories to display.")
    
    with tab3:
        st.subheader("Risk Treatment Planning")
        
        # Calculate combined risks if not already done
        if 'combined_risks' not in locals():
            combined_risks = prioritize_risks(threat_data, vulnerability_data)
        
        # Create risk treatment options
        treatment_options = ["Accept", "Mitigate", "Transfer", "Avoid"]
        
        # Group risks by severity levels
        critical_risks = combined_risks[combined_risks['severity'] == 'Critical'].sort_values('risk_score', ascending=False)
        high_risks = combined_risks[combined_risks['severity'] == 'High'].sort_values('risk_score', ascending=False)
        medium_risks = combined_risks[combined_risks['severity'] == 'Medium'].sort_values('risk_score', ascending=False)
        low_risks = combined_risks[combined_risks['severity'] == 'Low'].sort_values('risk_score', ascending=False)
        
        # Display risk treatment status
        treatment_status = pd.DataFrame({
            'Risk Level': ['Critical', 'High', 'Medium', 'Low'],
            'Count': [len(critical_risks), len(high_risks), len(medium_risks), len(low_risks)],
            'Recommended Treatment': ['Mitigate/Avoid', 'Mitigate', 'Mitigate/Transfer', 'Accept/Monitor']
        })
        
        # Create horizontal bar chart of risk counts by level
        colors = ['#d7191c', '#fdae61', '#ffffbf', '#abd9e9']
        
        fig = px.bar(
            treatment_status,
            x='Count',
            y='Risk Level',
            color='Risk Level',
            text='Count',
            orientation='h',
            title="Risk Counts by Severity Level",
            color_discrete_map={
                'Critical': '#d7191c',
                'High': '#fdae61',
                'Medium': '#ffffbf',
                'Low': '#abd9e9'
            }
        )
        
        fig.update_layout(
            xaxis_title="Number of Risks",
            yaxis_title="Risk Level",
            showlegend=False,
            height=300
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Display treatment recommendations table
        st.dataframe(treatment_status[['Risk Level', 'Count', 'Recommended Treatment']], use_container_width=True)
        
        # Generate risk treatment timeline
        st.subheader("Risk Treatment Timeline")
        
        # Create sample treatment timeline data
        timeline_data = []
        # Add critical risks (immediate treatment)
        for i, risk in enumerate(critical_risks.head(min(3, len(critical_risks))).iterrows()):
            start = datetime.now() + timedelta(days=1)
            end = datetime.now() + timedelta(days=7 + i)
            timeline_data.append({
                'Risk': risk[1]['name'],
                'Severity': 'Critical',
                'Start': start,
                'End': end,
                'Treatment': 'Mitigate'
            })
        # Add high risks (short-term treatment)
        for i, risk in enumerate(high_risks.head(min(5, len(high_risks))).iterrows()):
            start = datetime.now() + timedelta(days=7)
            end = datetime.now() + timedelta(days=21 + i * 2)
            timeline_data.append({
                'Risk': risk[1]['name'],
                'Severity': 'High',
                'Start': start,
                'End': end,
                'Treatment': 'Mitigate'
            })
        # Add medium risks (medium-term treatment)
        for i, risk in enumerate(medium_risks.head(min(3, len(medium_risks))).iterrows()):
            start = datetime.now() + timedelta(days=14)
            end = datetime.now() + timedelta(days=30 + i * 3)
            timeline_data.append({
                'Risk': risk[1]['name'],
                'Severity': 'Medium',
                'Start': start,
                'End': end,
                'Treatment': str(np.random.choice(['Mitigate', 'Transfer']))
            })
        # Add low risks (longer-term treatment or acceptance)
        for i, risk in enumerate(low_risks.head(min(2, len(low_risks))).iterrows()):
            start = datetime.now() + timedelta(days=30)
            end = datetime.now() + timedelta(days=60 + i * 5)
            timeline_data.append({
                'Risk': risk[1]['name'],
                'Severity': 'Low',
                'Start': start,
                'End': end,
                'Treatment': 'Accept'
            })
        # Create timeline DataFrame
        if timeline_data:
            timeline_df = pd.DataFrame(timeline_data)
            timeline_df['Task'] = timeline_df['Risk'] + ' (' + timeline_df['Treatment'] + ')'
            # Final bulletproof timedelta removal for all columns
            for col in timeline_df.columns:
                # Convert any timedelta to string (or to a valid datetime if you want)
                timeline_df[col] = timeline_df[col].apply(
                    lambda x: (
                        (datetime.now() + x) if isinstance(x, timedelta) else
                        (pd.to_datetime(x) if isinstance(x, str) else x)
                    )
                )
                # If any are still timedelta, convert to string
                timeline_df[col] = timeline_df[col].apply(lambda x: str(x) if isinstance(x, timedelta) else x)

            # Drop any rows where Start or End is not a datetime
            timeline_df = timeline_df[
                timeline_df['Start'].apply(lambda x: isinstance(x, (pd.Timestamp, datetime))) &
                timeline_df['End'].apply(lambda x: isinstance(x, (pd.Timestamp, datetime)))
            ]
            # Create Gantt chart
            colors = {
                'Critical': '#d7191c',
                'High': '#fdae61',
                'Medium': '#ffffbf',
                'Low': '#abd9e9'
            }
            fig = px.timeline(
                timeline_df, 
                x_start='Start', 
                x_end='End', 
                y='Task',
                color='Severity',
                color_discrete_map=colors,
                title="Risk Treatment Timeline",
                labels={'Task': 'Risk (Treatment)', 'Start': 'Start Date', 'End': 'End Date'}
            )
            fig.update_layout(
                xaxis_title="Date",
                yaxis_title="Risk (Treatment)",
                height=400 + len(timeline_df) * 25  # Adjust height based on number of items
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("No risks available for timeline generation.")
        
        # Risk treatment selection for high-priority risks
        st.subheader("High-Priority Risk Treatment")
        
        high_priority = pd.concat([critical_risks, high_risks]).head(5)
        
        if not high_priority.empty:
            for i, (_, risk) in enumerate(high_priority.iterrows()):
                col1, col2, col3 = st.columns([3, 1, 1])
                
                with col1:
                    st.markdown(f"**{risk['name']}** ({risk['severity']}) - Score: {risk['risk_score']:.1f}")
                
                with col2:
                    treatment = st.selectbox(
                        "Treatment",
                        options=treatment_options,
                        index=1 if risk['severity'] in ['Critical', 'High'] else 0,
                        key=f"treatment_{i}"
                    )
                
                with col3:
                    priority = st.selectbox(
                        "Priority",
                        options=["Critical", "High", "Medium", "Low"],
                        index=0 if risk['severity'] == 'Critical' else 1,
                        key=f"priority_{i}"
                    )
                
                # Show recommended actions based on selected treatment
                if treatment == "Mitigate":
                    if risk['type'] == "Threat" and 'category' in risk:
                        recommendations = get_mitigation_recommendations(risk['category'])
                        with st.expander("Recommended Mitigation Actions"):
                            for rec in recommendations[:3]:
                                st.markdown(f"- {rec}")
                    else:
                        with st.expander("Recommended Mitigation Actions"):
                            st.markdown("- Implement security controls to reduce the likelihood or impact")
                            st.markdown("- Conduct regular testing and monitoring")
                            st.markdown("- Provide training and awareness programs")
                
                elif treatment == "Transfer":
                    with st.expander("Recommended Transfer Actions"):
                        st.markdown("- Evaluate cyber insurance options")
                        st.markdown("- Consider outsourcing to specialized security providers")
                        st.markdown("- Establish vendor risk management for shared responsibilities")
                
                elif treatment == "Avoid":
                    with st.expander("Recommended Avoidance Actions"):
                        st.markdown("- Discontinue high-risk activities or systems")
                        st.markdown("- Implement alternative approaches with lower risk")
                        st.markdown("- Redesign processes to eliminate the risk source")
                
                elif treatment == "Accept":
                    with st.expander("Recommended Acceptance Actions"):
                        st.markdown("- Document the decision to accept the risk")
                        st.markdown("- Establish monitoring to ensure risk remains acceptable")
                        st.markdown("- Define trigger points for reassessment")
                
                st.markdown("---")
        else:
            st.warning("No high-priority risks available for treatment planning.")

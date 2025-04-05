import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import random

from utils.risk_assessment import get_compliance_status
from utils.visualization import plot_compliance_radar

def show_compliance_status():
    """Display the compliance status page content"""
    
    # Get compliance frameworks data
    compliance_frameworks = get_compliance_status()
    
    # Create tabs for different compliance views
    tab1, tab2, tab3 = st.tabs(["Compliance Overview", "Framework Details", "Compliance Timeline"])
    
    with tab1:
        st.subheader("Compliance Status Overview")
        
        # Compliance summary metrics
        framework_names = [fw['name'] for fw in compliance_frameworks]
        framework_scores = [fw['overall_compliance'] for fw in compliance_frameworks]
        critical_findings = [fw['critical_findings'] for fw in compliance_frameworks]
        last_assessments = [fw['last_assessment'] for fw in compliance_frameworks]
        
        # Create a summary bar chart
        compliance_summary = pd.DataFrame({
            'Framework': framework_names,
            'Compliance Score': framework_scores,
            'Critical Findings': critical_findings,
            'Last Assessment': last_assessments
        })
        
        # Sort by compliance score
        compliance_summary = compliance_summary.sort_values('Compliance Score', ascending=True)
        
        # Define color gradient based on compliance scores
        colors = [
            '#d7191c' if score < 70 else 
            '#fdae61' if score < 80 else 
            '#ffffbf' if score < 90 else 
            '#a6d96a'
            for score in compliance_summary['Compliance Score']
        ]
        
        # Create horizontal bar chart
        fig = go.Figure()
        
        fig.add_trace(go.Bar(
            y=compliance_summary['Framework'],
            x=compliance_summary['Compliance Score'],
            orientation='h',
            marker_color=colors,
            text=compliance_summary['Compliance Score'].apply(lambda x: f"{x}%"),
            textposition='auto',
            name='Compliance Score'
        ))
        
        # Add target line at 80%
        fig.add_shape(
            type="line",
            x0=80, y0=-0.5,
            x1=80, y1=len(framework_names) - 0.5,
            line=dict(color="black", width=2, dash="dash")
        )
        
        fig.add_annotation(
            x=80, y=len(framework_names) - 0.5,
            text="Target: 80%",
            showarrow=False,
            yshift=10
        )
        
        # Update layout
        fig.update_layout(
            title="Compliance Scores by Framework",
            xaxis_title="Compliance Score (%)",
            yaxis_title="Framework",
            xaxis=dict(range=[0, 105]),
            height=400,
            margin=dict(l=200)
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Critical findings summary
        st.subheader("Critical Findings Summary")
        
        critical_df = pd.DataFrame({
            'Framework': framework_names,
            'Critical Findings': critical_findings,
            'Last Assessment': last_assessments
        })
        
        critical_df = critical_df.sort_values('Critical Findings', ascending=False)
        
        # Create chart for critical findings
        fig = px.bar(
            critical_df,
            x='Framework',
            y='Critical Findings',
            color='Critical Findings',
            color_continuous_scale='Reds',
            text='Critical Findings',
            title="Critical Findings by Framework"
        )
        
        fig.update_layout(
            xaxis_title="Framework",
            yaxis_title="Number of Critical Findings",
            height=350,
            coloraxis_showscale=False
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Display assessment dates
        st.subheader("Last Assessment Dates")
        
        # Convert to datetime for sorting
        critical_df['Last Assessment'] = pd.to_datetime(critical_df['Last Assessment'])
        critical_df = critical_df.sort_values('Last Assessment')
        
        # Calculate days since assessment
        current_date = datetime.now().date()
        critical_df['Days Since Assessment'] = critical_df['Last Assessment'].apply(
            lambda x: (current_date - x.date()).days
        )
        
        # Convert back to string for display
        critical_df['Last Assessment'] = critical_df['Last Assessment'].dt.strftime('%Y-%m-%d')
        
        # Create a timeline chart
        fig = px.bar(
            critical_df,
            x='Framework',
            y='Days Since Assessment',
            color='Days Since Assessment',
            color_continuous_scale='Blues',
            text='Last Assessment',
            title="Days Since Last Assessment"
        )
        
        fig.update_layout(
            xaxis_title="Framework",
            yaxis_title="Days Since Last Assessment",
            height=350
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        st.subheader("Framework Compliance Details")
        
        # Framework selection
        selected_framework = st.selectbox(
            "Select Compliance Framework",
            [fw['name'] for fw in compliance_frameworks]
        )
        
        # Get the selected framework data
        framework = next((fw for fw in compliance_frameworks if fw['name'] == selected_framework), None)
        
        if framework:
            # Display summary information
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric(
                    label="Overall Compliance",
                    value=f"{framework['overall_compliance']}%",
                    delta=f"{random.choice(['+', '-'])}{random.randint(1, 5)}%" 
                )
                
            with col2:
                st.metric(
                    label="Critical Findings",
                    value=framework['critical_findings'],
                    delta=f"-{random.randint(0, 3)}",
                    delta_color="inverse"
                )
                
            with col3:
                st.metric(
                    label="Last Assessment",
                    value=framework['last_assessment'],
                    delta=f"{random.randint(10, 60)} days ago"
                )
            
            # Display radar chart of category compliance
            st.plotly_chart(plot_compliance_radar(framework), use_container_width=True)
            
            # Display category details
            st.subheader("Category Compliance Details")
            
            # Create DataFrame for category scores
            categories = framework['categories']
            scores = [framework['category_scores'][cat] for cat in categories]
            
            category_df = pd.DataFrame({
                'Category': categories,
                'Compliance Score': scores
            })
            
            # Sort by compliance score
            category_df = category_df.sort_values('Compliance Score')
            
            # Create bar chart for category scores
            fig = px.bar(
                category_df,
                x='Category',
                y='Compliance Score',
                color='Compliance Score',
                color_continuous_scale='RdYlGn',
                range_color=[50, 100],
                text='Compliance Score',
                title=f"{framework['name']} Category Compliance Scores"
            )
            
            # Add target line at 80%
            fig.add_shape(
                type="line",
                x0=-0.5, y0=80,
                x1=len(categories) - 0.5, y1=80,
                line=dict(color="black", width=2, dash="dash")
            )
            
            fig.add_annotation(
                x=len(categories) - 1, y=80,
                text="Target: 80%",
                showarrow=False,
                yshift=10
            )
            
            fig.update_layout(
                xaxis_title="Category",
                yaxis_title="Compliance Score (%)",
                yaxis=dict(range=[0, 105]),
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Generate some mock findings
            st.subheader("Top Compliance Findings")
            
            # Generate findings based on lowest scoring categories
            low_categories = category_df[category_df['Compliance Score'] < 80]['Category'].tolist()
            
            if low_categories:
                findings = []
                
                finding_templates = [
                    "Inadequate {control} controls in place for {category}",
                    "Missing documentation for {category} procedures",
                    "Lack of regular testing for {category} systems",
                    "Insufficient monitoring of {category} activities",
                    "Outdated {category} policies",
                    "Incomplete implementation of {control} for {category}"
                ]
                
                control_types = [
                    "access", "security", "monitoring", "backup", "incident response",
                    "authentication", "authorization", "encryption", "audit"
                ]
                
                severity_weights = {
                    'Critical': 0.2,
                    'High': 0.4, 
                    'Medium': 0.3,
                    'Low': 0.1
                }
                
                # Generate 2-4 findings per low-scoring category
                for category in low_categories:
                    num_findings = random.randint(2, 4)
                    
                    for _ in range(num_findings):
                        template = random.choice(finding_templates)
                        control = random.choice(control_types)
                        
                        finding = template.format(category=category, control=control)
                        severity = random.choices(
                            list(severity_weights.keys()),
                            weights=list(severity_weights.values())
                        )[0]
                        
                        findings.append({
                            'Finding': finding,
                            'Category': category,
                            'Severity': severity,
                            'Status': random.choice(['Open', 'In Remediation', 'Under Review'])
                        })
                
                # Create DataFrame of findings
                findings_df = pd.DataFrame(findings)
                
                # Sort by severity
                severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
                findings_df['Severity_order'] = findings_df['Severity'].map(severity_order)
                findings_df = findings_df.sort_values('Severity_order').drop('Severity_order', axis=1)
                
                # Display as table with colored severity
                def highlight_severity(val):
                    colors = {
                        'Critical': 'background-color: #d7191c; color: white',
                        'High': 'background-color: #fdae61; color: black',
                        'Medium': 'background-color: #ffffbf; color: black',
                        'Low': 'background-color: #abd9e9; color: black'
                    }
                    return colors.get(val, '')
                
                st.dataframe(
                    findings_df.style.applymap(highlight_severity, subset=['Severity']),
                    use_container_width=True
                )
            else:
                st.success("No significant compliance gaps found. All categories meet the minimum compliance threshold.")
    
    with tab3:
        st.subheader("Compliance Improvement Timeline")
        
        # Generate historical compliance data
        months = 12
        frameworks = [fw['name'] for fw in compliance_frameworks]
        
        historical_data = []
        
        for fw_name in frameworks:
            # Start with current compliance and work backwards with some randomization
            framework = next((fw for fw in compliance_frameworks if fw['name'] == fw_name), None)
            current_compliance = framework['overall_compliance']
            
            for i in range(months):
                month_date = (datetime.now() - timedelta(days=30 * i)).strftime('%Y-%m')
                
                # Add some randomness, but trend downward as we go back in time
                if i == 0:
                    compliance = current_compliance
                else:
                    # Random decrease between 0-3% per month going backward
                    decrease = random.uniform(0, 3)
                    compliance = max(50, current_compliance - (decrease * i) + random.uniform(-2, 2))
                
                historical_data.append({
                    'Month': month_date,
                    'Framework': fw_name,
                    'Compliance': round(compliance, 1)
                })
        
        historical_df = pd.DataFrame(historical_data)
        
        # Convert month to datetime for proper ordering
        historical_df['Month'] = pd.to_datetime(historical_df['Month'])
        
        # Create line chart
        fig = px.line(
            historical_df,
            x='Month',
            y='Compliance',
            color='Framework',
            markers=True,
            title="Compliance Score Trends Over Time",
            labels={'Month': 'Month', 'Compliance': 'Compliance Score (%)', 'Framework': 'Framework'}
        )
        
        # Add target line at 80%
        fig.add_shape(
            type="line",
            x0=historical_df['Month'].min(), y0=80,
            x1=historical_df['Month'].max(), y1=80,
            line=dict(color="black", width=2, dash="dash")
        )
        
        fig.add_annotation(
            x=historical_df['Month'].max(),
            y=80,
            text="Target: 80%",
            showarrow=False,
            xshift=50
        )
        
        fig.update_layout(
            xaxis_title="Month",
            yaxis_title="Compliance Score (%)",
            yaxis=dict(range=[50, 100]),
            height=500,
            hovermode="x unified"
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Display projected compliance
        st.subheader("Projected Compliance Improvements")
        
        # Allow selection of frameworks to project
        selected_frameworks = st.multiselect(
            "Select Frameworks for Projection",
            frameworks,
            default=[frameworks[0]] if frameworks else []
        )
        
        if selected_frameworks:
            # Generate projection data
            projection_months = 6
            projection_data = []
            
            for fw_name in selected_frameworks:
                # Get current compliance
                framework = next((fw for fw in compliance_frameworks if fw['name'] == fw_name), None)
                current_compliance = framework['overall_compliance']
                
                # Calculate improvement needed to reach target (if not already there)
                target_compliance = 95
                compliance_gap = max(0, target_compliance - current_compliance)
                
                # Monthly improvement rate
                if compliance_gap > 0:
                    monthly_improvement = compliance_gap / projection_months
                else:
                    monthly_improvement = random.uniform(0.1, 0.5)  # Slight improvement if already at target
                
                for i in range(projection_months + 1):  # +1 to include current month
                    month_date = (datetime.now() + timedelta(days=30 * i)).strftime('%Y-%m')
                    
                    # Add some randomness to the projection
                    if i == 0:
                        projected_compliance = current_compliance
                    else:
                        random_factor = random.uniform(-0.5, 1.0)
                        projected_compliance = min(100, current_compliance + (monthly_improvement * i) + random_factor)
                    
                    projection_data.append({
                        'Month': month_date,
                        'Framework': fw_name,
                        'Projected Compliance': round(projected_compliance, 1)
                    })
            
            projection_df = pd.DataFrame(projection_data)
            
            # Convert month to datetime for proper ordering
            projection_df['Month'] = pd.to_datetime(projection_df['Month'])
            
            # Create projection line chart
            fig = px.line(
                projection_df,
                x='Month',
                y='Projected Compliance',
                color='Framework',
                markers=True,
                title="Projected Compliance Improvements",
                labels={'Month': 'Month', 'Projected Compliance': 'Compliance Score (%)', 'Framework': 'Framework'}
            )
            
            # Add target line at 95%
            fig.add_shape(
                type="line",
                x0=projection_df['Month'].min(), y0=95,
                x1=projection_df['Month'].max(), y1=95,
                line=dict(color="green", width=2, dash="dash")
            )
            
            fig.add_annotation(
                x=projection_df['Month'].max(),
                y=95,
                text="Target: 95%",
                showarrow=False,
                xshift=50
            )
            
            fig.update_layout(
                xaxis_title="Month",
                yaxis_title="Projected Compliance Score (%)",
                yaxis=dict(range=[min(50, current_compliance - 10), 100]),
                height=500,
                hovermode="x unified"
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Improvement recommendations
            st.subheader("Recommended Compliance Improvements")
            
            for fw_name in selected_frameworks:
                framework = next((fw for fw in compliance_frameworks if fw['name'] == fw_name), None)
                
                if framework:
                    st.markdown(f"### {fw_name}")
                    
                    # Find lowest scoring categories
                    categories = framework['categories']
                    category_scores = framework['category_scores']
                    
                    # Sort categories by score
                    sorted_categories = sorted(categories, key=lambda cat: category_scores[cat])
                    
                    # Show recommendations for the 3 lowest categories
                    for i, category in enumerate(sorted_categories[:3]):
                        score = category_scores[category]
                        
                        st.markdown(f"**{category}** (Current Score: {score}%)")
                        
                        # Generic recommendations based on category
                        recommendations = [
                            f"Update {category} policies and procedures to align with current compliance requirements",
                            f"Conduct specialized training for staff on {category} compliance",
                            f"Implement additional controls for {category} to address gaps",
                            f"Increase monitoring and auditing frequency for {category} processes"
                        ]
                        
                        for rec in recommendations:
                            st.markdown(f"- {rec}")
                        
                        # Add specific timeline
                        if i == 0:
                            timeframe = "1 month"
                        elif i == 1:
                            timeframe = "2 months"
                        else:
                            timeframe = "3 months"
                            
                        st.markdown(f"*Target timeframe for implementation: {timeframe}*")
                        st.markdown("---")

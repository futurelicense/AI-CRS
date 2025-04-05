import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def plot_threat_overview(threat_data):
    """
    Create a bar chart showing threat counts by category and severity.
    
    Args:
        threat_data (pd.DataFrame): DataFrame containing threat data
        
    Returns:
        go.Figure: Plotly figure object
    """
    if threat_data.empty:
        # Return empty figure with message if no data
        fig = go.Figure()
        fig.add_annotation(
            text="No threat data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False
        )
        return fig
    
    # Group by category and severity and count
    threat_counts = threat_data.groupby(['category', 'severity']).size().reset_index(name='count')
    
    # Sort severity in order of priority
    severity_order = ['Critical', 'High', 'Medium', 'Low']
    threat_counts['severity'] = pd.Categorical(threat_counts['severity'], categories=severity_order, ordered=True)
    threat_counts = threat_counts.sort_values(['category', 'severity'])
    
    # Create color mapping for severity levels
    color_map = {
        'Critical': '#d7191c',
        'High': '#fdae61',
        'Medium': '#ffffbf',
        'Low': '#abd9e9'
    }
    
    # Create the bar chart
    fig = px.bar(
        threat_counts, 
        x='category', 
        y='count', 
        color='severity',
        color_discrete_map=color_map,
        title='Threats by Category and Severity',
        labels={'category': 'Threat Category', 'count': 'Number of Threats', 'severity': 'Severity Level'},
        category_orders={"severity": severity_order}
    )
    
    # Customize layout
    fig.update_layout(
        xaxis_title='Threat Category',
        yaxis_title='Number of Threats',
        legend_title='Severity',
        plot_bgcolor='rgba(0,0,0,0)',
        bargap=0.2,
        height=400
    )
    
    return fig

def plot_vulnerability_heatmap(vulnerability_data):
    """
    Create a heatmap of vulnerabilities by system and severity.
    
    Args:
        vulnerability_data (pd.DataFrame): DataFrame containing vulnerability data
        
    Returns:
        go.Figure: Plotly figure object
    """
    if vulnerability_data.empty:
        # Return empty figure with message if no data
        fig = go.Figure()
        fig.add_annotation(
            text="No vulnerability data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False
        )
        return fig
    
    # Group by affected system and severity and count
    vuln_counts = vulnerability_data.groupby(['affected_systems', 'severity']).size().reset_index(name='count')
    
    # Pivot the data for the heatmap
    heatmap_data = vuln_counts.pivot(index='affected_systems', columns='severity', values='count').fillna(0)
    
    # Ensure all severity levels are present
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        if severity not in heatmap_data.columns:
            heatmap_data[severity] = 0
    
    # Reorder severity columns
    heatmap_data = heatmap_data[['Critical', 'High', 'Medium', 'Low']]
    
    # Define color scale (red for critical to blue for low)
    colorscale = [
        [0, "#abd9e9"],     # Low
        [0.33, "#ffffbf"],  # Medium
        [0.66, "#fdae61"],  # High
        [1, "#d7191c"]      # Critical
    ]
    
    # Create heatmap
    fig = go.Figure(data=go.Heatmap(
        z=heatmap_data.values,
        x=heatmap_data.columns,
        y=heatmap_data.index,
        colorscale=colorscale,
        showscale=True,
        text=heatmap_data.values,
        texttemplate="%{text}",
        textfont={"size": 12},
    ))
    
    # Update layout
    fig.update_layout(
        title='Vulnerability Heatmap by System and Severity',
        xaxis_title='Severity Level',
        yaxis_title='Affected System',
        height=500,
        margin=dict(l=120)
    )
    
    return fig

def plot_risk_trends(incident_data):
    """
    Create a line chart showing incident trends over time.
    
    Args:
        incident_data (pd.DataFrame): DataFrame containing incident data
        
    Returns:
        go.Figure: Plotly figure object
    """
    if incident_data.empty:
        # Return empty figure with message if no data
        fig = go.Figure()
        fig.add_annotation(
            text="No incident data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False
        )
        return fig
    
    # Ensure timestamp is datetime format
    incident_data['timestamp'] = pd.to_datetime(incident_data['timestamp'])
    
    # Convert timestamp to just the date portion
    incident_data['date'] = incident_data['timestamp'].dt.date
    
    # Group by date and severity and count
    daily_incidents = incident_data.groupby(['date', 'severity']).size().reset_index(name='count')
    
    # Sort by date
    daily_incidents = daily_incidents.sort_values('date')
    
    # Create color mapping for severity levels
    color_map = {
        'Critical': '#d7191c',
        'High': '#fdae61',
        'Medium': '#ffffbf',
        'Low': '#abd9e9'
    }
    
    # Create the line chart
    fig = px.line(
        daily_incidents, 
        x='date', 
        y='count', 
        color='severity',
        color_discrete_map=color_map,
        title='Incident Trends Over Time',
        labels={'date': 'Date', 'count': 'Number of Incidents', 'severity': 'Severity Level'},
        markers=True
    )
    
    # Customize layout
    fig.update_layout(
        xaxis_title='Date',
        yaxis_title='Number of Incidents',
        legend_title='Severity',
        plot_bgcolor='rgba(0,0,0,0)',
        height=400
    )
    
    return fig

def plot_compliance_radar(compliance_data):
    """
    Create a radar chart showing compliance scores across different categories.
    
    Args:
        compliance_data (dict): Dictionary containing compliance framework data
        
    Returns:
        go.Figure: Plotly figure object
    """
    # Extract data for the selected framework
    categories = compliance_data['categories']
    scores = [compliance_data['category_scores'][cat] for cat in categories]
    
    # Create radar chart
    fig = go.Figure()
    
    fig.add_trace(go.Scatterpolar(
        r=scores,
        theta=categories,
        fill='toself',
        name=compliance_data['name'],
        line_color='rgb(27, 158, 119)',
        fillcolor='rgba(27, 158, 119, 0.2)'
    ))
    
    # Add threshold line at 80% compliance
    fig.add_trace(go.Scatterpolar(
        r=[80] * len(categories),
        theta=categories,
        fill=None,
        name='Target Compliance (80%)',
        line=dict(color='rgba(217, 95, 2, 0.8)', dash='dash')
    ))
    
    # Update layout
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 100]
            )
        ),
        title=f"{compliance_data['name']} Compliance Assessment",
        height=500,
        showlegend=True
    )
    
    return fig

def plot_risk_matrix(risk_data):
    """
    Create a risk matrix (bubble chart) showing risks by likelihood and impact.
    
    Args:
        risk_data (pd.DataFrame): DataFrame containing risk data
        
    Returns:
        go.Figure: Plotly figure object
    """
    if risk_data.empty:
        # Return empty figure with message if no data
        fig = go.Figure()
        fig.add_annotation(
            text="No risk data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False
        )
        return fig
    
    # Map severity to impact score
    severity_map = {
        'Critical': 4,
        'High': 3,
        'Medium': 2,
        'Low': 1
    }
    
    # Add impact score based on severity
    risk_data['impact'] = risk_data['severity'].map(severity_map)
    
    # Create bubble chart
    fig = px.scatter(
        risk_data,
        x='likelihood',
        y='impact',
        size='risk_score',
        color='type',
        hover_name='name',
        text='name',
        size_max=50,
        color_discrete_map={'Threat': '#636EFA', 'Vulnerability': '#EF553B'},
        labels={'likelihood': 'Likelihood', 'impact': 'Impact', 'risk_score': 'Risk Score', 'type': 'Risk Type'},
        title='Risk Matrix',
        custom_data=['description', 'category', 'severity']
    )
    
    # Change y-axis to show severity labels instead of numeric values
    fig.update_yaxes(
        tickvals=[1, 2, 3, 4],
        ticktext=['Low', 'Medium', 'High', 'Critical']
    )
    
    # Update hover template
    fig.update_traces(
        hovertemplate="<b>%{hovertext}</b><br>" +
                      "Type: %{color}<br>" +
                      "Category: %{customdata[1]}<br>" +
                      "Severity: %{customdata[2]}<br>" +
                      "Likelihood: %{x:.2f}<br>" +
                      "Risk Score: %{marker.size:.1f}<br>" +
                      "Description: %{customdata[0]}<extra></extra>",
        marker=dict(
            line=dict(width=1, color='DarkSlateGrey')
        ),
        textposition='top center'
    )
    
    # Add regions for risk levels
    # High risk zone (red)
    fig.add_shape(
        type="rect", 
        x0=0.5, y0=3, 
        x1=1, y1=4.5,
        line=dict(color="rgba(0,0,0,0)"),
        fillcolor="rgba(215, 25, 28, 0.2)"
    )
    
    # Medium-high risk zone (orange)
    fig.add_shape(
        type="rect", 
        x0=0.5, y0=2, 
        x1=1, y1=3,
        line=dict(color="rgba(0,0,0,0)"),
        fillcolor="rgba(253, 174, 97, 0.2)"
    )
    fig.add_shape(
        type="rect", 
        x0=0.25, y0=3, 
        x1=0.5, y1=4.5,
        line=dict(color="rgba(0,0,0,0)"),
        fillcolor="rgba(253, 174, 97, 0.2)"
    )
    
    # Medium risk zone (yellow)
    fig.add_shape(
        type="rect", 
        x0=0.25, y0=2, 
        x1=0.5, y1=3,
        line=dict(color="rgba(0,0,0,0)"),
        fillcolor="rgba(255, 255, 191, 0.2)"
    )
    fig.add_shape(
        type="rect", 
        x0=0, y0=3, 
        x1=0.25, y1=4.5,
        line=dict(color="rgba(0,0,0,0)"),
        fillcolor="rgba(255, 255, 191, 0.2)"
    )
    fig.add_shape(
        type="rect", 
        x0=0.5, y0=1, 
        x1=1, y1=2,
        line=dict(color="rgba(0,0,0,0)"),
        fillcolor="rgba(255, 255, 191, 0.2)"
    )
    
    # Low risk zone (green)
    fig.add_shape(
        type="rect", 
        x0=0, y0=1, 
        x1=0.5, y1=2,
        line=dict(color="rgba(0,0,0,0)"),
        fillcolor="rgba(171, 217, 233, 0.2)"
    )
    fig.add_shape(
        type="rect", 
        x0=0, y0=0, 
        x1=1, y1=1,
        line=dict(color="rgba(0,0,0,0)"),
        fillcolor="rgba(171, 217, 233, 0.2)"
    )
    
    # Update layout
    fig.update_layout(
        xaxis=dict(
            title='Likelihood',
            range=[0, 1.05],
            dtick=0.25
        ),
        yaxis=dict(
            title='Impact',
            range=[0.5, 4.5]
        ),
        height=600,
        margin=dict(l=40, r=40, t=50, b=40),
        legend=dict(
            yanchor="top",
            y=0.99,
            xanchor="left",
            x=0.01
        )
    )
    
    return fig

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta

def render_dashboard(dns_queries, alerts, is_monitoring, simulation_data):
    """Render the main dashboard"""
    
    # Top metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Queries", 
            len(dns_queries),
            f"+{len([q for q in dns_queries if 'timestamp' in q and (datetime.now() - q['timestamp']).seconds < 60])} last min"
        )
    
    with col2:
        high_alerts = len([a for a in alerts if a.get('severity') == 'HIGH'])
        st.metric("High Severity Alerts", high_alerts, delta=None)
    
    with col3:
        unique_clients = len(set([q.get('client_ip', '') for q in dns_queries]))
        st.metric("Unique Clients", unique_clients)
    
    with col4:
        monitoring_status = "🟢 ACTIVE" if is_monitoring else "🔴 INACTIVE"
        st.metric("Monitoring Status", monitoring_status)
    
    st.markdown("---")
    
    # Charts and alerts
    col1, col2 = st.columns([2, 1])
    
    with col1:
        render_traffic_charts(dns_queries, simulation_data)
    
    with col2:
        render_alerts_panel(alerts)
    
    # Query log
    st.markdown("---")
    render_query_log(dns_queries)

def render_traffic_charts(dns_queries, simulation_data):
    """Render traffic analysis charts"""
    
    st.subheader("📊 Traffic Analysis")
    
    # Query type distribution
    if dns_queries:
        query_types = [q.get('type', 'A') for q in dns_queries]
        type_counts = pd.Series(query_types).value_counts()
        
        fig_pie = go.Figure(data=[go.Pie(
            labels=type_counts.index,
            values=type_counts.values,
            hole=.3
        )])
        fig_pie.update_layout(title="DNS Query Types Distribution")
        st.plotly_chart(fig_pie, use_container_width=True)
    
    # Traffic comparison
    normal_count = len(simulation_data.get('normal_traffic', []))
    tunnel_count = len(simulation_data.get('tunnel_traffic', []))
    
    if normal_count > 0 or tunnel_count > 0:
        fig_bar = go.Figure(data=[
            go.Bar(name='Normal Traffic', x=['Normal'], y=[normal_count]),
            go.Bar(name='Tunnel Traffic', x=['Tunnel'], y=[tunnel_count])
        ])
        fig_bar.update_layout(title="Traffic Comparison", barmode='group')
        st.plotly_chart(fig_bar, use_container_width=True)

def render_alerts_panel(alerts):
    """Render the alerts panel"""
    
    st.subheader("🚨 Active Alerts")
    
    if not alerts:
        st.info("No alerts detected. Start monitoring or simulate an attack.")
        return
    
    # Show latest alerts
    recent_alerts = sorted(alerts, key=lambda x: x.get('timestamp', datetime.min), reverse=True)[:10]
    
    for alert in recent_alerts:
        timestamp = alert.get('timestamp', datetime.now()).strftime("%H:%M:%S")
        severity = alert.get('severity', 'LOW')
        
        if severity == 'HIGH':
            alert_class = "alert-high"
            icon = "🔴"
        elif severity == 'MEDIUM':
            alert_class = "alert-medium"
            icon = "🟡"
        else:
            alert_class = "alert-low"
            icon = "🔵"
        
        st.markdown(f"""
        <div class="{alert_class}">
            {icon} <strong>{severity}</strong> - {timestamp}<br>
            <small>Client: {alert.get('query', {}).get('client_ip', 'Unknown')}</small><br>
            <small>Reason: {', '.join(alert.get('alerts', []))}</small>
        </div>
        """, unsafe_allow_html=True)

def render_query_log(dns_queries):
    """Render the DNS query log"""
    
    st.subheader("📋 DNS Query Log")
    
    if not dns_queries:
        st.info("No queries logged. Generate traffic or start monitoring.")
        return
    
    # Create DataFrame for display
    log_data = []
    for query in dns_queries[-50:]:  # Show last 50 queries
        log_data.append({
            'Time': query.get('timestamp', datetime.now()).strftime("%H:%M:%S"),
            'Client IP': query.get('client_ip', 'Unknown'),
            'Query Type': query.get('type', 'A'),
            'Domain': query.get('domain', ''),
            'Entropy': f"{query.get('entropy', 0):.2f}",
            'Status': '🚨' if query.get('suspicious', False) else '✅'
        })
    
    if log_data:
        df = pd.DataFrame(log_data)
        st.dataframe(df, use_container_width=True, height=300)
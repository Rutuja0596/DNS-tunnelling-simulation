import streamlit as st
import pandas as pd
import numpy as np
import time
import random
from datetime import datetime, timedelta
from components.dashboard import render_dashboard
from components.detector import DNSDetector
from components.simulator import DNSTunnelSimulator
from dotenv import load_dotenv  # NEW

# Load environment variables
load_dotenv()

# Get portfolio links from environment variables
PORTFOLIO_URL = os.getenv('PORTFOLIO_URL')

# Page configuration
st.set_page_config(
    page_title="CovertDNS - DNS Tunneling Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional look
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #1f77b4;
    }
    .alert-high {
        background-color: #ff4b4b;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
    }
    .alert-medium {
        background-color: #ffa500;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
    }
    .alert-low {
        background-color: #008000;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

class CovertDNSApp:
    def __init__(self):
        self.detector = DNSDetector()
        self.simulator = DNSTunnelSimulator()
        self.initialize_session_state()
    
    def initialize_session_state(self):
        """Initialize session state variables"""
        if 'dns_queries' not in st.session_state:
            st.session_state.dns_queries = []
        if 'alerts' not in st.session_state:
            st.session_state.alerts = []
        if 'is_monitoring' not in st.session_state:
            st.session_state.is_monitoring = False
        if 'simulation_data' not in st.session_state:
            st.session_state.simulation_data = {
                'normal_traffic': [],
                'tunnel_traffic': []
            }
    
    def render_sidebar(self):
        """Render the sidebar controls"""
        with st.sidebar:
            st.title("🛡️ CovertDNS")
            st.markdown("---")
            
            st.subheader("Monitoring Controls")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("▶️ Start Monitoring", use_container_width=True):
                    st.session_state.is_monitoring = True
                    st.success("Monitoring started!")
            with col2:
                if st.button("⏹️ Stop Monitoring", use_container_width=True):
                    st.session_state.is_monitoring = False
                    st.info("Monitoring stopped!")
            
            st.markdown("---")
            st.subheader("Simulation Controls")
            
            if st.button("🚀 Simulate DNS Tunnel Attack", use_container_width=True):
                self.simulate_attack()
            
            if st.button("🌐 Generate Normal Traffic", use_container_width=True):
                self.generate_normal_traffic()
            
            st.markdown("---")
            st.subheader("Detection Settings")
            
            # Detection sensitivity
            sensitivity = st.slider("Detection Sensitivity", 1, 10, 7)
            st.session_state.sensitivity = sensitivity
            
            # Alert thresholds
            st.number_input("Max Queries/Min", value=100, key="max_qpm")
            st.number_input("Entropy Threshold", value=4.5, key="entropy_threshold")
    
    def simulate_attack(self):
        """Simulate a DNS tunneling attack"""
        with st.spinner("Simulating DNS tunnel attack..."):
            tunnel_queries = self.simulator.generate_tunnel_traffic()
            
            # Analyze the tunnel traffic
            for query in tunnel_queries:
                alerts = self.detector.analyze_query(query)
                if alerts:
                    for alert in alerts:
                        st.session_state.alerts.append({
                            'timestamp': datetime.now(),
                            'query': query,
                            'alerts': alert,
                            'severity': 'HIGH'
                        })
            
            st.session_state.simulation_data['tunnel_traffic'].extend(tunnel_queries)
            st.session_state.dns_queries.extend(tunnel_queries)
            
            st.success(f"Generated {len(tunnel_queries)} tunnel queries with {len(alerts) if alerts else 0} alerts!")
    
    def generate_normal_traffic(self):
        """Generate normal DNS traffic"""
        with st.spinner("Generating normal DNS traffic..."):
            normal_queries = self.simulator.generate_normal_traffic()
            st.session_state.simulation_data['normal_traffic'].extend(normal_queries)
            st.session_state.dns_queries.extend(normal_queries)
            st.success(f"Generated {len(normal_queries)} normal DNS queries!")
    
    def run(self):
        """Main application loop"""
        # Header
        st.markdown('<h1 class="main-header">🛡️ CovertDNS</h1>', unsafe_allow_html=True)
        st.markdown("### Enterprise DNS Tunneling Detection System")
        
        # Sidebar
        self.render_sidebar()
        
        # Main content
        render_dashboard(
            st.session_state.dns_queries,
            st.session_state.alerts,
            st.session_state.is_monitoring,
            st.session_state.simulation_data
        )
        
        # Auto-refresh when monitoring
        if st.session_state.is_monitoring:
            time.sleep(2)
            st.rerun()

# Run the application
if __name__ == "__main__":
    app = CovertDNSApp()
    app.run()


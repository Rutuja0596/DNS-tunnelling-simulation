import math
import re
from collections import Counter
import base64

class DNSDetector:
    def __init__(self):
        self.suspicious_patterns = [
            r'[a-z2-7]{20,}',  # Base32
            r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64
            r'[0-9a-f]{20,}',  # Hex
            r'(\w{10,}\.){3,}',  # Long subdomains
        ]
    
    def calculate_entropy(self, text):
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0
        
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy
    
    def analyze_query(self, query):
        """Analyze a DNS query for tunneling indicators"""
        alerts = []
        domain = query.get('domain', '')
        
        # Entropy analysis
        entropy = self.calculate_entropy(domain.split('.')[0])  # Check subdomain
        if entropy > 4.5:
            alerts.append(f"High entropy detected: {entropy:.2f}")
        
        # Pattern matching
        for pattern in self.suspicious_patterns:
            if re.search(pattern, domain):
                alerts.append(f"Suspicious pattern: {pattern}")
        
        # Query type analysis
        query_type = query.get('type', 'A')
        if query_type in ['TXT', 'NULL'] and entropy > 3.0:
            alerts.append(f"Unusual {query_type} record with high entropy")
        
        # Subdomain length analysis
        subdomain_parts = domain.split('.')
        if len(subdomain_parts) > 5:
            alerts.append(f"Excessive subdomain levels: {len(subdomain_parts)}")
        
        # Mark query as suspicious if any alerts
        if alerts:
            query['suspicious'] = True
            query['entropy'] = entropy
        
        return alerts
    
    def statistical_analysis(self, queries, time_window_minutes=5):
        """Perform statistical analysis on query set"""
        recent_queries = [q for q in queries 
                         if (datetime.now() - q.get('timestamp', datetime.now())).seconds < time_window_minutes * 60]
        
        if not recent_queries:
            return []
        
        alerts = []
        
        # Query rate analysis
        queries_per_minute = len(recent_queries) / time_window_minutes
        if queries_per_minute > 100:  # Threshold
            alerts.append(f"High query rate: {queries_per_minute:.1f}/min")
        
        # Unique subdomains analysis
        unique_subdomains = len(set([q.get('domain', '') for q in recent_queries]))
        if unique_subdomains > 50:  # Threshold
            alerts.append(f"High unique subdomains: {unique_subdomains}")
        
        return alerts
import random
import string
import base64
from datetime import datetime, timedelta

class DNSTunnelSimulator:
    def __init__(self):
        self.normal_domains = [
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
            'reddit.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
            'twitter.com', 'instagram.com', 'linkedin.com', 'netflix.com'
        ]
    
    def generate_normal_traffic(self, count=20):
        """Generate normal DNS traffic patterns"""
        queries = []
        
        for _ in range(count):
            domain = random.choice(self.normal_domains)
            subdomain = random.choice(['', 'www.', 'api.', 'cdn.'])
            full_domain = f"{subdomain}{domain}"
            
            queries.append({
                'timestamp': datetime.now() - timedelta(seconds=random.randint(0, 300)),
                'client_ip': f"192.168.1.{random.randint(1, 50)}",
                'type': random.choice(['A', 'AAAA', 'CNAME']),
                'domain': full_domain,
                'suspicious': False
            })
        
        return queries
    
    def generate_tunnel_traffic(self, count=15):
        """Generate DNS tunneling traffic patterns"""
        queries = []
        
        # Simulate different tunneling techniques
        techniques = [
            self._generate_base32_tunnel,
            self._generate_base64_tunnel, 
            self._generate_hex_tunnel,
            self._generate_long_subdomain_tunnel
        ]
        
        for _ in range(count):
            technique = random.choice(techniques)
            queries.extend(technique(3))  # Generate 3 queries per technique
        
        return queries
    
    def _generate_base32_tunnel(self, count):
        """Generate Base32 encoded tunnel queries"""
        queries = []
        
        for _ in range(count):
            # Simulate encoded data
            random_data = ''.join(random.choices(string.ascii_letters + string.digits, k=30))
            encoded = base64.b32encode(random_data.encode()).decode().lower().replace('=', '')
            
            queries.append({
                'timestamp': datetime.now(),
                'client_ip': f"192.168.1.{random.randint(100, 150)}",
                'type': 'TXT',
                'domain': f"{encoded}.tunnel.evil.com",
                'suspicious': True
            })
        
        return queries
    
    def _generate_base64_tunnel(self, count):
        """Generate Base64-like encoded tunnel queries"""
        queries = []
        
        for _ in range(count):
            random_data = ''.join(random.choices(string.ascii_letters + string.digits + '+/', k=40))
            
            queries.append({
                'timestamp': datetime.now(),
                'client_ip': f"192.168.1.{random.randint(100, 150)}", 
                'type': 'TXT',
                'domain': f"{random_data}.data.malicious.com",
                'suspicious': True
            })
        
        return queries
    
    def _generate_hex_tunnel(self, count):
        """Generate hex encoded tunnel queries"""
        queries = []
        
        for _ in range(count):
            hex_data = ''.join(random.choices('0123456789abcdef', k=32))
            
            queries.append({
                'timestamp': datetime.now(),
                'client_ip': f"192.168.1.{random.randint(100, 150)}",
                'type': 'NULL', 
                'domain': f"{hex_data}.exfil.attacker.com",
                'suspicious': True
            })
        
        return queries
    
    def _generate_long_subdomain_tunnel(self, count):
        """Generate long subdomain chain tunnel queries"""
        queries = []
        
        for _ in range(count):
            # Create long subdomain chain
            subdomains = [''.join(random.choices(string.ascii_lowercase, k=8)) for _ in range(6)]
            domain = '.'.join(subdomains) + '.covert.com'
            
            queries.append({
                'timestamp': datetime.now(),
                'client_ip': f"192.168.1.{random.randint(100, 150)}",
                'type': 'A',
                'domain': domain,
                'suspicious': True
            })
        
        return queries
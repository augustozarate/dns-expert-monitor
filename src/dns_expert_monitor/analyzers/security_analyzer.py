"""
DNS Security Analyzer
"""
from typing import Dict, Any, List
import math
from collections import Counter

class SecurityAnalyzer:
    """Scans DNS packets for malicious activity"""
    
    def __init__(self):
        self.suspicious_domains = set()
        self.client_behavior = {}
        self.alert_history = []
    
    def analyze_packet(self, packet_data: Dict[str, Any]) -> List[str]:
        """Scans a packet for anomalies"""
        alerts = []
        
        # 1. Check suspicious domain
        domain = packet_data.get('domain', '')
        if self._is_suspicious_domain(domain):
            alerts.append(f"Suspicious domain detected: {domain}")
        
        # 2. Check TTL too low (possible poisoning)
        if not packet_data.get('is_query', True):
            ttl = packet_data.get('ttl', 0)
            if ttl < 30 and ttl > 0:  # TTL muy bajo
                alerts.append(f"Low TTL detected ({ttl}s): possible DNS poisoning")
        
        # 3. Check unusual record types
        record_type = packet_data.get('record_type', '')
        if record_type in ['TXT', 'NULL', 'KEY', 'OPT']:
            alerts.append(f"Unusual record type: {record_type}")
        
        return alerts
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if a domain is suspicious"""
        if not domain or domain == 'unknown':
            return False
        
        domain_lower = domain.lower()
        
        # Known free hosting domains
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        
        for tld in suspicious_tlds:
            if domain_lower.endswith(tld):
                return True
        
        # High entropy in subdomains
        if self._calculate_entropy(domain) > 4.5:
            return True
        
        # Very long subdomains
        if len(domain) > 100:
            return True
        
        return False
    
    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        counter = Counter(text)
        entropy = 0.0
        total = len(text)
        
        for count in counter.values():
            p = count / total
            entropy -= p * math.log2(p)
        
        return entropy
"""
Detector of DNS tunneling
"""
from typing import Dict, Any, List, Tuple
import math
from collections import Counter
import re

class DNSTunnelingDetector:
    """Detects DNS tunneling activity using multiple heuristics"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {
            'entropy_threshold': 4.5,
            'max_subdomain_length': 50,
            'max_queries_per_second': 100,
            'suspicious_record_types': ['TXT', 'NULL', 'KEY', 'OPT'],
            'max_subdomain_count': 5,
            'min_domain_length_for_check': 20,
            'high_entropy_suspicious': True,
            'check_base64_patterns': True,
            'check_hex_patterns': True
        }
        
        self.client_stats = {}
        self.domain_stats = {}
        self.alerts = []
        
        # Patterns for detection
        self.base64_pattern = re.compile(r'[A-Za-z0-9+/=]{20,}')
        self.hex_pattern = re.compile(r'[0-9a-fA-F]{20,}')
    
    def detect(self, packet_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyzes a packet for DNS tunneling"""
        if packet_data.get('is_query', True):
            return self._analyze_query(packet_data)
        return []
    
    def _analyze_query(self, packet_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze a DNS query for tunneling"""
        alerts = []
        domain = packet_data.get('domain', '')
        client_ip = packet_data.get('src_ip', 'unknown')
        record_type = packet_data.get('record_type', '')
        
        if not domain or domain == 'unknown':
            return alerts
        
        # 1. Check domain entropy
        entropy = self._calculate_entropy(domain)
        if entropy > self.config['entropy_threshold']:
            alerts.append({
                'type': 'high_entropy',
                'severity': 'high',
                'message': f'High entropy ({entropy:.2f}) in domain: {domain[:50]}',
                'details': {
                    'domain': domain,
                    'entropy': entropy,
                    'threshold': self.config['entropy_threshold'],
                    'client': client_ip
                }
            })
        
        # 2. Check subdomain length
        domain_parts = domain.split('.')
        if len(domain) > self.config['max_subdomain_length']:
            alerts.append({
                'type': 'long_subdomain',
                'severity': 'medium',
                'message': f'Very long subdomain ({len(domain)} chars): {domain[:50]}',
                'details': {
                    'domain': domain,
                    'length': len(domain),
                    'threshold': self.config['max_subdomain_length'],
                    'client': client_ip
                }
            })
        
        # 3. Check number of subdomains
        if len(domain_parts) > self.config['max_subdomain_count'] + 2:  # +2 for domain and TLD
            alerts.append({
                'type': 'many_subdomains',
                'severity': 'medium',
                'message': f'Muchos subdominios ({len(domain_parts)}): {domain[:50]}',
                'details': {
                    'domain': domain,
                    'subdomain_count': len(domain_parts),
                    'threshold': self.config['max_subdomain_count'],
                    'client': client_ip
                }
            })
        
        # 4. Check suspicious record types
        if record_type in self.config['suspicious_record_types']:
            alerts.append({
                'type': 'suspicious_record',
                'severity': 'medium',
                'message': f'Suspicious record type: {record_type} for {domain[:50]}',
                'details': {
                    'domain': domain,
                    'record_type': record_type,
                    'client': client_ip
                }
            })
        
        # 5. Base64 Patterns
        if self.config['check_base64_patterns']:
            if self.base64_pattern.search(domain):
                alerts.append({
                    'type': 'base64_pattern',
                    'severity': 'high',
                    'message': f'Possible Base64 encoding in domain: {domain[:50]}',
                    'details': {
                        'domain': domain,
                        'client': client_ip,
                        'pattern': 'base64'
                    }
                })
        
        # 6. Hex Patterns
        if self.config['check_hex_patterns']:
            if self.hex_pattern.search(domain):
                alerts.append({
                    'type': 'hex_pattern',
                    'severity': 'medium',
                    'message': f'Possible hexadecimal encoding in domain: {domain[:50]}',
                    'details': {
                        'domain': domain,
                        'client': client_ip,
                        'pattern': 'hex'
                    }
                })
        
        # Update customer statistics
        self._update_client_stats(client_ip)
        
        return alerts
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        
        text = text.lower()
        counter = Counter(text)
        entropy = 0.0
        total = len(text)
        
        for count in counter.values():
            p = count / total
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _update_client_stats(self, client_ip: str):
        """Update statistics by client"""
        if client_ip not in self.client_stats:
            self.client_stats[client_ip] = {
                'query_count': 0,
                'alert_count': 0,
                'first_seen': None,
                'last_seen': None
            }
        
        from datetime import datetime
        now = datetime.now()
        
        stats = self.client_stats[client_ip]
        stats['query_count'] += 1
        stats['last_seen'] = now
        
        if not stats['first_seen']:
            stats['first_seen'] = now
    
    def get_client_summary(self, client_ip: str) -> Dict[str, Any]:
        """Get a summary of a client's activity"""
        if client_ip not in self.client_stats:
            return {}
        
        stats = self.client_stats[client_ip]
        return {
            'query_count': stats['query_count'],
            'alert_count': stats['alert_count'],
            'first_seen': stats['first_seen'],
            'last_seen': stats['last_seen'],
            'suspicious_level': 'high' if stats['alert_count'] > 10 else 
                              'medium' if stats['alert_count'] > 5 else 'low'
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get detector summary"""
        suspicious_clients = [
            ip for ip, stats in self.client_stats.items() 
            if stats['alert_count'] > 0
        ]
        
        return {
            'total_clients': len(self.client_stats),
            'suspicious_clients': len(suspicious_clients),
            'total_alerts': len(self.alerts),
            'client_stats': {
                ip: self.get_client_summary(ip) 
                for ip in suspicious_clients[:10]  # Top 10
            }
        }
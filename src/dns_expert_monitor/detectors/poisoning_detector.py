"""
Detector de DNS poisoning/cache poisoning
"""
from typing import Dict, Any, List
from collections import defaultdict
from datetime import datetime, timedelta

class PoisoningDetector:
    """Detects DNS poisoning attempts"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {
            'min_ttl_for_alert': 30,  # A TTL lower than this is suspicious
            'max_different_responses': 2,  # More than X different answers is suspicious
            'time_window_minutes': 5,  # Time window for analysis
            'check_ttl_anomalies': True,
            'check_multiple_responses': True,
            'check_unauthorized_servers': True
        }
        
        self.query_history = defaultdict(list)
        self.response_history = defaultdict(list)
        self.ttl_distribution = defaultdict(list)
        self.alerts = []
        
        # List of authoritative DNS servers (can be customized)
        self.authorized_servers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9']
    
    def detect(self, packet_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze a packet for DNS poisoning"""
        alerts = []
        
        if packet_data.get('is_query', True):
            # Register query
            domain = packet_data.get('domain', '')
            if domain and domain != 'unknown':
                key = f"{domain}:{packet_data.get('record_type', 'A')}"
                self.query_history[key].append({
                    'timestamp': packet_data['timestamp'],
                    'client': packet_data.get('src_ip'),
                    'server': packet_data.get('dst_ip')
                })
        else:
            # Analyze response
            alerts.extend(self._analyze_response(packet_data))
        
        return alerts
    
    def _analyze_response(self, packet_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze a DNS response"""
        alerts = []
        domain = packet_data.get('domain', '')
        ttl = packet_data.get('ttl', 0)
        response_data = packet_data.get('response_data', '')
        server_ip = packet_data.get('src_ip', '')
        record_type = packet_data.get('record_type', 'A')
        
        if not domain or domain == 'unknown':
            return alerts
        
        key = f"{domain}:{record_type}"
        
        # 1. Check TTL is very low
        if self.config['check_ttl_anomalies'] and ttl > 0:
            if ttl < self.config['min_ttl_for_alert']:
                alerts.append({
                    'type': 'low_ttl',
                    'severity': 'medium',
                    'message': f'Abnormally low TTL ({ttl}s) for {domain[:50]}',
                    'details': {
                        'domain': domain,
                        'ttl': ttl,
                        'threshold': self.config['min_ttl_for_alert'],
                        'response': response_data[:100],
                        'server': server_ip
                    }
                })
            
            # Record TTL for statistical analysis
            self.ttl_distribution[key].append({
                'timestamp': packet_data['timestamp'],
                'ttl': ttl,
                'server': server_ip
            })
        
        # 2. Check multiple different answers
        if self.config['check_multiple_responses']:
            self.response_history[key].append({
                'timestamp': packet_data['timestamp'],
                'response': response_data,
                'server': server_ip,
                'ttl': ttl
            })
            
            unique_responses = len(set(
                r['response'] for r in self.response_history[key]
                if r['response'] and r['response'] != 'N/A'
            ))
            
            if unique_responses > self.config['max_different_responses']:
                alerts.append({
                    'type': 'multiple_responses',
                    'severity': 'high',
                    'message': f'Múltiples respuestas diferentes ({unique_responses}) para {domain[:50]}',
                    'details': {
                        'domain': domain,
                        'unique_responses': unique_responses,
                        'threshold': self.config['max_different_responses'],
                        'responses': list(set(
                            r['response'][:50] for r in self.response_history[key]
                            if r['response'] and r['response'] != 'N/A'
                        ))[:5]
                    }
                })
        
        # 3. Check for unauthorized servers
        if self.config['check_unauthorized_servers'] and server_ip:
            if server_ip not in self.authorized_servers and not self._is_local_server(server_ip):
                # Check if it's a response to a recent query
                recent_queries = [
                    q for q in self.query_history.get(key, [])
                    if packet_data['timestamp'] - q['timestamp'] < timedelta(minutes=1)
                ]
                
                if recent_queries:
                    alerts.append({
                        'type': 'unauthorized_server',
                        'severity': 'medium',
                        'message': f'Unauthorized server response: {server_ip} for {domain[:50]}',
                        'details': {
                            'domain': domain,
                            'server': server_ip,
                            'authorized_servers': self.authorized_servers,
                            'response': response_data[:100]
                        }
                    })
        
        # 4. Clean old data
        self._clean_old_data()
        
        return alerts
    
    def _is_local_server(self, ip: str) -> bool:
        """Check if the IP is local/private"""
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.16.'):
            return True
        
        if ip.startswith('127.') or ip == '::1' or ip == 'localhost':
            return True
        
        return False
    
    def _clean_old_data(self):
        """Cleans data older than the time window"""
        cutoff = datetime.now() - timedelta(minutes=self.config['time_window_minutes'])
        
        # Clear query_history
        for key in list(self.query_history.keys()):
            self.query_history[key] = [
                q for q in self.query_history[key]
                if q['timestamp'] > cutoff
            ]
            if not self.query_history[key]:
                del self.query_history[key]
        
        # Clear response_history
        for key in list(self.response_history.keys()):
            self.response_history[key] = [
                r for r in self.response_history[key]
                if r['timestamp'] > cutoff
            ]
            if not self.response_history[key]:
                del self.response_history[key]
    
    def get_ttl_analysis(self, domain: str, record_type: str = 'A') -> Dict[str, Any]:
        """Gets TTL analysis for a domain"""
        key = f"{domain}:{record_type}"
        
        if key not in self.ttl_distribution or not self.ttl_distribution[key]:
            return {}
        
        ttls = [item['ttl'] for item in self.ttl_distribution[key]]
        
        return {
            'domain': domain,
            'record_type': record_type,
            'samples': len(ttls),
            'min_ttl': min(ttls) if ttls else 0,
            'max_ttl': max(ttls) if ttls else 0,
            'avg_ttl': sum(ttls) / len(ttls) if ttls else 0,
            'servers': list(set(item['server'] for item in self.ttl_distribution[key]))
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """Gets detector summary"""
        suspicious_domains = []
        
        for key, responses in self.response_history.items():
            unique_responses = len(set(
                r['response'] for r in responses
                if r['response'] and r['response'] != 'N/A'
            ))
            
            if unique_responses > self.config['max_different_responses']:
                domain = key.split(':')[0]
                suspicious_domains.append({
                    'domain': domain,
                    'unique_responses': unique_responses,
                    'total_responses': len(responses)
                })
        
        return {
            'monitored_domains': len(self.query_history),
            'suspicious_domains': len(suspicious_domains),
            'total_alerts': len(self.alerts),
            'suspicious_domains_list': suspicious_domains[:10]
        }
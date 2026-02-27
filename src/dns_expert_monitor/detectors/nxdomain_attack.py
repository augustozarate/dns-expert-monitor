"""
NXDOMAIN Attack Detector
"""
from typing import Dict, Any, List
from collections import defaultdict
from datetime import datetime, timedelta

class NXDomainAttackDetector:
    """Detect NXDOMAIN flooding attacks"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {
            'nxdomain_percentage_threshold': 30,  # NXDOMAIN maximum %
            'nxdomain_per_minute_threshold': 100,  # NXDOMAIN/minute for alert
            'check_random_subdomains': True,
            'max_random_subdomains_per_domain': 50,
            'time_window_minutes': 5,
            'check_domain_generation_algorithms': True
        }
        
        self.client_stats = defaultdict(lambda: {
            'total_responses': 0,
            'nxdomain_responses': 0,
            'domains': set(),
            'timestamps': []
        })
        
        self.domain_stats = defaultdict(lambda: {
            'total_queries': 0,
            'subdomains': set(),
            'clients': set()
        })
        
        self.alerts = []
    
    def detect(self, packet_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyzes a packet for NXDOMAIN attacks"""
        alerts = []
        
        if not packet_data.get('is_query', True):  # Only parse responses
            alerts.extend(self._analyze_response(packet_data))
        else:
            # Register query for subdomain analysis
            self._record_query(packet_data)
        
        return alerts
    
    def _analyze_response(self, packet_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze a DNS response"""
        alerts = []
        rcode = packet_data.get('rcode', 0)
        client_ip = packet_data.get('dst_ip', '')  # Client is the destiny in answers
        domain = packet_data.get('domain', '')
        
        if not client_ip or client_ip == 'unknown':
            return alerts
        
        # Update customer statistics
        stats = self.client_stats[client_ip]
        stats['total_responses'] += 1
        stats['timestamps'].append(packet_data['timestamp'])
        
        if rcode == 3:  # NXDOMAIN
            stats['nxdomain_responses'] += 1
            stats['domains'].add(domain)
            
            # Check NXDOMAIN percentage
            if stats['total_responses'] >= 10:  # Minimum samples
                nxdomain_percent = (stats['nxdomain_responses'] / stats['total_responses']) * 100
                
                if nxdomain_percent > self.config['nxdomain_percentage_threshold']:
                    alerts.append({
                        'type': 'high_nxdomain_percentage',
                        'severity': 'medium',
                        'message': f'High NXDOMAIN percentage ({nxdomain_percent:.1f}%) for client {client_ip}',
                        'details': {
                            'client': client_ip,
                            'nxdomain_percent': nxdomain_percent,
                            'threshold': self.config['nxdomain_percentage_threshold'],
                            'total_responses': stats['total_responses'],
                            'nxdomain_count': stats['nxdomain_responses'],
                            'unique_domains': len(stats['domains'])
                        }
                    })
        
        # Check NXDOMAIN rate per minute
        alerts.extend(self._check_nxdomain_rate(client_ip, stats))
        
        # Clean old data
        self._clean_old_data()
        
        return alerts
    
    def _record_query(self, packet_data: Dict[str, Any]):
        """Register a query for subdomain analysis"""
        domain = packet_data.get('domain', '')
        client_ip = packet_data.get('src_ip', '')
        
        if not domain or domain == 'unknown' or not client_ip:
            return
        
        # Extract base domain (without subdomains)
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            base_domain = '.'.join(domain_parts[-2:])  # ej: example.com
            
            # Update domain statistics
            stats = self.domain_stats[base_domain]
            stats['total_queries'] += 1
            stats['clients'].add(client_ip)
            
            # Register subdomain if it exists
            if len(domain_parts) > 2:
                subdomain = '.'.join(domain_parts[:-2])
                stats['subdomains'].add(subdomain)
                
                # Check if there are many random subdomains
                if len(stats['subdomains']) > self.config['max_random_subdomains_per_domain']:
                    # Check entropy of subdomains (simple)
                    if self._has_random_subdomains(stats['subdomains']):
                        self.alerts.append({
                            'type': 'random_subdomain_attack',
                            'severity': 'high',
                            'message': f'Possible random subdomain attack on {base_domain}',
                            'details': {
                                'base_domain': base_domain,
                                'subdomain_count': len(stats['subdomains']),
                                'threshold': self.config['max_random_subdomains_per_domain'],
                                'client_count': len(stats['clients']),
                                'total_queries': stats['total_queries']
                            }
                        })
    
    def _check_nxdomain_rate(self, client_ip: str, stats: Dict) -> List[Dict[str, Any]]:
        """Check NXDOMAIN rate per minute"""
        alerts = []
        
        # Calculate NXDOMAIN at the last minute
        cutoff = datetime.now() - timedelta(minutes=1)
        recent_nxdomains = sum(
            1 for ts in stats['timestamps']
            if ts > cutoff
        )
        
        if recent_nxdomains > self.config['nxdomain_per_minute_threshold']:
            alerts.append({
                'type': 'nxdomain_flood',
                'severity': 'high',
                'message': f'NXDOMAIN flood attack detected ({recent_nxdomains}/min) from {client_ip}',
                'details': {
                    'client': client_ip,
                    'nxdomain_per_minute': recent_nxdomains,
                    'threshold': self.config['nxdomain_per_minute_threshold'],
                    'unique_domains': len(stats['domains'])
                }
            })
        
        return alerts
    
    def _has_random_subdomains(self, subdomains: set) -> bool:
        """Check if subdomains appear random"""
        if len(subdomains) < 10:
            return False
        
        # Simple heuristic: check average length and variation
        lengths = [len(s) for s in subdomains]
        avg_length = sum(lengths) / len(lengths)
        
        # Very short or very long subdomains can be random
        if avg_length < 5 or avg_length > 20:
            return True
        
        # Check if there are many subdomains with non-alphabetic characters
        non_alpha_count = sum(
            1 for s in subdomains 
            if any(not c.isalpha() and not c.isdigit() and c != '-' for c in s)
        )
        
        return non_alpha_count > len(subdomains) * 0.5  # Más del 50%
    
    def _clean_old_data(self):
        """Clean up old data"""
        cutoff = datetime.now() - timedelta(minutes=self.config['time_window_minutes'])
        
        # Clear client_stats
        for client_ip in list(self.client_stats.keys()):
            stats = self.client_stats[client_ip]
            stats['timestamps'] = [ts for ts in stats['timestamps'] if ts > cutoff]
            
            # If there is no recent activity, delete client
            if not stats['timestamps']:
                del self.client_stats[client_ip]
        
        # Clear domain_stats (keep only recently active domains) 
        # Note: In a real implementation, you would need to track timestamps per domain
    
    def get_client_analysis(self, client_ip: str) -> Dict[str, Any]:
        """Gets analytics for a specific customer"""
        if client_ip not in self.client_stats:
            return {}
        
        stats = self.client_stats[client_ip]
        
        if stats['total_responses'] == 0:
            return {}
        
        nxdomain_percent = (stats['nxdomain_responses'] / stats['total_responses']) * 100
        
        # Calculate recent rate
        cutoff = datetime.now() - timedelta(minutes=1)
        recent_nxdomains = sum(1 for ts in stats['timestamps'] if ts > cutoff)
        
        return {
            'client_ip': client_ip,
            'total_responses': stats['total_responses'],
            'nxdomain_responses': stats['nxdomain_responses'],
            'nxdomain_percentage': nxdomain_percent,
            'unique_domains': len(stats['domains']),
            'recent_nxdomain_rate': recent_nxdomains,
            'suspicious_level': 'high' if nxdomain_percent > 50 or recent_nxdomains > 50 else
                              'medium' if nxdomain_percent > 30 or recent_nxdomains > 20 else 'low'
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get detector summary"""
        suspicious_clients = []
        
        for client_ip in self.client_stats:
            analysis = self.get_client_analysis(client_ip)
            if analysis.get('suspicious_level') in ['high', 'medium']:
                suspicious_clients.append(analysis)
        
        return {
            'monitored_clients': len(self.client_stats),
            'suspicious_clients': len(suspicious_clients),
            'total_alerts': len(self.alerts),
            'suspicious_clients_list': suspicious_clients[:10]
        }
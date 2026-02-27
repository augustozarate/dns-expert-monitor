"""
DNS amplification attack detector
"""
from typing import Dict, Any, List
from collections import defaultdict
from datetime import datetime, timedelta
import struct

class AmplificationDetector:
    """Detect possible DNS amplification attacks"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {
            'min_amplification_ratio': 10,  # Minimum alert ratio
            'max_queries_per_second': 100,  # Query limit/second
            'check_any_queries': True,
            'any_query_threshold': 50,  # ANY queries per minute
            'time_window_seconds': 60,  # Calculation window
            'check_source_ip_spoofing': True,
            'suspicious_record_types': ['ANY', 'AAAA', 'MX', 'TXT']
        }
        
        self.client_stats = defaultdict(lambda: {
            'queries': [],
            'responses': [],
            'query_sizes': [],
            'response_sizes': []
        })
        
        self.any_query_counts = defaultdict(int)
        self.alerts = []
    
    def detect(self, packet_data: Dict[str, Any], packet_size: int = None) -> List[Dict[str, Any]]:
        """Analyzes a packet for amplification"""
        alerts = []
        client_ip = packet_data.get('src_ip', '')
        record_type = packet_data.get('record_type', '')
        
        if not client_ip or client_ip == 'unknown':
            return alerts
        
        # Update statistics
        stats = self.client_stats[client_ip]
        
        if packet_data.get('is_query', True):
            stats['queries'].append({
                'timestamp': packet_data['timestamp'],
                'domain': packet_data.get('domain', ''),
                'record_type': record_type,
                'size': packet_size or 100  # Approximate DNS query size
            })
            
            # Count ANY queries
            if record_type == 'ANY' and self.config['check_any_queries']:
                minute_key = packet_data['timestamp'].strftime("%Y-%m-%d %H:%M")
                self.any_query_counts[minute_key] += 1
        
        else:
            # It's an answer
            response_size = packet_size or 500  # Approximate response size
            stats['responses'].append({
                'timestamp': packet_data['timestamp'],
                'domain': packet_data.get('domain', ''),
                'size': response_size
            })
            
            # Calculate amplification ratio if there are recent queries
            recent_queries = [
                q for q in stats['queries']
                if packet_data['timestamp'] - q['timestamp'] < timedelta(seconds=5)
            ]
            
            if recent_queries:
                avg_query_size = sum(q['size'] for q in recent_queries) / len(recent_queries)
                amplification_ratio = response_size / avg_query_size if avg_query_size > 0 else 0
                
                if amplification_ratio > self.config['min_amplification_ratio']:
                    alerts.append({
                        'type': 'high_amplification',
                        'severity': 'high',
                        'message': f'Alto ratio de amplificación ({amplification_ratio:.1f}x) desde {client_ip}',
                        'details': {
                            'client': client_ip,
                            'amplification_ratio': amplification_ratio,
                            'threshold': self.config['min_amplification_ratio'],
                            'query_size_avg': avg_query_size,
                            'response_size': response_size,
                            'domain': packet_data.get('domain', '')
                        }
                    })
        
        # Check query rate
        alerts.extend(self._check_query_rate(client_ip, stats))
        
        # Check excessive ANY queries
        alerts.extend(self._check_any_queries())
        
        # Clean old data
        self._clean_old_data()
        
        return alerts
    
    def _check_query_rate(self, client_ip: str, stats: Dict) -> List[Dict[str, Any]]:
        """Verify rate of queries per second"""
        alerts = []
        
        # Calculate queries in the last seconds
        cutoff = datetime.now() - timedelta(seconds=self.config['time_window_seconds'])
        recent_queries = [
            q for q in stats['queries']
            if q['timestamp'] > cutoff
        ]
        
        if recent_queries:
            time_span = (datetime.now() - min(q['timestamp'] for q in recent_queries)).total_seconds()
            if time_span > 0:
                qps = len(recent_queries) / time_span
                
                if qps > self.config['max_queries_per_second']:
                    alerts.append({
                        'type': 'high_query_rate',
                        'severity': 'medium',
                        'message': f'High query rate ({qps:.1f} QPS) from {client_ip}',
                        'details': {
                            'client': client_ip,
                            'qps': qps,
                            'threshold': self.config['max_queries_per_second'],
                            'query_count': len(recent_queries),
                            'time_window': self.config['time_window_seconds']
                        }
                    })
        
        return alerts
    
    def _check_any_queries(self) -> List[Dict[str, Any]]:
        """Check for excessive ANY queries"""
        alerts = []
        
        if not self.config['check_any_queries']:
            return alerts
        
        current_minute = datetime.now().strftime("%Y-%m-%d %H:%M")
        
        for minute_key, count in list(self.any_query_counts.items()):
            if count > self.config['any_query_threshold']:
                alerts.append({
                    'type': 'excessive_any_queries',
                    'severity': 'medium',
                    'message': f'Excessive ANY queries ({count}) in minute {minute_key}',
                    'details': {
                        'minute': minute_key,
                        'any_query_count': count,
                        'threshold': self.config['any_query_threshold']
                    }
                })
        
        return alerts
    
    def _clean_old_data(self):
        """Clean up old data"""
        cutoff = datetime.now() - timedelta(minutes=5)
        
        # Clear client_stats
        for client_ip in list(self.client_stats.keys()):
            stats = self.client_stats[client_ip]
            
            for key in ['queries', 'responses']:
                stats[key] = [
                    item for item in stats[key]
                    if item['timestamp'] > cutoff
                ]
            
            # Delete client if they have no recent activity
            if not stats['queries'] and not stats['responses']:
                del self.client_stats[client_ip]
        
        # Clear any_query_counts (keep last time only)
        hour_cutoff = datetime.now() - timedelta(hours=1)
        cutoff_key = hour_cutoff.strftime("%Y-%m-%d %H:%M")
        
        for minute_key in list(self.any_query_counts.keys()):
            if minute_key < cutoff_key:
                del self.any_query_counts[minute_key]
    
    def get_client_analysis(self, client_ip: str) -> Dict[str, Any]:
        """Gets analytics for a specific customer"""
        if client_ip not in self.client_stats:
            return {}
        
        stats = self.client_stats[client_ip]
        cutoff = datetime.now() - timedelta(seconds=self.config['time_window_seconds'])
        
        recent_queries = [q for q in stats['queries'] if q['timestamp'] > cutoff]
        recent_responses = [r for r in stats['responses'] if r['timestamp'] > cutoff]
        
        if not recent_queries:
            return {}
        
        time_span = (datetime.now() - min(q['timestamp'] for q in recent_queries)).total_seconds()
        qps = len(recent_queries) / time_span if time_span > 0 else 0
        
        # Calculate amplification ratios
        amplification_ratios = []
        for response in recent_responses:
            matching_queries = [
                q for q in recent_queries 
                if (response['timestamp'] - q['timestamp']).total_seconds() < 5
                and q['domain'] == response['domain']
            ]
            
            if matching_queries:
                avg_query_size = sum(q['size'] for q in matching_queries) / len(matching_queries)
                if avg_query_size > 0:
                    amplification_ratios.append(response['size'] / avg_query_size)
        
        avg_amplification = sum(amplification_ratios) / len(amplification_ratios) if amplification_ratios else 0
        
        return {
            'client_ip': client_ip,
            'query_count': len(recent_queries),
            'response_count': len(recent_responses),
            'qps': qps,
            'avg_amplification': avg_amplification,
            'max_amplification': max(amplification_ratios) if amplification_ratios else 0,
            'record_types': list(set(q['record_type'] for q in recent_queries))
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get detector summary"""
        high_amplification_clients = []
        high_qps_clients = []
        
        for client_ip, stats in self.client_stats.items():
            analysis = self.get_client_analysis(client_ip)
            
            if analysis.get('avg_amplification', 0) > self.config['min_amplification_ratio']:
                high_amplification_clients.append({
                    'client': client_ip,
                    'amplification': analysis['avg_amplification'],
                    'query_count': analysis['query_count']
                })
            
            if analysis.get('qps', 0) > self.config['max_queries_per_second']:
                high_qps_clients.append({
                    'client': client_ip,
                    'qps': analysis['qps'],
                    'query_count': analysis['query_count']
                })
        
        return {
            'monitored_clients': len(self.client_stats),
            'high_amplification_clients': len(high_amplification_clients),
            'high_qps_clients': len(high_qps_clients),
            'total_any_queries': sum(self.any_query_counts.values()),
            'alerts': len(self.alerts)
        }
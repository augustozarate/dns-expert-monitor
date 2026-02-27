"""
Real-time statistics engine for DNS
"""
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

class StatisticsEngine:
    """Collect and analyze DNS traffic statistics"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        """Reset all statistics"""
        self.start_time = datetime.now()
        
        # Basic counters
        self.counters = {
            'total_packets': 0,
            'queries': 0,
            'responses': 0,
            'errors': 0,
        }
        
        # Distributions
        self.distributions = {
            'record_types': Counter(),
            'response_codes': Counter(),
            'clients': Counter(),
            'domains': Counter(),
            'query_types': Counter(),
        }
        
        # Time series (last hour)
        self.timeline = {
            'queries_per_minute': defaultdict(int),
            'responses_per_minute': defaultdict(int),
        }
    
    def add_packet(self, packet_data: Dict[str, Any]):
        """Process a DNS packet for statistics"""
        self.counters['total_packets'] += 1
        
        if packet_data.get('is_query'):
            self.counters['queries'] += 1
            
            # Update per minute
            minute_key = packet_data['timestamp'].strftime("%H:%M")
            self.timeline['queries_per_minute'][minute_key] += 1
            
            # Domains and types
            domain = packet_data.get('domain')
            record_type = packet_data.get('record_type')
            
            if domain and domain != 'unknown':
                self.distributions['domains'][domain] += 1
            
            if record_type and record_type != 'unknown':
                self.distributions['record_types'][record_type] += 1
            
            # Customers
            client = packet_data.get('src_ip')
            if client and client != 'unknown':
                self.distributions['clients'][client] += 1
        
        else:  # Answer
            self.counters['responses'] += 1
            
            minute_key = packet_data['timestamp'].strftime("%H:%M")
            self.timeline['responses_per_minute'][minute_key] += 1
            
            # Response codes
            rcode = packet_data.get('rcode', 0)
            self.distributions['response_codes'][rcode] += 1
    
    def get_summary(self) -> Dict[str, Any]:
        """Returns a summary of the statistics"""
        duration = datetime.now() - self.start_time
        hours, remainder = divmod(duration.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        
        # Calculate rates
        if duration.total_seconds() > 0:
            qps = self.counters['queries'] / duration.total_seconds()
            rps = self.counters['responses'] / duration.total_seconds()
        else:
            qps = rps = 0
        
        return {
            'duration': {
                'hours': int(hours),
                'minutes': int(minutes),
                'seconds': int(seconds),
                'total_seconds': duration.total_seconds()
            },
            'counters': dict(self.counters),
            'rates': {
                'queries_per_second': round(qps, 2),
                'responses_per_second': round(rps, 2),
                'queries_per_minute': round(qps * 60, 2),
            },
            'top_domains': self.distributions['domains'].most_common(10),
            'top_clients': self.distributions['clients'].most_common(10),
            'record_type_distribution': dict(self.distributions['record_types']),
            'response_code_distribution': dict(self.distributions['response_codes']),
        }
    
    def get_top_items(self, category: str, limit: int = 10) -> List[tuple]:
        """Gets the most frequent items of a category"""
        if category in self.distributions:
            return self.distributions[category].most_common(limit)
        return []
    
    def get_timeline_data(self, window_minutes: int = 60) -> Dict[str, List]:
        """Returns timeline data for charts"""
        now = datetime.now()
        window_start = now - timedelta(minutes=window_minutes)
        
        labels = []
        queries = []
        responses = []
        
        # Generate points for each minute in the window
        for i in range(window_minutes):
            point_time = window_start + timedelta(minutes=i)
            minute_key = point_time.strftime("%H:%M")
            
            labels.append(minute_key)
            queries.append(self.timeline['queries_per_minute'].get(minute_key, 0))
            responses.append(self.timeline['responses_per_minute'].get(minute_key, 0))
        
        return {
            'labels': labels,
            'queries': queries,
            'responses': responses,
            'window_minutes': window_minutes
        }
"""
DNS cache response analyzer
"""
from typing import Dict, Any, List
from datetime import datetime, timedelta

class CacheAnalyzer:
    """Analyze DNS responses from a cache perspective"""
    
    def __init__(self):
        self.cache = {}
        self.ttl_distribution = {}
    
    def analyze_response(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a DNS response for cache"""
        analysis = {
            'cacheable': False,
            'ttl': 0,
            'cache_hit': False,
            'recommendation': ''
        }
        
        if packet_data.get('is_query', True):
            return analysis
        
        domain = packet_data.get('domain', '')
        ttl = packet_data.get('ttl', 0)
        record_type = packet_data.get('record_type', '')
        
        # Determine if it is cacheable
        cacheable_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR']
        analysis['cacheable'] = record_type in cacheable_types and ttl > 0
        
        if analysis['cacheable']:
            analysis['ttl'] = ttl
            
            # Check if it is already cached
            cache_key = f"{domain}:{record_type}"
            current_time = datetime.now()
            
            if cache_key in self.cache:
                cached_until = self.cache[cache_key]
                if current_time < cached_until:
                    analysis['cache_hit'] = True
            
            # Refresh cache
            expires_at = current_time + timedelta(seconds=ttl)
            self.cache[cache_key] = expires_at
            
            # TTL-based recommendations
            if ttl < 300:
                analysis['recommendation'] = 'TTL too low, consider increasing'
            elif ttl > 86400:
                analysis['recommendation'] = 'TTL too high, consider reduction'
            else:
                analysis['recommendation'] = 'TTL appropriate'
        
        return analysis
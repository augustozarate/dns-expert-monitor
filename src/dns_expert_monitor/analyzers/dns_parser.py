"""
Advanced parser for DNS packets
"""
import struct
from typing import Dict, Any, Optional

class DNSParser:
    """Parser to extract detailed information from DNS packets"""
    
    @staticmethod
    def parse_dns_packet(packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Basic DNS packet parsing"""
        result = {
            'timestamp': packet_data.get('timestamp'),
            'src_ip': packet_data.get('src_ip'),
            'dst_ip': packet_data.get('dst_ip'),
            'is_query': packet_data.get('is_query', False),
            'domain': packet_data.get('domain', 'unknown'),
            'record_type': packet_data.get('record_type', 'unknown'),
            'protocol': packet_data.get('protocol', 'UDP')
        }
        
        # Add specific information
        if packet_data.get('is_query'):
            result.update({
                'qtype': packet_data.get('qtype'),
                'qclass': packet_data.get('qclass'),
                'type': 'query'
            })
        else:
            result.update({
                'rcode': packet_data.get('rcode', 0),
                'response_data': packet_data.get('response_data', 'N/A'),
                'ttl': packet_data.get('ttl', 0),
                'type': 'response'
            })
        
        return result
    
    @staticmethod
    def get_rcode_name(rcode: int) -> str:
        """Convert DNS response code to readable name"""
        rcode_names = {
            0: "NOERROR",
            1: "FORMERR",
            2: "SERVFAIL",
            3: "NXDOMAIN",
            4: "NOTIMP",
            5: "REFUSED",
            6: "YXDOMAIN",
            7: "YXRRSET",
            8: "NXRRSET",
            9: "NOTAUTH",
            10: "NOTZONE"
        }
        return rcode_names.get(rcode, f"UNKNOWN({rcode})")
    
    @staticmethod
    def extract_domain_components(domain: str) -> Dict[str, Any]:
        """Extract components from a domain"""
        if domain == 'unknown':
            return {'tld': 'unknown', 'subdomains': [], 'level': 0}
        
        parts = domain.rstrip('.').split('.')
        
        return {
            'tld': parts[-1] if len(parts) > 1 else '',
            'domain': parts[-2] if len(parts) > 2 else parts[-1] if parts else '',
            'subdomains': parts[:-2] if len(parts) > 2 else [],
            'level': len(parts),
            'is_ip_reverse': domain.endswith('.in-addr.arpa') or '.ip6.arpa' in domain
        }
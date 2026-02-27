"""
DNS Capture Engine using Scapy - Cross Platform
"""
import time
from datetime import datetime
from threading import Thread, Event
from typing import Optional, Callable, Dict, Any
import signal

from scapy.all import sniff, conf, get_if_list
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, TCP

from .packet_queue import PacketQueue

class DNSCaptureEngine:
    """DNS capture engine with robust error handling"""
    
    def __init__(self, interface: Optional[str] = None):
        self.interface = self._validate_interface(interface)
        self.running = False
        self.capture_thread = None
        self.stop_event = Event()
        self.packet_queue = PacketQueue(maxsize=5000)
        
        # Statistics
        self.stats = {
            'start_time': None,
            'total_packets': 0,
            'dns_queries': 0,
            'dns_responses': 0,
            'errors': 0,
            'by_record_type': {},
            'by_domain': {},
            'by_client': {},
            'by_rcode': {}
        }
        
        # Callbacks
        self.on_packet_callbacks = []
        self.on_error_callbacks = []
        
        print(f"[✓] Engine initialized in interface: {self.interface}")
    
    def _validate_interface(self, interface: Optional[str]) -> str:
        """Validate and select the appropriate interface"""
        if interface:
            ifaces = get_if_list()
            if interface in ifaces:
                return interface
            else:
                print(f"[!] Interface '{interface}' not found")
                print(f"[i] Available interfaces: {', '.join(ifaces[:5])}")
        
        # Use Scapy's default interface
        if conf.iface:
            return conf.iface
        
        # First interface available
        ifaces = get_if_list()
        if ifaces:
            # Avoid loopback if there are others
            for iface in ifaces:
                if iface != 'lo' and not iface.startswith('lo:'):
                    return iface
            return ifaces[0]
        
        raise RuntimeError("No network interfaces found")
    
    def _packet_handler(self, packet):
        """Primary DNS packet handler"""
        try:
            self.stats['total_packets'] += 1
            
            # Filter only DNS packets (port 53)
            if packet.haslayer(DNS):
                # Extract basic information
                src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
                dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
                
                dns_layer = packet[DNS]
                is_query = dns_layer.qr == 0
                
                # Build base data
                dns_data = {
                    'timestamp': datetime.now(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'is_query': is_query,
                    'id': dns_layer.id,
                    'opcode': dns_layer.opcode,
                    'type': 'query' if is_query else 'response',
                    'domain': 'unknown',
                    'record_type': 'unknown',
                    'protocol': 'TCP' if packet.haslayer(TCP) else 'UDP'
                }
                
                # Process query
                if is_query and dns_layer.qd:
                    self.stats['dns_queries'] += 1
                    query = dns_layer.qd
                    
                    # Extract domain
                    try:
                        domain = str(query.qname.decode('utf-8', errors='ignore'))
                    except (AttributeError, UnicodeDecodeError):
                        domain = str(query.qname)
                    
                    # Clear domain
                    domain = domain.rstrip('.')
                    
                    dns_data.update({
                        'domain': domain,
                        'record_type': self._get_record_type_name(query.qtype),
                        'qtype': query.qtype,
                        'qclass': query.qclass
                    })
                
                # Process response
                elif not is_query:
                    self.stats['dns_responses'] += 1
                    
                    # Save response code
                    rcode = dns_layer.rcode
                    self.stats['by_rcode'][rcode] = self.stats['by_rcode'].get(rcode, 0) + 1
                    dns_data['rcode'] = rcode
                    
                    # Extract domain from question if it exists
                    if dns_layer.qd:
                        query = dns_layer.qd
                        try:
                            domain = str(query.qname.decode('utf-8', errors='ignore'))
                            domain = domain.rstrip('.')
                            dns_data['domain'] = domain
                            dns_data['record_type'] = self._get_record_type_name(query.qtype)
                        except:
                            pass
                    
                    # Extract response data if it exists
                    if dns_layer.an:
                        answer = dns_layer.an[0]
                        dns_data['response_data'] = str(answer.rdata) if hasattr(answer, 'rdata') else 'N/A'
                        dns_data['ttl'] = answer.ttl if hasattr(answer, 'ttl') else 0
                
                # Update statistics
                self._update_stats(dns_data)
                
                # Add to queue for asynchronous processing
                self.packet_queue.put(dns_data)
        
        except Exception as e:
            self.stats['errors'] += 1
            error_msg = f"Error processing package: {type(e).__name__}: {str(e)[:50]}"
            
            for callback in self.on_error_callbacks:
                try:
                    callback(error_msg, packet)
                except:
                    pass
    
    def _get_record_type_name(self, qtype: int) -> str:
        """Convert numeric type to readable name"""
        record_types = {
            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA',
            12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA',
            33: 'SRV', 43: 'DS', 46: 'RRSIG', 47: 'NSEC',
            48: 'DNSKEY', 255: 'ANY', 41: 'OPT'
        }
        return record_types.get(qtype, f"TYPE{qtype}")
    
    def _update_stats(self, data: Dict[str, Any]):
        """Update statistics in real time"""
        domain = data.get('domain', 'unknown')
        record_type = data.get('record_type', 'unknown')
        client = data.get('src_ip', 'unknown')
        
        if domain != 'unknown' and len(self.stats['by_domain']) < 1000:
            self.stats['by_domain'][domain] = self.stats['by_domain'].get(domain, 0) + 1
        
        if record_type != 'unknown':
            self.stats['by_record_type'][record_type] = \
                self.stats['by_record_type'].get(record_type, 0) + 1
        
        if client != 'unknown':
            self.stats['by_client'][client] = self.stats['by_client'].get(client, 0) + 1
    
    def register_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Register a callback for custom processing"""
        self.packet_queue.register_processor(callback)
        self.on_packet_callbacks.append(callback)
    
    def register_error_callback(self, callback: Callable[[str, Any], None]):
        """Register a callback for errors"""
        self.on_error_callbacks.append(callback)
    
    def start(self, num_workers: int = 2):
        """Start the capture in a separate thread"""
        if self.running:
            print("[!] Capture is already running")
            return
        
        self.running = True
        self.stop_event.clear()
        self.stats['start_time'] = datetime.now()
        
        # Start processing workers
        self.packet_queue.start(num_workers)
        
        print(f"[→] Initiating DNS capture on {self.interface}...")
        print("[i] Press Ctrl+C to stop\n")
        
        def capture_loop():
            try:
                sniff(
                    iface=self.interface,
                    filter="port 53",
                    prn=self._packet_handler,
                    store=0,
                    stop_filter=lambda _: self.stop_event.is_set(),
                    promisc=True
                )
            except PermissionError:
                print("\n[!] ERROR: Insufficient permissions")
                print("[i] Run with sudo: sudo python run.py monitor")
                self.running = False
            except Exception as e:
                print(f"[!] Capture error: {type(e).__name__}: {str(e)[:100]}")
                self.running = False

        self.capture_thread = Thread(target=capture_loop, daemon=True)
        self.capture_thread.start()
    
    def stop(self):
        """Stop capture"""
        if not self.running:
            return
        
        print("\n[!] Stopping capture...")
        self.stop_event.set()
        self.running = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=3)
        
        self.packet_queue.stop()
        print("[✓] Capture stopped")
    
    def print_stats(self):
        """Shows capture statistics"""
        from rich.console import Console
        from rich.table import Table
        
        console = Console()
        
        if self.stats['start_time']:
            duration = datetime.now() - self.stats['start_time']
            duration_str = str(duration).split('.')[0]
        else:
            duration_str = "N/A"
        
        table = Table(title="📊 DNS Capture Statistics")
        table.add_column("Metrics", style="cyan")
        table.add_column("Value", style="green", justify="right")
        
        table.add_row("Duration", duration_str)
        table.add_row("Total packets", f"{self.stats['total_packets']:,}")
        table.add_row("DNS queries", f"{self.stats['dns_queries']:,}")
        table.add_row("DNS Responses", f"{self.stats['dns_responses']:,}")
        table.add_row("Errors", f"{self.stats['errors']:,}")
        table.add_row("Processing queue", f"{self.packet_queue.size()}")
        table.add_row("Unique domains", f"{len(self.stats['by_domain']):,}")
        table.add_row("Unique clients", f"{len(self.stats['by_client']):,}")
        table.add_row("Record types", f"{len(self.stats['by_record_type']):,}")
        
        console.print(table)
        
        # Show top domains if there is data
        if self.stats['by_domain']:
            top_domains = sorted(
                self.stats['by_domain'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            table2 = Table(title="🏆 Top 10 Domains Consulted")
            table2.add_column("#", style="dim", width=3)
            table2.add_column("Domain", style="yellow")
            table2.add_column("Queries", style="green", justify="right")
            
            for idx, (domain, count) in enumerate(top_domains, 1):
                # Shorten very long domains
                if len(domain) > 40:
                    domain = domain[:37] + "..."
                table2.add_row(str(idx), domain, f"{count:,}")
            
            console.print(table2)
    
    def get_stats(self) -> Dict[str, Any]:
        """Returns current statistics"""
        return self.stats.copy()
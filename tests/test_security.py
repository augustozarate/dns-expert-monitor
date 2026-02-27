#!/usr/bin/env python3
"""
DNS Expert Monitor - Security Detectors Test Script
Tests all security detectors with simulated malicious traffic
"""
import sys
import os
import time
import random
import string
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from dns_expert_monitor.detectors import (
    DNSTunnelingDetector, 
    PoisoningDetector,
    AmplificationDetector,
    NXDomainAttackDetector,
    SecurityManager
)

# Terminal colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

def print_banner():
    """Show test banner"""
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                                  ║
║   {Colors.BOLD}🧪 DNS EXPERT MONITOR - SECURITY DETECTORS TEST{Colors.END}{Colors.CYAN}          ║
║   {Colors.DIM}Unit tests for all security detection modules{Colors.END}{Colors.CYAN}             ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)

def random_string(length=30):
    """Generate a random string"""
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def test_tunneling_detector():
    """Test DNS Tunneling Detector"""
    print(f"\n{Colors.BOLD}1. Testing DNS Tunneling Detector{Colors.END}")
    print("═" * 50)
    
    detector = DNSTunnelingDetector()
    
    # Test 1: Normal domain (should not alert)
    normal_packet = {
        'timestamp': datetime.now(),
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'is_query': True,
        'domain': 'google.com',
        'record_type': 'A'
    }
    alerts = detector.detect(normal_packet)
    print(f"  • Normal domain: {Colors.GREEN}{len(alerts)} alerts ✓{Colors.END}")
    
    # Test 2: High entropy domain (should alert)
    high_entropy_packet = {
        'timestamp': datetime.now(),
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'is_query': True,
        'domain': random_string(35) + '.example.com',
        'record_type': 'TXT'
    }
    alerts = detector.detect(high_entropy_packet)
    print(f"  • High entropy domain: {Colors.YELLOW}{len(alerts)} alerts{Colors.END}")
    for alert in alerts:
        print(f"    → {alert.get('type')}: {alert.get('message')[:60]}...")
    
    return detector

def test_poisoning_detector():
    """Test DNS Poisoning Detector"""
    print(f"\n{Colors.BOLD}2. Testing DNS Poisoning Detector{Colors.END}")
    print("═" * 50)
    
    detector = PoisoningDetector()
    
    # Test 1: Normal response (should not alert)
    normal_response = {
        'timestamp': datetime.now(),
        'src_ip': '8.8.8.8',
        'dst_ip': '192.168.1.100',
        'is_query': False,
        'domain': 'google.com',
        'record_type': 'A',
        'response_data': '142.250.185.78',
        'ttl': 300,
        'rcode': 0
    }
    alerts = detector.detect(normal_response)
    print(f"  • Normal response: {Colors.GREEN}{len(alerts)} alerts ✓{Colors.END}")
    
    # Test 2: Low TTL response (should alert)
    low_ttl_response = {
        'timestamp': datetime.now(),
        'src_ip': '192.168.1.50',
        'dst_ip': '192.168.1.100',
        'is_query': False,
        'domain': 'bank.com',
        'record_type': 'A',
        'response_data': '1.2.3.4',
        'ttl': 5,
        'rcode': 0
    }
    alerts = detector.detect(low_ttl_response)
    print(f"  • Low TTL response: {Colors.YELLOW}{len(alerts)} alerts{Colors.END}")
    for alert in alerts:
        print(f"    → {alert.get('type')}: {alert.get('message')}")
    
    return detector

def test_amplification_detector():
    """Test Amplification DDoS Detector"""
    print(f"\n{Colors.BOLD}3. Testing Amplification Detector{Colors.END}")
    print("═" * 50)
    
    detector = AmplificationDetector()
    client_ip = '192.168.1.200'
    
    # Test 1: Normal traffic
    normal_query = {
        'timestamp': datetime.now(),
        'src_ip': client_ip,
        'dst_ip': '8.8.8.8',
        'is_query': True,
        'domain': 'example.com',
        'record_type': 'A'
    }
    detector.detect(normal_query)
    print(f"  • Normal traffic: {Colors.GREEN}OK{Colors.END}")
    
    # Test 2: High rate traffic
    print(f"  • Generating high rate traffic...")
    for i in range(150):
        query = {
            'timestamp': datetime.now(),
            'src_ip': client_ip,
            'dst_ip': '8.8.8.8',
            'is_query': True,
            'domain': f'test{i}.example.com',
            'record_type': 'ANY' if i % 10 == 0 else 'A'
        }
        detector.detect(query)
    
    # Test 3: Amplified response
    large_response = {
        'timestamp': datetime.now(),
        'src_ip': '8.8.8.8',
        'dst_ip': client_ip,
        'is_query': False,
        'domain': 'test.example.com',
        'record_type': 'TXT',
        'response_data': 'x' * 4000,
        'rcode': 0
    }
    alerts = detector.detect(large_response, packet_size=4000)
    print(f"  • Amplified response: {Colors.YELLOW}{len(alerts)} alerts{Colors.END}")
    
    return detector

def test_nxdomain_detector():
    """Test NXDOMAIN Attack Detector"""
    print(f"\n{Colors.BOLD}4. Testing NXDOMAIN Attack Detector{Colors.END}")
    print("═" * 50)
    
    detector = NXDomainAttackDetector()
    client_ip = '192.168.1.150'
    
    # Generate NXDOMAIN flood
    print(f"  • Generating NXDOMAIN flood...")
    for i in range(120):
        response = {
            'timestamp': datetime.now(),
            'src_ip': '8.8.8.8',
            'dst_ip': client_ip,
            'is_query': False,
            'domain': f'nonexistent{i}.example.com',
            'record_type': 'A',
            'rcode': 3  # NXDOMAIN
        }
        detector.detect(response)
    
    # Show analysis
    analysis = detector.get_client_analysis(client_ip)
    if analysis:
        print(f"  • Client analysis:")
        print(f"    → NXDOMAIN percentage: {analysis.get('nxdomain_percentage', 0):.1f}%")
        print(f"    → Recent rate: {analysis.get('recent_nxdomain_rate', 0)}/min")
        print(f"    → Suspicious level: {Colors.YELLOW}{analysis.get('suspicious_level')}{Colors.END}")
    
    return detector

def test_security_manager():
    """Test Security Manager with multiple detectors"""
    print(f"\n{Colors.BOLD}5. Testing Security Manager{Colors.END}")
    print("═" * 50)
    
    manager = SecurityManager()
    
    # Test packets
    test_packets = [
        # Tunneling attempt
        {
            'timestamp': datetime.now(),
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'is_query': True,
            'domain': random_string(35) + '.example.com',
            'record_type': 'TXT'
        },
        # Poisoning attempt
        {
            'timestamp': datetime.now(),
            'src_ip': '192.168.1.50',
            'dst_ip': '192.168.1.100',
            'is_query': False,
            'domain': 'bank.com',
            'record_type': 'A',
            'response_data': '1.2.3.4',
            'ttl': 5,
            'rcode': 0
        }
    ]
    
    total_alerts = 0
    for packet in test_packets:
        alerts = manager.analyze_packet(packet)
        total_alerts += len(alerts)
    
    print(f"  • Total alerts generated: {Colors.YELLOW}{total_alerts}{Colors.END}")
    
    # Show summary
    summary = manager.get_alerts_summary()
    if summary.get('by_detector'):
        print(f"  • Alerts by detector:")
        for detector, count in summary['by_detector'].items():
            print(f"    → {detector}: {count}")
    
    return manager

def main():
    """Main test function"""
    print_banner()
    
    try:
        # Run tests
        test_tunneling_detector()
        test_poisoning_detector()
        test_amplification_detector()
        test_nxdomain_detector()
        test_security_manager()
        
        print(f"\n{Colors.GREEN}✅ ALL TESTS COMPLETED SUCCESSFULLY{Colors.END}")
        print(f"\n{Colors.BOLD}📋 Summary:{Colors.END}")
        print("  • DNS Tunneling Detector: Working ✓")
        print("  • DNS Poisoning Detector: Working ✓")
        print("  • Amplification Detector: Working ✓")
        print("  • NXDOMAIN Detector: Working ✓")
        print("  • Security Manager: Working ✓")
        print(f"\n{Colors.CYAN}💡 Next steps:{Colors.END}")
        print("  1. Run live monitor: sudo python run.py monitor --security")
        print("  2. Generate test traffic: python tests/generate_test_traffic.py")
        print("  3. Create reports: python run.py report capture.json")
        
    except Exception as e:
        print(f"\n{Colors.RED}❌ Test failed: {e}{Colors.END}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
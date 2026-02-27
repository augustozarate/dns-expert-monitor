#!/usr/bin/env python3
"""
DNS Expert Monitor - Test Traffic Generator
Generates simulated DNS traffic to test security detectors

Features:
- Alternates between normal and suspicious domains
- Shows real-time query results
- Helps verify detector functionality
"""
import subprocess
import time
import random
import string
import sys
from datetime import datetime

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
║   {Colors.BOLD}🧪 DNS EXPERT MONITOR - TEST TRAFFIC GENERATOR{Colors.END}{Colors.CYAN}           ║
║   {Colors.DIM}Generate simulated DNS traffic to test security detectors{Colors.END}{Colors.CYAN}  ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)

def random_string(length=20):
    """Generate a random string for suspicious domains"""
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def dns_query(domain, server="8.8.8.8", timeout=3):
    """
    Perform DNS query and return detailed result
    
    Returns:
        tuple: (status, details)
    """
    try:
        start_time = time.time()
        result = subprocess.run(
            ["nslookup", domain, server],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        elapsed = time.time() - start_time
        
        output = result.stdout.lower()
        
        # Analyze response
        if "nxdomain" in output or "can't find" in output or "nonexistent domain" in output:
            return "NXDOMAIN", f"Domain does not exist ({elapsed:.2f}s)"
        elif "timed out" in output or "no response" in output:
            return "TIMEOUT", f"Server timeout ({elapsed:.2f}s)"
        elif result.returncode == 0:
            # Extract IP if available
            import re
            ip_match = re.search(r'address:?\s*([0-9.]+)', result.stdout.lower())
            ip = ip_match.group(1) if ip_match else "unknown"
            return "SUCCESS", f"Resolved to {ip} ({elapsed:.2f}s)"
        else:
            return "ERROR", f"Query failed ({elapsed:.2f}s)"
            
    except subprocess.TimeoutExpired:
        return "TIMEOUT", f"Query timeout ({timeout}s)"
    except Exception as e:
        return "ERROR", f"{str(e)}"

def print_result(count, domain_type, domain, status, details):
    """Print formatted result"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # Color by status
    if status == "SUCCESS":
        status_color = Colors.GREEN
        status_symbol = "✅"
    elif status == "NXDOMAIN":
        status_color = Colors.YELLOW
        status_symbol = "⚠️ "
    elif status == "TIMEOUT":
        status_color = Colors.RED
        status_symbol = "⏱️ "
    else:
        status_color = Colors.RED
        status_symbol = "❌"
    
    # Color by domain type
    if domain_type == "SUSPICIOUS":
        type_color = Colors.RED
    else:
        type_color = Colors.GREEN
    
    # Truncate long domains
    display_domain = domain[:40] + "..." if len(domain) > 40 else domain
    
    print(f"{Colors.DIM}[{timestamp}]{Colors.END} "
          f"{status_symbol}{status_color}{status:8}{Colors.END} "
          f"{type_color}{domain_type:10}{Colors.END} "
          f"{display_domain:<44} "
          f"{Colors.DIM}{details}{Colors.END}")

def main():
    """Main function"""
    print_banner()
    
    print(f"{Colors.BOLD}📡 Configuration:{Colors.END}")
    print(f"  • DNS Server: {Colors.CYAN}8.8.8.8{Colors.END}")
    print(f"  • Query interval: {Colors.CYAN}0.5 seconds{Colors.END}")
    print(f"  • Suspicious domains: {Colors.RED}30-char random strings{Colors.END}")
    print(f"  • Normal domains: {Colors.GREEN}Common websites{Colors.END}")
    print(f"\n{Colors.BOLD}🚀 Starting test traffic generation...{Colors.END}")
    print(f"{Colors.YELLOW}📡 Press Ctrl+C to stop{Colors.END}\n")
    
    normal_domains = [
        "google.com", "github.com", "wikipedia.org", 
        "example.com", "python.org", "stackoverflow.com",
        "gitlab.com", "docker.com", "kubernetes.io",
        "amazon.com", "microsoft.com", "apple.com"
    ]
    
    try:
        count = 0
        while True:
            # Alternate between suspicious and normal domains
            if count % 3 == 0 or count % 5 == 0:  # More frequent suspicious
                # Suspicious domain (high entropy, tunneling-like)
                rand_len = random.choice([25, 30, 35, 40])
                domain = f"{random_string(rand_len)}.example.com"
                domain_type = "SUSPICIOUS"
            else:
                # Normal domain
                domain = random.choice(normal_domains)
                domain_type = "NORMAL"
            
            # Perform DNS query
            status, details = dns_query(domain)
            
            # Show result
            print_result(count, domain_type, domain, status, details)
            
            count += 1
            time.sleep(0.5)  # Wait half second between queries
            
    except KeyboardInterrupt:
        print(f"\n\n{Colors.GREEN}✅ Test completed{Colors.END}")
        print(f"{Colors.BOLD}📊 Statistics:{Colors.END}")
        print(f"  • Total queries: {Colors.CYAN}{count}{Colors.END}")
        print(f"\n{Colors.YELLOW}💡 Check your DNS Expert Monitor terminal{Colors.END}")
        print(f"{Colors.YELLOW}   to see security alerts from this test traffic{Colors.END}")
        print(f"\n{Colors.DIM}Generated with ❤️ by DNS Expert Monitor{Colors.END}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n{Colors.RED}❌ Error: {e}{Colors.END}")
        sys.exit(1)
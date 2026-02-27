#!/usr/bin/env python3
"""
🚀 DNS Expert Monitor - Main execution script
Usage: python run.py [command] [options]

Available commands:
  monitor     - Real-time DNS monitoring
  quick       - Quick analysis (10-60 seconds)
  report      - Generate security report
  export      - Export data to multiple formats
  interfaces  - List network interfaces
  test        - Test mode (no real traffic)
  fix-json    - Repair corrupt JSON files
  analyze     - Analyze PCAP file (coming soon)
  version     - Show version
  help        - Show this help
"""
import sys
import os
import platform
import subprocess
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
    """Show home banner"""
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                                  ║
║   {Colors.BOLD}🐧 DNS EXPERT MONITOR v0.2.0{Colors.END}{Colors.CYAN}                                 ║
║   {Colors.DIM}Advanced DNS Traffic Security Analysis{Colors.END}{Colors.CYAN}                      ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)

def print_help():
    """Show detailed help"""
    print_banner()
    print(f"{Colors.BOLD}📋 AVAILABLE COMMANDS:{Colors.END}\n")
    
    commands = [
        ("🔍  monitor", "Real-time DNS monitoring with threat detection"),
        ("⚡  quick", "Quick analysis (10-60s) - ideal for testing"),
        ("📊  report", "Generate professional security report (Markdown/JSON)"),
        ("📤  export", "Export data to HTML, CSV, PCAP, YAML, JSON"),
        ("🌐  interfaces", "Show available network interfaces"),
        ("🧪  test", "Test mode - generates simulated DNS traffic"),
        ("🔧  fix-json", "Fix corrupt JSON files"),
        ("🔬  analyze", "Analyze PCAP file (coming soon)"),
        ("ℹ️   version", "Show program version"),
        ("❓  help", "Show this help"),
    ]
    
    for cmd, desc in commands:
        print(f"  {Colors.CYAN}{cmd:<15}{Colors.END} {desc}")
    
    print(f"\n{Colors.BOLD}💡 EXAMPLES:{Colors.END}")
    print(f"  {Colors.GREEN}sudo python run.py monitor --security --output capture.json{Colors.END}")
    print(f"  {Colors.GREEN}sudo python run.py quick --duration 30{Colors.END}")
    print(f"  {Colors.GREEN}python run.py report capture.json --output report.md{Colors.END}")
    print(f"  {Colors.GREEN}python run.py export capture.json --format all{Colors.END}")
    print(f"  {Colors.GREEN}python run.py fix-json --diagnostic captura.json{Colors.END}")
    
    print(f"\n{Colors.BOLD}⚙️  COMMON OPTIONS:{Colors.END}")
    print(f"  {Colors.YELLOW}--interface, -i{Colors.END}     Network interface (eth0, wlan0, etc.)")
    print(f"  {Colors.YELLOW}--output, -o{Colors.END}        Output file")
    print(f"  {Colors.YELLOW}--verbose, -v{Colors.END}       Detailed mode")
    print(f"  {Colors.YELLOW}--security, -s{Colors.END}      Enable security detection")
    print(f"  {Colors.YELLOW}--duration{Colors.END}          Duration in seconds")
    print(f"  {Colors.YELLOW}--format, -f{Colors.END}        Export format (html,json,csv,pcap,yaml,all)")
    
    print(f"\n{Colors.BOLD}🔧 TIPS:{Colors.END}")
    print(f"  • Use {Colors.CYAN}sudo{Colors.END} to capture packets: sudo python run.py monitor")
    print(f"  • If the JSON is corrupt: python run.py fix-json capture.json")
    print(f"  • For professional reports: python run.py report capture.json --output report.md")
    print(f"  • To export to Wireshark: python run.py export capture.json --format pcap")
    print()

def check_dependencies():
    """Check necessary dependencies"""
    missing = []
    
    try:
        import scapy
    except ImportError:
        missing.append("scapy")
    
    try:
        import rich
    except ImportError:
        missing.append("rich")
    
    try:
        import click
    except ImportError:
        missing.append("click")
    
    if missing:
        print(f"{Colors.RED}❌ Error: Missing dependencies{Colors.END}")
        print(f"   Install: {Colors.CYAN}pip install {' '.join(missing)}{Colors.END}")
        return False
    
    return True

def check_pcap_permissions():
    """Simple permission check for run.py"""
    if os.name != 'posix':
        return True
    
    # Si somos root, OK
    if os.geteuid() == 0:
        return True
    
    # Si no, mostrar mensaje amigable
    print(f"\n{Colors.YELLOW}⚠️  This command requires root privileges{Colors.END}")
    print(f"{Colors.CYAN}Please run with:{Colors.END} {Colors.GREEN}sudo python run.py {' '.join(sys.argv[1:])}{Colors.END}")
    print()
    return False

def setup_environment():
    """Configure the runtime environment"""
    # Add src to path
    src_path = os.path.join(os.path.dirname(__file__), 'src')
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
    
    # Verify that the module exists
    module_path = os.path.join(src_path, 'dns_expert_monitor')
    if not os.path.exists(module_path):
        print(f"{Colors.RED}❌ Error: Module 'dns_expert_monitor not found'{Colors.END}")
        print(f"   Searched in: {module_path}")
        print(f"   Run from the project root directory")
        sys.exit(1)
    
    return True

def main():
    """Main function"""
    # Configure environment
    if not setup_environment():
        sys.exit(1)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # If there are no arguments, show help
    if len(sys.argv) == 1:
        print_help()
        sys.exit(0)
    
    # Commands that do NOT require root permissions
    no_root_commands = ['report', 'export', 'interfaces', 'fix-json', 'help', 'version']
    
    # Check permissions for commands that capture
    if sys.argv[1] not in no_root_commands:
        if os.geteuid() != 0:
            print(f"\n{Colors.YELLOW}⚠️  This command requires root privileges{Colors.END}")
            print(f"{Colors.CYAN}Please run with:{Colors.END} {Colors.GREEN}sudo python run.py {' '.join(sys.argv[1:])}{Colors.END}")
            print()
            sys.exit(1)
    
    # Handle special commands
    if sys.argv[1] == 'help' or sys.argv[1] == '--help' or sys.argv[1] == '-h':
        print_help()
        sys.exit(0)
    
    if sys.argv[1] == 'version' or sys.argv[1] == '--version':
        print_banner()
        print(f"{Colors.BOLD}Versión:{Colors.END} 0.2.0")
        print(f"{Colors.BOLD}Python:{Colors.END} {platform.python_version()}")
        print(f"{Colors.BOLD}System:{Colors.END} {platform.system()} {platform.release()}")
        print(f"{Colors.BOLD}Date:{Colors.END} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        sys.exit(0)
    
    # Special command: fix-json (shortcut)
    if sys.argv[1] == 'fix-json':
        try:
            # Try to import from the module
            from dns_expert_monitor.cli import fix_json
            
            # Prepare arguments for click
            import shlex
            cmd_args = ['fix-json'] + sys.argv[2:]
            
            # Call the function directly
            sys.argv = ['dns-expert'] + cmd_args
            fix_json()
            
        except ImportError:
            # Fallback to standalone script
            script_path = os.path.join(os.path.dirname(__file__), 'fix_json.py')
            if os.path.exists(script_path):
                # Pass all arguments after 'fix-json'
                args = [sys.executable, script_path] + sys.argv[2:]
                os.execv(sys.executable, args)
            else:
                print(f"{Colors.RED}❌ Error: No se encuentra fix_json.py{Colors.END}")
                sys.exit(1)
        sys.exit(0)
    
    # Special command: export (shortcut)
    if sys.argv[1] == 'export':
        try:
            from dns_expert_monitor.visualizers import DataExporter
            # The CLI will handle this
        except ImportError:
            pass
    
    # Import and run CLI
    try:
        from dns_expert_monitor.cli import cli
        cli()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}🛑 Interrupt received. leaving...{Colors.END}")
        sys.exit(0)
    except ImportError as e:
        print(f"{Colors.RED}❌ Error importing module: {e}{Colors.END}")
        print(f"{Colors.CYAN}   Verify the installation: pip install -e .{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}❌ Unexpected error: {e}{Colors.END}")
        if '--debug' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
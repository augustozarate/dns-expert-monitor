#!/usr/bin/env python3
"""
Core CLI for DNS Expert Monitor
"""
import click
import sys
import os
import signal
import json
from typing import Any, List, Dict
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

from dns_expert_monitor.core.interface_manager import InterfaceManager
from dns_expert_monitor.core.packet_engine import DNSCaptureEngine
from dns_expert_monitor.analyzers.statistics_engine import StatisticsEngine
from dns_expert_monitor.detectors import SecurityManager

console = Console()

def json_serializer(obj: Any) -> Any:
    """Serializer for JSON that handles datetime"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def check_permissions() -> bool:
    """Simple permission check"""
    # En Windows no aplica
    if os.name != 'posix':
        return True
    
    # Si somos root, OK
    if os.geteuid() == 0:
        return True
    
    # Si no somos root, mostrar mensaje claro
    console.print("\n[bold yellow]⚠️  Root permissions required for packet capture[/bold yellow]")
    console.print("[cyan]Please run with:[/cyan] [bold]sudo dns-expert monitor[/bold]")
    console.print("[dim]Or use the run.py script:[/dim] [bold]sudo python run.py monitor[/bold]")
    console.print()
    return False

@click.group()
@click.version_option(version="0.1.0")
def cli():
    """DNS Expert Monitor - Advanced DNS traffic monitoring and security analysis"""
    pass

@cli.command(name='fix-json')
@click.argument('json_file', type=click.Path(exists=True))
def fix_json(json_file):
    """Repair a JSON file with formatting errors (basic version)"""
    import subprocess
    console.print("[yellow]ℹ️ Using basic repairer. For more options, install 'dns-fix'[/yellow]")
    
    # Call the basic repair script
    script_path = os.path.join(os.path.dirname(__file__), '..', '..', 'fix_json.py')
    if os.path.exists(script_path):
        subprocess.run(['python3', script_path, json_file])
    else:
        console.print("[red]Error: Repair script not found[/red]")

@cli.command()
@click.option('--duration', default=30, help='Test duration in seconds')
def test(duration: int):
    """Run a functionality test"""
    import time
    import threading
    
    console.print(Panel.fit(
        "[bold cyan]🧪 DNS Expert Monitor - Test Mode[/bold cyan]",
        border_style="cyan"
    ))
    
    if not check_permissions():
        sys.exit(1)
    
    # Create engine
    try:
        engine = DNSCaptureEngine()
        stats_engine = StatisticsEngine()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    
    # List of test domains
    test_domains = [
        "google.com", "github.com", "wikipedia.org",
        "example.com", "test.local", "api.example.org",
        "cdn.cloudflare.com", "mail.server.com"
    ]
    
    # Callback to show activity
    def test_callback(packet_data):
        stats_engine.add_packet(packet_data)
        
        timestamp = packet_data['timestamp'].strftime("%H:%M:%S")
        domain = packet_data.get('domain', 'unknown')
        
        if packet_data['is_query']:
            console.print(f"[{timestamp}] [blue]←[/blue] TEST: {domain}")
        else:
            console.print(f"[{timestamp}] [green]→[/green] TEST: {domain}")
    
    engine.register_callback(test_callback)
    
    # Function to generate test traffic
    def generate_test_traffic():
        """Generate test DNS traffic"""
        test_ip = "192.168.1.100"  # fictitious IP
        count = 0
        
        while getattr(threading.current_thread(), "do_run", True) and count < duration * 2:
            for domain in test_domains:
                # Create mock DNS packet
                test_packet = {
                    'timestamp': datetime.now(),
                    'src_ip': test_ip,
                    'dst_ip': "8.8.8.8",
                    'is_query': True,
                    'id': count,
                    'opcode': 0,
                    'type': 'query',
                    'domain': domain,
                    'record_type': 'A',
                    'protocol': 'UDP'
                }
                
                # Process as if it were real
                test_callback(test_packet)
                
                # Little pause
                time.sleep(0.5)
                count += 1
                
                # Mock response
                time.sleep(0.1)
                test_response = {
                    'timestamp': datetime.now(),
                    'src_ip': "8.8.8.8",
                    'dst_ip': test_ip,
                    'is_query': False,
                    'id': count,
                    'opcode': 0,
                    'rcode': 0,
                    'type': 'response',
                    'domain': domain,
                    'record_type': 'A',
                    'response_data': '93.184.216.34',  # example.com IP
                    'ttl': 300,
                    'protocol': 'UDP'
                }
                
                test_callback(test_response)
                time.sleep(0.5)
    
    # Handle Ctrl+C
    def signal_handler(sig, frame):
        console.print("\n[yellow]🛑 Stopping test...[/yellow]")
        engine.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start
    console.print(f"[bold]🎯 Using interface:[/bold] [cyan]{engine.interface}[/cyan]")
    console.print(f"[yellow]🧪 Generating test traffic for {duration} seconds...[/yellow]")
    console.print("[yellow]🛑 Press [bold]Ctrl+C[/bold] to stop[/yellow]\n")
    
    engine.start()
    
    # Thread to generate traffic
    traffic_thread = threading.Thread(target=generate_test_traffic)
    traffic_thread.do_run = True
    traffic_thread.daemon = True
    traffic_thread.start()
    
    # Wait
    try:
        time.sleep(duration)
        traffic_thread.do_run = False
        traffic_thread.join(timeout=2)
        
        console.print("\n[bold]📊 Test completed:[/bold]")
        summary = stats_engine.get_summary()
        
        table = Table(box=None)
        table.add_column("Metrics", style="cyan")
        table.add_column("Values", style="green")
        
        table.add_row("Queries generated", str(summary['counters']['queries']))
        table.add_row("Responses generated", str(summary['counters']['responses']))
        table.add_row("Average QPS", f"{summary['rates']['queries_per_second']:.2f}")
        table.add_row("Test domains", str(len(test_domains)))
        
        console.print(table)
        
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    
    finally:
        engine.stop()

@cli.command()
def interfaces():
    """Shows all available network interfaces"""
    console.print(Panel.fit(
        "[bold cyan]🔍 DNS Expert Monitor - Network Interfaces[/bold cyan]",
        border_style="cyan"
    ))
    
    try:
        manager = InterfaceManager()
        manager.print_interfaces_table()
        
        default = manager.get_default_interface()
        if default:
            console.print(f"\n[yellow]🎯 Recommended interface:[/yellow] [bold]{default}[/bold]")
        else:
            console.print("\n[red]⚠️ Could not determine default interface[/red]")
            
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print("[yellow]Asegúrate de tener instalado netifaces[/yellow]")

@cli.command()
@click.option('--interface', '-i', help='Network interface to use')
@click.option('--verbose', '-v', is_flag=True, help='Detailed mode')
@click.option('--stats', is_flag=True, help='Show statistics in real time')
@click.option('--output', '-o', help='File to save capture (JSON)')
@click.option('--security', '-s', is_flag=True, help='Enable security detection')
@click.option('--config', '-c', help='YAML configuration file for listeners')
def monitor(interface, verbose, stats, output, security, config):
    """Start real-time DNS monitoring"""
    
    if not check_permissions():
        sys.exit(1)
    
    # Banner
    console.print(Panel.fit(
        "[bold green]🚀 DNS Expert Monitor[/bold green]\n"
        "[yellow]Real-time DNS monitoring[/yellow]",
        border_style="green"
    ))
    
    try:
        # Create components
        engine = DNSCaptureEngine(interface)
        stats_engine = StatisticsEngine()
        
        # Initialize security manager if enabled
        security_manager = None
        if security:
            security_manager = SecurityManager(config)
            console.print("[green]🔒 Security detection enabled[/green]")
        
        # Set output file if specified
        output_file = None
        packet_count = 0
        if output:
            try:
                output_file = open(output, 'w', encoding='utf-8')
                output_file.write("[\n")
                console.print(f"[green]📁 Saving capture to: {output}[/green]")
            except Exception as e:
                console.print(f"[red]Error opening file: {e}[/red]")
                output_file = None
        
        # Callback for processing
        def process_packet(packet_data):
            """Processes each captured DNS packet"""
            nonlocal packet_count
            
            # Update statistics
            stats_engine.add_packet(packet_data)
            
            # Security detection
            security_alerts = []
            if security_manager:
                security_alerts = security_manager.analyze_packet(packet_data)
                
                # Show security alerts
                for alert in security_alerts:
                    severity = alert.get('severity', 'medium')
                    message = alert.get('message', '')
                    
                    if severity == 'high':
                        console.print(f"[bold red]🚨 ALERT: {message}[/bold red]")
                    elif severity == 'medium':
                        console.print(f"[bold yellow]⚠️  WARNING: {message}[/bold yellow]")
                    elif verbose:  # Show low alerts only in verbose
                        console.print(f"[blue]ℹ️  INFO: {message}[/blue]")
            
            # Show basic activity (without --verbose)
            if not verbose and not stats and not security_alerts:
                timestamp = packet_data['timestamp'].strftime("%H:%M:%S")
                domain = packet_data.get('domain', 'unknown')
                
                # Shorten long domains
                if len(domain) > 40:
                    display_domain = domain[:37] + "..."
                else:
                    display_domain = domain
                
                if packet_data['is_query']:
                    # Only show every 5th query to avoid saturation
                    if stats_engine.counters['queries'] % 5 == 0:
                        console.print(f"[{timestamp}] [blue]←[/blue] {display_domain}")
                else:
                    rcode = packet_data.get('rcode', 0)
                    if rcode == 0:  # Only show successful answers
                        if stats_engine.counters['responses'] % 5 == 0:
                            console.print(f"[{timestamp}] [green]→[/green] {display_domain}")
            
            # Show in verbose
            if verbose:
                timestamp = packet_data['timestamp'].strftime("%H:%M:%S.%f")[:-3]
                src = packet_data['src_ip']
                dst = packet_data['dst_ip']
                domain = packet_data.get('domain', 'unknown')
                rtype = packet_data.get('record_type', 'unknown')
                
                if packet_data['is_query']:
                    console.print(f"[{timestamp}] [blue]←[/blue] {src:15} → {dst:15} [cyan]QUERY[/cyan] {domain:40} ({rtype})")
                else:
                    rcode = packet_data.get('rcode', 0)
                    rcode_text = "OK" if rcode == 0 else f"ERR:{rcode}"
                    console.print(f"[{timestamp}] [green]→[/green] {src:15} ← {dst:15} [yellow]RESP[/yellow] {domain:40} [{rcode_text}]")
            
            # Save to file if enabled
            if output_file:
                try:
                    # Convert to serializable JSON
                    json_data = packet_data.copy()
                    json_data['timestamp'] = json_data['timestamp'].isoformat()
                    if 'raw_packet' in json_data:
                        del json_data['raw_packet']
                    
                    # Add security alerts if any
                    if security_alerts:
                        json_data['security_alerts'] = security_alerts
                    
                    # Write JSON line
                    json_line = json.dumps(json_data, ensure_ascii=False, default=json_serializer)
                    
                    # If it is not the first element, add a comma before
                    if packet_count > 0:
                        output_file.write(",\n")
                    
                    output_file.write(json_line)
                    packet_count += 1
                    
                except Exception as e:
                    console.print(f"[yellow]⚠️  Error saving package: {e}[/yellow]")
        
        # Register callback
        engine.register_callback(process_packet)
        
        # Handle Ctrl+C
        def signal_handler(sig, frame):
            console.print("\n[yellow]🛑 Interrupt signal received...[/yellow]")
            engine.stop()
            
            # Close output file
            if output_file:
                try:
                    output_file.write("\n]")
                    output_file.close()
                    console.print(f"[green]💾 Capture saved in: {output}[/green]")
                    console.print(f"[green]📄 {packet_count} saved packages[/green]")
                    
                    # Verify that the JSON is valid
                    try:
                        with open(output, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        console.print(f"[green]✅ Validated JSON file ({len(data)} records)[/green]")
                    except json.JSONDecodeError as e:
                        console.print(f"[yellow]⚠️  JSON file might have errors: {e}[/yellow]")
                        
                except Exception as e:
                    console.print(f"[yellow]⚠️  Error closing file: {e}[/yellow]")
                    try:
                        output_file.close()
                    except:
                        pass
            
            # Show final statistics
            console.print("\n[bold cyan]📈 CAPTURE SUMMARY[/bold cyan]")

            summary = stats_engine.get_summary()

            # Main table
            main_table = Table(show_header=True, box=None)
            main_table.add_column("Metrics", style="cyan", no_wrap=True)
            main_table.add_column("Values", style="green")

            main_table.add_row("Total duration", 
                            f"{summary['duration']['minutes']}m {summary['duration']['seconds']}s")
            main_table.add_row("DNS packets", 
                            f"{summary['counters']['total_packets']:,}")
            main_table.add_row("Queries → Responses", 
                            f"{summary['counters']['queries']:,} → {summary['counters']['responses']:,}")
            main_table.add_row("Balance", 
                            f"{summary['counters']['queries'] - summary['counters']['responses']:,}")
            main_table.add_row("Tasa (QPS)", 
                            f"{summary['rates']['queries_per_second']:.2f}")
            main_table.add_row("Errors", 
                            f"{summary['counters'].get('errors', 0):,}")

            console.print(main_table)
            
            # Show security summary if enabled
            if security_manager:
                console.print("\n[bold red]🔒 SECURITY SUMMARY[/bold red]")
                security_summary = security_manager.get_alerts_summary()
                
                if security_summary['total_alerts'] > 0:
                    sec_table = Table(title="Security Alerts", box=None)
                    sec_table.add_column("Type", style="cyan")
                    sec_table.add_column("Quantity", style="red", justify="right")
                    
                    for alert_type, count in security_summary.get('by_type', {}).items():
                        sec_table.add_row(alert_type, str(count))
                    
                    console.print(sec_table)
                    
                    # Show detector summaries
                    detector_summary = security_manager.get_detector_summary()
                    console.print("\n[bold yellow]Active detectors:[/bold yellow]")
                    for name, summary_info in detector_summary.items():
                        console.print(f"  • {name}: {summary_info}")
                else:
                    console.print("[green]✅ No security threats detected[/green]")

            # Top domains if there is data
            if stats_engine.distributions['domains']:
                top_domains = stats_engine.get_top_items('domains', 5)
                
                if top_domains:
                    domains_table = Table(title="🏆 Top 5 Domains", box=None)
                    domains_table.add_column("#", style="dim", width=3)
                    domains_table.add_column("Domain", style="yellow")
                    domains_table.add_column("Queries", style="green", justify="right")
                    
                    for idx, (domain, count) in enumerate(top_domains, 1):
                        if len(domain) > 35:
                            domain = domain[:32] + "..."
                        domains_table.add_row(str(idx), domain, f"{count:,}")
                    
                    console.print(domains_table)

            # Distribution of record types
            if stats_engine.distributions['record_types']:
                record_types = stats_engine.get_top_items('record_types', 5)
                
                if record_types:
                    types_table = Table(title="🔧 Record Types", box=None)
                    types_table.add_column("Type", style="magenta")
                    types_table.add_column("Amount", style="green", justify="right")
                    
                    for rtype, count in record_types:
                        types_table.add_row(rtype, f"{count:,}")
                    
                    console.print(types_table)
            
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start capture
        console.print(f"[bold]🎯 Using interface:[/bold] [cyan]{engine.interface}[/cyan]")
        console.print("[yellow]📡 Capturing DNS traffic... (perform DNS queries to see activity)[/yellow]")
        console.print("[yellow]🛑 Press [bold]Ctrl+C[/bold] to stop[/yellow]\n")
        
        engine.start()
        
        # Main loop
        try:
            while engine.running:
                if stats:
                    # Show live statistics
                    with Live(refresh_per_second=2) as live:
                        while engine.running:
                            summary = stats_engine.get_summary()
                            
                            stats_table = Table(title="📊 Real Time Statistics", box=None)
                            stats_table.add_column("Metrics", style="cyan")
                            stats_table.add_column("Value", style="green")
                            
                            stats_table.add_row("Duration", f"{summary['duration']['minutes']}m {summary['duration']['seconds']}s")
                            stats_table.add_row("Queries", str(summary['counters']['queries']))
                            stats_table.add_row("Answers", str(summary['counters']['responses']))
                            stats_table.add_row("QPS", f"{summary['rates']['queries_per_second']:.2f}")
                            stats_table.add_row("QPM", f"{summary['rates']['queries_per_minute']:.0f}")
                            
                            live.update(stats_table)
                            signal.pause()
                else:
                    signal.pause()
                    
        except KeyboardInterrupt:
            signal_handler(signal.SIGINT, None)
    
    except Exception as e:
        console.print(f"[red]❌ Error: {type(e).__name__}: {str(e)}[/red]")
        sys.exit(1)

@cli.command()
@click.option('--duration', default=10, help='Capture seconds')
@click.option('--interface', '-i', help='Interface to use')
@click.option('--output', '-o', help='File to save capture (JSON)')
@click.option('--security', '-s', is_flag=True, help='Enable security detection')
@click.option('--config', '-c', help='YAML configuration file for listeners')
@click.option('--verbose', '-v', is_flag=True, help='Detailed mode')
def quick(duration, interface, output, security, config, verbose):
    """Quick capture and display analysis"""
    if not check_permissions():
        sys.exit(1)
    
    console.print(Panel.fit(
        f"[bold green]⚡ Quick Analysis ({duration}s)[/bold green]",
        border_style="green"
    ))
    
    import time
    from threading import Event
    import json
    
    try:
        # Create components
        engine = DNSCaptureEngine(interface)
        stats_engine = StatisticsEngine()
        
        # Initialize security manager if enabled
        security_manager = None
        if security:
            security_manager = SecurityManager(config)
            console.print("[green]🔒 Security detection enabled[/green]")
        
        # Set output file if specified
        output_file = None
        packet_count = 0
        if output:
            try:
                output_file = open(output, 'w', encoding='utf-8')
                output_file.write("[\n")
                console.print(f"[green]📁 Saving screenshot to: {output}[/green]")
            except Exception as e:
                console.print(f"[red]Error opening file: {e}[/red]")
                output_file = None
        
        # Callback for fast processing
        def quick_callback(packet_data):
            nonlocal packet_count
            stats_engine.add_packet(packet_data)
            
            # Security detection
            security_alerts = []
            if security_manager:
                security_alerts = security_manager.analyze_packet(packet_data)
                
                # Show security alerts
                for alert in security_alerts:
                    severity = alert.get('severity', 'medium')
                    message = alert.get('message', '')
                    
                    if severity == 'high':
                        console.print(f"[bold red]🚨 ALERT: {message}[/bold red]")
                    elif severity == 'medium':
                        console.print(f"[bold yellow]⚠️  WARNING: {message}[/bold yellow]")
                    elif verbose:  # Show low alerts only in verbose
                        console.print(f"[blue]ℹ️  INFO: {message}[/blue]")
            
            # Show activity in verbose
            if verbose:
                timestamp = packet_data['timestamp'].strftime("%H:%M:%S")
                domain = packet_data.get('domain', 'unknown')
                if packet_data['is_query']:
                    console.print(f"[{timestamp}] [blue]←[/blue] QUERY: {domain}")
                else:
                    console.print(f"[{timestamp}] [green]→[/green] RESP: {domain}")
            
            # Save to file if enabled
            if output_file:
                try:
                    json_data = packet_data.copy()
                    json_data['timestamp'] = json_data['timestamp'].isoformat()
                    if 'raw_packet' in json_data:
                        del json_data['raw_packet']
                    
                    if security_alerts:
                        json_data['security_alerts'] = security_alerts
                    
                    json_line = json.dumps(json_data, ensure_ascii=False, default=json_serializer)
                    
                    if packet_count > 0:
                        output_file.write(",\n")
                    output_file.write(json_line)
                    packet_count += 1
                    
                except Exception as e:
                    if verbose:
                        console.print(f"[yellow]⚠️ Error saving: {e}[/yellow]")
        
        engine.register_callback(quick_callback)
        
        console.print(f"[cyan]🎯 Capturing on {engine.interface} for {duration} seconds...[/cyan]")
        if not verbose:
            console.print("[yellow]Use --verbose to see real-time activity[/yellow]")
        console.print("")
        
        # Progress bar
        from rich.progress import Progress
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Capturing...", total=duration)
            
            engine.start()
            
            for _ in range(duration):
                time.sleep(1)
                progress.update(task, advance=1)
            
            engine.stop()
        
        # Close output file
        if output_file:
            try:
                output_file.write("\n]")
                output_file.close()
                console.print(f"[green]💾 Capture saved in: {output}[/green]")
                console.print(f"[green]📄 {packet_count} saved packages[/green]")
            except Exception as e:
                console.print(f"[yellow]⚠️ Error closing file: {e}[/yellow]")
        
        # Show analysis
        console.print("\n[bold cyan]📊 QUICK ANALYSIS[/bold cyan]")
        
        summary = stats_engine.get_summary()
        
        if summary['counters']['total_packets'] == 0:
            console.print("[yellow]⚠️ No DNS traffic captured[/yellow]")
            console.print("[white]Suggestions:[/white]")
            console.print("  • Open a browser and visit a web page")
            console.print("  • Run: ping google.com")
            console.print("  • Run: nslookup example.com")
            return
        
        # Metrics table
        metrics = Table(box=None)
        metrics.add_column("Metrics", style="cyan")
        metrics.add_column("Value", style="green")
        
        metrics.add_row("Total DNS traffic", 
                       f"{summary['counters']['total_packets']:,} packages")
        metrics.add_row("Queries/Responses", 
                       f"{summary['counters']['queries']:,} / {summary['counters']['responses']:,}")
        metrics.add_row("Tasa (QPS)", 
                       f"{summary['rates']['queries_per_second']:.2f}")
        metrics.add_row("Unique clients", 
                       f"{len(stats_engine.distributions['clients']):,}")
        metrics.add_row("Unique domains", 
                       f"{len(stats_engine.distributions['domains']):,}")
        
        console.print(metrics)
        
        # Show security summary if enabled
        if security_manager:
            console.print("\n[bold red]🔒 SECURITY SUMMARY[/bold red]")
            security_summary = security_manager.get_alerts_summary()
            
            if security_summary['total_alerts'] > 0:
                sec_table = Table(title="Security Alerts", box=None)
                sec_table.add_column("Type", style="cyan")
                sec_table.add_column("Amount", style="red", justify="right")
                
                for alert_type, count in security_summary.get('by_type', {}).items():
                    sec_table.add_row(alert_type, str(count))
                
                console.print(sec_table)
                
                # Show detector summaries
                detector_summary = security_manager.get_detector_summary()
                console.print("\n[bold yellow]Active detectors:[/bold yellow]")
                for name, summary_info in detector_summary.items():
                    console.print(f"  • {name}: {summary_info}")
            else:
                console.print("[green]✅ No security threats detected[/green]")
        
        # Basic alerts
        alerts = []
        
        # Check query/response ratio
        if summary['counters']['queries'] > 0:
            ratio = summary['counters']['responses'] / summary['counters']['queries']
            if ratio < 0.8:
                alerts.append(f"⚠️ Low response rate: {ratio:.1%} (expected ~100%)")
        
        # Check high rate
        if summary['rates']['queries_per_second'] > 50:
            alerts.append(f"🚨 High consultation rate: {summary['rates']['queries_per_second']:.1f} QPS")
        
        # Show alerts
        if alerts:
            console.print("\n[bold yellow]🔔 ALERTS:[/bold yellow]")
            for alert in alerts:
                console.print(f"  • {alert}")
        
        # Top 3 domains
        top_domains = stats_engine.get_top_items('domains', 3)
        if top_domains:
            console.print("\n[bold cyan]🔝 Most consulted domains:[/bold cyan]")
            for domain, count in top_domains:
                display_domain = domain[:40] + "..." if len(domain) > 40 else domain
                console.print(f"  • {display_domain}: {count:,}")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if '--debug' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)

@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--format', '-f', default='html', 
              type=click.Choice(['html', 'json', 'csv', 'yaml', 'pcap', 'all']),
              help='Export format')
@click.option('--output', '-o', help='Output file (no extension)')
def export(input_file, format, output):
    """Export DNS data from JSON file"""
    import json
    import os
    from dns_expert_monitor.visualizers import DataExporter
    
    console.print(Panel.fit(
        f"[bold cyan]📤 Exporting DNS data[/bold cyan]",
        border_style="cyan"
    ))
    
    try:
        # Load data
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        console.print(f"[green]✓[/green] Loaded {len(data)} records from {input_file}")
        
        # Determine output name
        if not output:
            basename = os.path.splitext(input_file)[0]
        else:
            basename = output
        
        # Export
        if format == 'all':
            results = DataExporter.export_all(data, basename)
            
            console.print("\n[bold green]📊 Export completed:[/bold green]")
            for fmt, success in results.items():
                status = "✅" if success else "❌"
                console.print(f"  {status} {fmt.upper()}")
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if format == 'html':
                filename = f"{basename}.html"
                success = DataExporter.to_html_report(data, filename)
            elif format == 'json':
                filename = f"{basename}.json"
                success = DataExporter.to_json(data, filename)
            elif format == 'csv':
                filename = f"{basename}.csv"
                success = DataExporter.to_csv(data, filename)
            elif format == 'yaml':
                filename = f"{basename}.yaml"
                success = DataExporter.to_yaml(data, filename)
            elif format == 'pcap':
                filename = f"{basename}.pcap"
                success = DataExporter.to_pcap(data, filename)
            
            if success:
                console.print(f"[bold green]✅ Exported to {format.upper()}: {filename}[/bold green]")
            else:
                console.print(f"[bold red]❌ Error exporting to {format.upper()}[/bold red]")
    
    except json.JSONDecodeError as e:
        console.print(f"[red]❌ Error in JSON file: {e}[/red]")
        console.print("[yellow]💡 Tip: Use 'python fix_json.py <file>' to fix it[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        if '--debug' in sys.argv:
            import traceback
            traceback.print_exc()

@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', '-o', help='Report output file')
@click.option('--format', '-f', type=click.Choice(['md', 'markdown', 'json']), 
              default='md', help='Report format (md/markdown o json)')
def report(input_file, output, format):
    """Generate professional security report"""
    import json
    import os
    from dns_expert_monitor.visualizers import (
        ReportGenerator, 
        create_tunneling_finding,
        create_poisoning_finding,
        create_amplification_finding
    )
    
    console.print(Panel.fit(
        "[bold cyan]📋 Generating Security Report[/bold cyan]",
        border_style="cyan"
    ))
    
    try:
        # Load data
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        console.print(f"[green]✓[/green] Parsing {len(data)} records...")
        
        # Create report
        report = ReportGenerator("DNS Security Analysis Report")
        report.generate_statistics(data)
        
        # Extract security findings from data
        security_alerts = []
        for item in data:
            if 'security_alerts' in item:
                for alert in item['security_alerts']:
                    alert['timestamp'] = item.get('timestamp', datetime.now().isoformat())
                    alert['source_ip'] = item.get('src_ip', 'unknown')
                    security_alerts.append(alert)
        
        # Convert alerts to findings
        for alert in security_alerts:
            if alert.get('type') in ['high_entropy', 'base64_pattern']:
                report.add_finding(create_tunneling_finding(
                    domain=alert.get('details', {}).get('domain', 'unknown'),
                    entropy=alert.get('details', {}).get('entropy', 0),
                    client_ip=alert.get('source_ip', 'unknown')
                ))
            elif alert.get('type') == 'low_ttl':
                report.add_finding(create_poisoning_finding(
                    domain=alert.get('details', {}).get('domain', 'unknown'),
                    ttl=alert.get('details', {}).get('ttl', 0),
                    server_ip=alert.get('details', {}).get('server', 'unknown')
                ))
            elif alert.get('type') == 'high_query_rate':
                report.add_finding(create_amplification_finding(
                    client_ip=alert.get('details', {}).get('client', 'unknown'),
                    qps=alert.get('details', {}).get('qps', 0),
                    ratio=alert.get('details', {}).get('amplification_ratio', 0)
                ))
        
        report.generate_executive_summary()
        
        # Show in console
        console.print("\n" + "="*60)
        report.print_console_report()
        
        # Save according to format
        if output:
            if format in ['md', 'markdown']:
                if not output.endswith('.md'):
                    output = f"{output}.md"
                report.save_report(output, "markdown")
            elif format == 'json':
                if not output.endswith('.json'):
                    output = f"{output}.json"
                report.save_report(output, "json")
        else:
            # Default name
            basename = os.path.splitext(input_file)[0]
            if format in ['md', 'markdown']:
                output = f"{basename}_report.md"
                report.save_report(output, "markdown")
            else:
                output = f"{basename}_report.json"
                report.save_report(output, "json")
        
        console.print(f"[green]✓[/green] Report saved as: {output}")
    
    except json.JSONDecodeError as e:
        console.print(f"[red]❌ Error in JSON file: {e}[/red]")
        console.print("[yellow]💡 Tip: Run 'python fix_json.py {}' to fix it[/yellow]".format(input_file))
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        if '--debug' in sys.argv:
            import traceback
            traceback.print_exc()

@cli.command()
@click.argument('pcap_file', type=click.Path(exists=True))
def analyze(pcap_file):
    """Analyze an existing PCAP file"""
    console.print(Panel.fit(
        f"[bold cyan]🔍 Analyzing PCAP: {pcap_file}[/bold cyan]",
        border_style="cyan"
    ))
    
    console.print("[yellow]⏳ This functionality will be available in the next version...[/yellow]")
    console.print("\n[bold]Planned for v0.2.0:[/bold]")
    console.print("  • Complete PCAP file analysis")
    console.print("  • Anomaly detection")
    console.print("  • HTML report generation")
    console.print("  • Advanced statistics")

@cli.command()
@click.argument('json_file', type=click.Path(exists=True))
def fix_json(json_file):
    """Repair a JSON file with formatting errors"""
    console.print(Panel.fit(
        f"[bold cyan]🔧 Repairing JSON file: {json_file}[/bold cyan]",
        border_style="cyan"
    ))
    
    try:
        # Read as text
        with open(json_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Common repairs
        import re
        
        # 1. Remove commas before closing brackets
        content = re.sub(r',\s*\]', ']', content)
        content = re.sub(r',\s*\}', '}', content)
        
        # 2. Ensure that it ends with ]
        content = content.strip()
        if not content.endswith(']'):
            if content.endswith(','):
                content = content[:-1] + ']'
            else:
                content += ']'
        
        # 3. Parse to verify that it is valid
        data = json.loads(content)
        
        # 4. Save repaired
        backup_file = json_file + '.bak'
        import os
        os.rename(json_file, backup_file)
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=json_serializer)
        
        console.print(f"[green]✅ JSON fixed successfully[/green]")
        console.print(f"[dim]   Original saved as: {backup_file}[/dim]")
        console.print(f"[dim]   Records: {len(data)}[/dim]")
        
    except json.JSONDecodeError as e:
        console.print(f"[red]❌ Error repairing JSON: {e}[/red]")
        console.print("[yellow]Try to repair it manually or generate a new screenshot[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")

if __name__ == "__main__":
    cli()
"""
Real-time dashboard for DNS traffic visualization
"""
from typing import Dict, List, Any, Optional
import time
from datetime import datetime, timedelta
from collections import deque

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn

console = Console()

class RealtimeDashboard:
    """Interactive dashboard for real-time DNS monitoring"""
    
    def __init__(self, title: str = "DNS Expert Monitor Dashboard"):
        self.title = title
        self.stats_history = deque(maxlen=100)  # Keep last 100 points
        self.start_time = datetime.now()
        self.alert_history = deque(maxlen=20)   # Last 20 alerts
        self.top_domains = {}
        self.top_clients = {}
        
        # Update settings
        self.update_interval = 1.0  # seconds
        self.last_update = time.time()
        
        # Layout
        self.layout = Layout()
        self._setup_layout()
    
    def _setup_layout(self):
        """Configure the dashboard layout"""
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=2),
            Layout(name="footer", size=3)
        )
        
        self.layout["main"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1)
        )
        
        self.layout["left"].split(
            Layout(name="stats", size=8),
            Layout(name="traffic", ratio=1)
        )
        
        self.layout["right"].split(
            Layout(name="alerts", ratio=1),
            Layout(name="domains", size=10)
        )
    
    def update(self, stats: Dict[str, Any], 
              new_packets: Optional[List[Dict[str, Any]]] = None,
              alerts: Optional[List[Dict[str, Any]]] = None):
        """Update the dashboard with new data"""
        
        # Update statistics history
        self.stats_history.append({
            'timestamp': datetime.now(),
            'queries': stats.get('queries', 0),
            'responses': stats.get('responses', 0),
            'qps': stats.get('queries_per_second', 0)
        })
        
        # Update top domains and clients
        if new_packets:
            for packet in new_packets[-10:]:  # Last 10 packages
                domain = packet.get('domain', '')
                client = packet.get('src_ip', '')
                
                if domain and domain != 'unknown':
                    self.top_domains[domain] = self.top_domains.get(domain, 0) + 1
                
                if client and client != 'unknown':
                    self.top_clients[client] = self.top_clients.get(client, 0) + 1
        
        # Update alerts
        if alerts:
            for alert in alerts[-5:]:  # Last 5 alerts
                self.alert_history.append({
                    'timestamp': datetime.now(),
                    'type': alert.get('type', 'unknown'),
                    'severity': alert.get('severity', 'medium'),
                    'message': alert.get('message', '')
                })
    
    def render(self) -> Layout:
        """Render the entire dashboard"""
        current_time = datetime.now()
        duration = current_time - self.start_time
        
        # HEADER
        header_text = Text(f"🚀 {self.title}", style="bold cyan")
        header_text.append(f"\n⏱️ Duration: {self._format_duration(duration)} | ", style="yellow")
        header_text.append(f"🕐 {current_time.strftime('%H:%M:%S')}", style="green")
        
        self.layout["header"].update(
            Panel(header_text, border_style="cyan")
        )
        
        # STATS PANEL
        stats_table = self._create_stats_table()
        self.layout["stats"].update(
            Panel(stats_table, title="📊 Real-time Statistics", border_style="green")
        )
        
        # TRAFFIC GRAPH
        traffic_text = self._create_traffic_graph()
        self.layout["traffic"].update(
            Panel(traffic_text, title="📈 Traffic Graph", border_style="blue")
        )
        
        # ALERTS PANEL
        alerts_panel = self._create_alerts_panel()
        self.layout["alerts"].update(
            Panel(alerts_panel, title="🛡️ Security Alerts", border_style="red")
        )
        
        # DOMAINS PANEL
        domains_panel = self._create_domains_panel()
        self.layout["domains"].update(
            Panel(domains_panel, title="🌐 Top Domains", border_style="yellow")
        )
        
        # FOOTER
        footer_text = Text("🛑 Press Ctrl+C to stop | ", style="dim")
        footer_text.append("🔍 DNS Expert Monitor v0.2.0", style="bold")
        
        self.layout["footer"].update(
            Panel(footer_text, border_style="dim")
        )
        
        return self.layout
    
    def _create_stats_table(self) -> Table:
        """Create real-time statistics table"""
        table = Table(show_header=False, box=None)
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="green")
        
        # Calculate history statistics
        if self.stats_history:
            recent_stats = list(self.stats_history)[-10:]  # Last 10 points
            avg_qps = sum(s['qps'] for s in recent_stats) / len(recent_stats) if recent_stats else 0
            total_queries = sum(s['queries'] for s in self.stats_history)
            total_responses = sum(s['responses'] for s in self.stats_history)
        else:
            avg_qps = 0
            total_queries = 0
            total_responses = 0
        
        table.add_row("Total Queries", f"{total_queries:,}")
        table.add_row("Total Responses", f"{total_responses:,}")
        table.add_row("Current QPS", f"{avg_qps:.1f}")
        table.add_row("Active Clients", f"{len(self.top_clients):,}")
        table.add_row("Unique Domains", f"{len(self.top_domains):,}")
        table.add_row("Active Alerts", f"{len(self.alert_history):,}")
        
        return table
    
    def _create_traffic_graph(self) -> Text:
        """Create ASCII traffic graph"""
        if not self.stats_history:
            return Text("No traffic data yet", style="dim")
        
        # Take last 20 points for the graph
        recent_stats = list(self.stats_history)[-20:]
        if not recent_stats:
            return Text("Collecting data...", style="dim")
        
        # Find maximum value to scale
        max_qps = max(s['qps'] for s in recent_stats)
        if max_qps == 0:
            max_qps = 1
        
        text = Text()
        for i, stats in enumerate(recent_stats):
            # Proportional bar
            bar_length = int((stats['qps'] / max_qps) * 20)
            bar = "█" * bar_length + "░" * (20 - bar_length)
            
            time_label = f"{i*5}s" if i % 2 == 0 else ""
            
            text.append(f"{time_label:>4} ", style="dim")
            text.append(f"{bar} ", style="cyan")
            text.append(f"{stats['qps']:.1f} QPS\n", style="green")
        
        return text
    
    def _create_alerts_panel(self):
        """Create security alert panel"""
        if not self.alert_history:
            return Text("✅ No security alerts", style="green")
        
        text = Text()
        for alert in list(self.alert_history)[-5:]:  # Last 5 alerts
            time_str = alert['timestamp'].strftime("%H:%M:%S")
            
            # Color by severity
            if alert['severity'] == 'high':
                style = "bold red"
                prefix = "🚨 "
            elif alert['severity'] == 'medium':
                style = "bold yellow"
                prefix = "⚠️  "
            else:
                style = "blue"
                prefix = "ℹ️  "
            
            # Truncate long message
            message = alert['message']
            if len(message) > 40:
                message = message[:37] + "..."
            
            text.append(f"{prefix}[{time_str}] ", style=style)
            text.append(f"{message}\n", style=style)
        
        return text
    
    def _create_domains_panel(self):
        """Create top domains panel"""
        if not self.top_domains:
            return Text("No domain queries yet", style="dim")
        
        # Sort domains by frequency
        sorted_domains = sorted(
            self.top_domains.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:5]  # Top 5
        
        text = Text()
        for i, (domain, count) in enumerate(sorted_domains, 1):
            # Truncate long domains
            display_domain = domain
            if len(domain) > 25:
                display_domain = domain[:22] + "..."
            
            text.append(f"{i}. ", style="bold")
            text.append(f"{display_domain:<28}", style="yellow")
            text.append(f"{count:>4}\n", style="green")
        
        return text
    
    def _format_duration(self, duration: timedelta) -> str:
        """Format duration for display"""
        hours, remainder = divmod(duration.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if hours > 0:
            return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
        elif minutes > 0:
            return f"{int(minutes)}m {int(seconds)}s"
        else:
            return f"{int(seconds)}s"
    
    def run_live(self, update_callback, refresh_rate: float = 1.0):
        """Run the dashboard in live mode"""
        self.update_interval = refresh_rate
        
        with Live(self.render(), refresh_per_second=1/refresh_rate, screen=True) as live:
            try:
                while True:
                    # Call callback to get new data
                    stats, packets, alerts = update_callback()
                    
                    # Update dashboard
                    self.update(stats, packets, alerts)
                    
                    # Render
                    live.update(self.render())
                    
                    time.sleep(refresh_rate)
                    
            except KeyboardInterrupt:
                console.print("\n[yellow]Dashboard stopped[/yellow]")


class SimpleDashboard:
    """Simplified dashboard for basic use"""
    
    @staticmethod
    def show_compact(stats: Dict[str, Any], alerts: List[Dict[str, Any]] = None):
        """Display a compact dashboard in a single update"""
        console = Console()
        
        # Statistics panel
        stats_table = Table(title="📊 DNS Traffic Summary", box=None)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")
        
        stats_table.add_row("Duration", f"{stats.get('duration_minutes', 0)}m {stats.get('duration_seconds', 0)}s")
        stats_table.add_row("Total Packets", f"{stats.get('total_packets', 0):,}")
        stats_table.add_row("Queries/Responses", f"{stats.get('queries', 0):,}/{stats.get('responses', 0):,}")
        stats_table.add_row("Current QPS", f"{stats.get('queries_per_second', 0):.1f}")
        stats_table.add_row("Unique Domains", f"{stats.get('unique_domains', 0):,}")
        stats_table.add_row("Unique Clients", f"{stats.get('unique_clients', 0):,}")
        
        console.print(stats_table)
        
        # Alert panel if they exist
        if alerts:
            alerts_table = Table(title="🛡️ Security Alerts", box=None)
            alerts_table.add_column("Time", style="dim", width=8)
            alerts_table.add_column("Type", style="cyan")
            alerts_table.add_column("Message", style="yellow")
            alerts_table.add_column("Severity", style="red")
            
            for alert in alerts[-5:]:  # Last 5 alerts
                time_str = alert.get('timestamp', '--:--:--')
                if hasattr(time_str, 'strftime'):
                    time_str = time_str.strftime("%H:%M:%S")
                
                alerts_table.add_row(
                    time_str[-8:],
                    alert.get('type', 'unknown')[:15],
                    alert.get('message', '')[:30],
                    alert.get('severity', 'medium')
                )
            
            console.print(alerts_table)
        
        # Top domains panel
        if stats.get('top_domains'):
            domains_table = Table(title="🌐 Top Domains", box=None)
            domains_table.add_column("#", style="dim", width=3)
            domains_table.add_column("Domain", style="yellow")
            domains_table.add_column("Queries", style="green")
            
            for idx, (domain, count) in enumerate(stats['top_domains'][:5], 1):
                display_domain = domain[:25] + "..." if len(domain) > 25 else domain
                domains_table.add_row(str(idx), display_domain, str(count))
            
            console.print(domains_table)
"""
Professional report generator for DNS analysis
"""
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import statistics

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()

class ReportSeverity(Enum):
    """Severity levels for reports"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityFinding:
    """Individual Safety Finding"""
    id: str
    title: str
    description: str
    severity: ReportSeverity
    evidence: List[Dict[str, Any]]
    recommendation: str
    timestamp: datetime
    detector: str
    
    def to_dict(self):
        """Convert to dictionary"""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['timestamp'] = self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp)
        return data

class ReportGenerator:
    """Generate professional DNS analysis reports"""
    
    def __init__(self, title: str = "DNS Security Analysis Report"):
        self.title = title
        self.findings: List[SecurityFinding] = []
        self.metadata: Dict[str, Any] = {}
        self.statistics: Dict[str, Any] = {}
        self.executive_summary: str = ""
    
    def _parse_timestamp(self, ts: Any) -> Optional[datetime]:
        """Convert timestamp to datetime object"""
        if ts is None:
            return None
        
        # If it is already datetime
        if isinstance(ts, datetime):
            return ts
        
        # If it is ISO string
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                try:
                    # Try common format
                    return datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%f')
                except (ValueError, TypeError):
                    return None
        
        return None
    
    def add_finding(self, finding: SecurityFinding):
        """Add a security finding to the report"""
        self.findings.append(finding)
    
    def add_metadata(self, key: str, value: Any):
        """Add metadata to the report"""
        self.metadata[key] = value
    
    def generate_executive_summary(self):
        """Generates executive summary based on findings"""
        total_findings = len(self.findings)
        
        if total_findings == 0:
            self.executive_summary = "✅ No security issues detected during the analysis period."
            return
        
        # Count by severity
        severity_counts = {}
        for sev in ReportSeverity:
            severity_counts[sev.value] = sum(1 for f in self.findings if f.severity == sev)
        
        # Critical/high findings
        critical_high = severity_counts.get('critical', 0) + severity_counts.get('high', 0)
        
        if critical_high > 0:
            self.executive_summary = (
                f"🚨 **CRITICAL FINDINGS DETECTED**: {critical_high} high/critical security issues found. "
                f"Immediate action recommended."
            )
        elif severity_counts.get('medium', 0) > 0:
            self.executive_summary = (
                f"⚠️  **SECURITY ISSUES DETECTED**: {total_findings} security issues found. "
                f"Review and remediation recommended."
            )
        else:
            self.executive_summary = (
                f"✅ **MINOR ISSUES DETECTED**: {total_findings} low severity findings. "
                f"Consider for future improvements."
            )
    
    def generate_statistics(self, traffic_data: List[Dict[str, Any]]):
        """Generates statistics of the analyzed traffic"""
        if not traffic_data:
            self.statistics = {}
            return
        
        # Process timestamps
        timestamps = []
        for d in traffic_data:
            ts = d.get('timestamp')
            if ts:
                parsed_ts = self._parse_timestamp(ts)
                if parsed_ts:
                    timestamps.append(parsed_ts)
        
        if timestamps:
            start_time = min(timestamps)
            end_time = max(timestamps)
            duration = end_time - start_time
        else:
            start_time = end_time = None
            duration = timedelta(0)
        
        # Accountants
        queries = sum(1 for d in traffic_data if d.get('is_query', True))
        responses = len(traffic_data) - queries
        
        # Unique
        unique_clients = set(d.get('src_ip', '') for d in traffic_data)
        unique_domains = set(
            d.get('domain', '') for d in traffic_data 
            if d.get('domain') and d.get('domain') != 'unknown'
        )
        
        # Record types
        record_types = {}
        for d in traffic_data:
            rtype = d.get('record_type', 'unknown')
            record_types[rtype] = record_types.get(rtype, 0) + 1
        
        # Tasa QPS
        if duration and duration.total_seconds() > 0:
            qps = queries / duration.total_seconds()
        else:
            qps = 0
        
        # Top domains
        domain_counts = {}
        for d in traffic_data:
            domain = d.get('domain', '')
            if domain and domain != 'unknown':
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
        
        top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        self.statistics = {
            'analysis_period': {
                'start': start_time.isoformat() if start_time else 'N/A',
                'end': end_time.isoformat() if end_time else 'N/A',
                'duration_seconds': duration.total_seconds() if duration else 0,
                'duration_human': self._format_duration(duration)
            },
            'traffic_volume': {
                'total_packets': len(traffic_data),
                'queries': queries,
                'responses': responses,
                'query_response_ratio': responses / queries if queries > 0 else 0
            },
            'network_scope': {
                'unique_clients': len(unique_clients),
                'unique_domains': len(unique_domains),
                'unique_record_types': len(record_types)
            },
            'performance': {
                'queries_per_second': round(qps, 2),
                'queries_per_minute': round(qps * 60, 2),
                'avg_packet_rate': round(len(traffic_data) / duration.total_seconds() if duration and duration.total_seconds() > 0 else 0, 2)
            },
            'record_type_distribution': record_types,
            'top_domains': [{'domain': d, 'count': c} for d, c in top_domains]
        }
    
    def _format_duration(self, duration: timedelta) -> str:
        """Format duration for display"""
        if not duration:
            return "0s"
        
        total_seconds = int(duration.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        
        parts = []
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if seconds > 0 or not parts:
            parts.append(f"{seconds}s")
        
        return " ".join(parts)
    
    def generate_markdown_report(self) -> str:
        """Generate report in Markdown format"""
        report = f"""# {self.title}
        
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
## Executive Summary
        
{self.executive_summary}
        
## Analysis Overview
        
### Key Statistics
        
- **Analysis Period**: {self.statistics.get('analysis_period', {}).get('duration_human', 'N/A')}
- **Total Packets Analyzed**: {self.statistics.get('traffic_volume', {}).get('total_packets', 0):,}
- **DNS Queries**: {self.statistics.get('traffic_volume', {}).get('queries', 0):,}
- **DNS Responses**: {self.statistics.get('traffic_volume', {}).get('responses', 0):,}
- **Unique Clients**: {self.statistics.get('network_scope', {}).get('unique_clients', 0):,}
- **Unique Domains**: {self.statistics.get('network_scope', {}).get('unique_domains', 0):,}
- **Average QPS**: {self.statistics.get('performance', {}).get('queries_per_second', 0):.2f}
        
## Security Findings
        
Total Findings: **{len(self.findings)}**
        
"""
        
        # Group findings by severity
        findings_by_severity = {}
        for sev in ReportSeverity:
            findings_by_severity[sev.value] = [f for f in self.findings if f.severity == sev]
        
        # Show by severity (highest to lowest)
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            findings = findings_by_severity.get(severity, [])
            if findings:
                severity_emoji = {
                    'critical': '🚨',
                    'high': '🔴',
                    'medium': '🟡',
                    'low': '🔵',
                    'info': 'ℹ️'
                }.get(severity, '•')
                
                report += f"\n### {severity_emoji} {severity.upper()} Severity Findings ({len(findings)})\n\n"
                
                for finding in findings:
                    timestamp_str = finding.timestamp.strftime('%Y-%m-%d %H:%M:%S') if isinstance(finding.timestamp, datetime) else str(finding.timestamp)
                    
                    report += f"#### {finding.title}\n\n"
                    report += f"**ID**: `{finding.id}`  \n"
                    report += f"**Detector**: `{finding.detector}`  \n"
                    report += f"**Time**: {timestamp_str}  \n\n"
                    report += f"**Description**: {finding.description}  \n\n"
                    report += f"**Evidence**:  \n"
                    
                    for evidence in finding.evidence[:3]:  # Show only 3 evidences
                        for key, value in evidence.items():
                            report += f"  - **{key}**: {value}  \n"
                    
                    report += f"\n**Recommendation**: {finding.recommendation}  \n\n"
                    report += "---\n\n"
        
        # General recommendations
        report += "## Recommendations & Next Steps\n\n"
        
        if not self.findings:
            report += "1. ✅ **Continue current monitoring practices**  \n"
            report += "2. 🔄 **Regularly update baseline configurations**  \n"
            report += "3. 📊 **Schedule periodic security reviews**  \n"
        else:
            report += "### Immediate Actions (Critical/High Findings)\n\n"
            report += "1. 🛑 **Investigate and remediate critical findings within 24 hours**  \n"
            report += "2. 📋 **Document all security incidents and responses**  \n"
            report += "3. 🔒 **Implement additional monitoring for detected threat patterns**  \n\n"
            
            report += "### Short-term Improvements (Medium Findings)\n\n"
            report += "1. ⚙️ **Review and update security configurations within 7 days**  \n"
            report += "2. 🎯 **Implement targeted security controls for identified risks**  \n"
            report += "3. 📈 **Monitor effectiveness of implemented controls**  \n\n"
            
            report += "### Long-term Strategy (All Findings)\n\n"
            report += "1. 🏗️ **Develop comprehensive DNS security policy**  \n"
            report += "2. 👨‍💻 **Provide security awareness training for staff**  \n"
            report += "3. 🔄 **Establish regular security assessment schedule**  \n"
        
        # Appendices
        report += "\n## Appendices\n\n"
        report += "### A. Analysis Methodology\n\n"
        report += "This analysis was performed using DNS Expert Monitor v0.2.0 with the following detectors:\n\n"
        report += "- DNS Tunneling Detector (entropy analysis, pattern matching)\n"
        report += "- DNS Poisoning Detector (TTL analysis, response validation)\n"
        report += "- Amplification Attack Detector (rate analysis, packet size ratios)\n"
        report += "- NXDOMAIN Attack Detector (error rate analysis, domain generation)\n\n"
        
        report += "### B. Severity Definitions\n\n"
        report += "- **Critical**: Immediate threat to infrastructure or data confidentiality\n"
        report += "- **High**: Significant security risk requiring prompt attention\n"
        report += "- **Medium**: Security issue that should be addressed in normal operations\n"
        report += "- **Low**: Minor issue or potential improvement opportunity\n"
        report += "- **Info**: Informational finding with no direct security impact\n\n"
        
        report += "### C. Contact Information\n\n"
        report += "For questions or additional analysis, contact your security team or:\n\n"
        report += "📧 augustozarate@pm.me  \n"
        report += "🔗 https://github.com/augustozarate/dns-expert-monitor  \n\n"
        
        report += "---\n\n"
        report += f"*Report generated by DNS Expert Monitor v0.2.0 on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S UTC')}*"
        
        return report
    
    def generate_json_report(self) -> Dict[str, Any]:
        """Generate report in structured JSON format"""
        return {
            'metadata': {
                'title': self.title,
                'generated_at': datetime.now().isoformat(),
                'tool_version': '0.2.0',
                'tool_name': 'DNS Expert Monitor'
            },
            'executive_summary': self.executive_summary,
            'statistics': self.statistics,
            'findings': [f.to_dict() for f in self.findings],
            'summary': {
                'total_findings': len(self.findings),
                'findings_by_severity': {
                    sev.value: sum(1 for f in self.findings if f.severity == sev)
                    for sev in ReportSeverity
                },
                'findings_by_detector': self._group_findings_by_detector()
            }
        }
    
    def _group_findings_by_detector(self) -> Dict[str, int]:
        """Group findings by detector"""
        detectors = {}
        for finding in self.findings:
            detectors[finding.detector] = detectors.get(finding.detector, 0) + 1
        return detectors
    
    def print_console_report(self):
        """Print formatted report in console"""
        console.print(Panel(f"[bold cyan]{self.title}[/bold cyan]", border_style="cyan"))
        console.print(f"[dim]Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")
        
        # Executive Summary
        console.print(Panel(self.executive_summary, title="📋 Executive Summary", border_style="green"))
        
        # Statistics
        stats_table = Table(title="📊 Analysis Statistics", box=None)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green")
        
        if self.statistics:
            stats_table.add_row("Analysis Period", 
                              self.statistics.get('analysis_period', {}).get('duration_human', 'N/A'))
            stats_table.add_row("Total Packets", 
                              f"{self.statistics.get('traffic_volume', {}).get('total_packets', 0):,}")
            stats_table.add_row("Queries/Responses", 
                              f"{self.statistics.get('traffic_volume', {}).get('queries', 0):,}/"
                              f"{self.statistics.get('traffic_volume', {}).get('responses', 0):,}")
            stats_table.add_row("Unique Clients", 
                              f"{self.statistics.get('network_scope', {}).get('unique_clients', 0):,}")
            stats_table.add_row("Unique Domains", 
                              f"{self.statistics.get('network_scope', {}).get('unique_domains', 0):,}")
            stats_table.add_row("Avg QPS", 
                              f"{self.statistics.get('performance', {}).get('queries_per_second', 0):.2f}")
        
        console.print(stats_table)
        
        # Findings
        if self.findings:
            console.print(Panel(f"[bold red]🚨 SECURITY FINDINGS DETECTED: {len(self.findings)} total[/bold red]", 
                              border_style="red"))
            
            # Findings summary table
            findings_table = Table(title="🔍 Findings Summary", box=None)
            findings_table.add_column("Severity", style="bold")
            findings_table.add_column("Count", style="cyan")
            findings_table.add_column("Detectors", style="yellow")
            
            # Group by severity
            for severity in ReportSeverity:
                count = sum(1 for f in self.findings if f.severity == severity)
                if count > 0:
                    detectors = set(f.detector for f in self.findings if f.severity == severity)
                    
                    # Color by severity
                    severity_color = {
                        ReportSeverity.CRITICAL: "bold red",
                        ReportSeverity.HIGH: "red",
                        ReportSeverity.MEDIUM: "yellow",
                        ReportSeverity.LOW: "blue",
                        ReportSeverity.INFO: "dim"
                    }.get(severity, "white")
                    
                    findings_table.add_row(
                        f"[{severity_color}]{severity.value.upper()}[/{severity_color}]",
                        str(count),
                        ", ".join(detectors)
                    )
            
            console.print(findings_table)
            
            # Show critical/high findings
            critical_findings = [f for f in self.findings if f.severity in [ReportSeverity.CRITICAL, ReportSeverity.HIGH]]
            if critical_findings:
                console.print(Panel("[bold red]⚠️  CRITICAL/HIGH FINDINGS (Require Immediate Attention)[/bold red]", 
                                  border_style="red"))
                
                for finding in critical_findings[:3]:  # Show only 3 reviews
                    timestamp_str = finding.timestamp.strftime('%H:%M:%S') if isinstance(finding.timestamp, datetime) else str(finding.timestamp)
                    console.print(f"\n[bold]{finding.title}[/bold]")
                    console.print(f"[dim]ID: {finding.id} | Time: {timestamp_str} | Detector: {finding.detector}[/dim]")
                    console.print(f"{finding.description}")
                    console.print(f"[yellow]Recommendation:[/yellow] {finding.recommendation}")
        else:
            console.print(Panel("[bold green]✅ No security findings detected[/bold green]", 
                              border_style="green"))
        
        # Recommendations
        console.print(Panel("[bold cyan]📋 Recommendations[/bold cyan]", border_style="cyan"))
        
        if not self.findings:
            console.print("1. ✅ Continue regular monitoring practices")
            console.print("2. 📊 Schedule periodic security reviews")
            console.print("3. 🔄 Keep security configurations updated")
        else:
            console.print("1. 🛑 Investigate critical/high findings immediately")
            console.print("2. 📋 Document all incidents and responses")
            console.print("3. ⚙️ Review and update security configurations")
            console.print("4. 👨‍💻 Consider security awareness training")
            console.print("5. 🔄 Establish regular assessment schedule")
    
    def save_report(self, filename: str, format: str = "markdown"):
        """Save the report to a file"""
        try:
            if format.lower() == "markdown":
                content = self.generate_markdown_report()
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"[✓] Saved Markdown report: {filename}")
                
            elif format.lower() == "json":
                content = self.generate_json_report()
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(content, f, indent=2, default=str)
                print(f"[✓] Saved JSON report: {filename}")
                
            else:
                print(f"[!] Unsupported format: {format}")
                return False
            
            return True
            
        except Exception as e:
            print(f"[!] Error saving report: {e}")
            return False


# Utility functions for creating findings
def create_tunneling_finding(domain: str, entropy: float, client_ip: str) -> SecurityFinding:
    """Create a finding for DNS tunneling"""
    return SecurityFinding(
        id=f"TUNNEL-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        title=f"Possible DNS Tunneling Detected",
        description=f"Domain '{domain[:50]}...' shows high entropy ({entropy:.2f}) indicative of possible data exfiltration via DNS tunneling.",
        severity=ReportSeverity.HIGH if entropy > 4.5 else ReportSeverity.MEDIUM,
        evidence=[
            {"domain": domain[:100]},
            {"entropy": f"{entropy:.2f}"},
            {"client": client_ip},
            {"timestamp": datetime.now().isoformat()}
        ],
        recommendation="Investigate source IP, block suspicious domains, implement DNS filtering policies.",
        timestamp=datetime.now(),
        detector="dns_tunneling"
    )

def create_poisoning_finding(domain: str, ttl: int, server_ip: str) -> SecurityFinding:
    """Create a finding for DNS poisoning"""
    return SecurityFinding(
        id=f"POISON-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        title=f"Possible DNS Cache Poisoning",
        description=f"Domain '{domain}' received response with suspiciously low TTL ({ttl}s) from server {server_ip}.",
        severity=ReportSeverity.HIGH if ttl < 10 else ReportSeverity.MEDIUM,
        evidence=[
            {"domain": domain},
            {"ttl": f"{ttl} seconds"},
            {"server": server_ip},
            {"timestamp": datetime.now().isoformat()}
        ],
        recommendation="Validate DNS responses, implement DNSSEC, monitor for multiple responses to same queries.",
        timestamp=datetime.now(),
        detector="poisoning_detector"
    )

def create_amplification_finding(client_ip: str, qps: float, ratio: float) -> SecurityFinding:
    """Create a finding for DDoS amplification"""
    return SecurityFinding(
        id=f"DDOS-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        title=f"Possible DNS Amplification Attack",
        description=f"Client {client_ip} showing high query rate ({qps:.1f} QPS) with amplification ratio {ratio:.1f}x.",
        severity=ReportSeverity.CRITICAL if ratio > 50 else ReportSeverity.HIGH if ratio > 20 else ReportSeverity.MEDIUM,
        evidence=[
            {"client": client_ip},
            {"queries_per_second": f"{qps:.1f}"},
            {"amplification_ratio": f"{ratio:.1f}x"},
            {"timestamp": datetime.now().isoformat()}
        ],
        recommendation="Implement rate limiting, block source IP, contact ISP if external, review firewall rules.",
        timestamp=datetime.now(),
        detector="amplification_detector"
    )
"""
DNS data exporter to multiple formats
"""
import json
import csv
import yaml
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from scapy.all import wrpcap
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
import os

class DataExporter:
    """Exports DNS data to different formats with full support"""
    
    @staticmethod
    def _parse_timestamp(ts):
        """Convert timestamp string a datetime object"""
        if ts is None:
            return datetime.now()
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                try:
                    return datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%f')
                except (ValueError, TypeError):
                    try:
                        return datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                    except:
                        return datetime.now()
        return datetime.now()
    
    @staticmethod
    def _flatten_dict(d: Dict, parent_key: str = '', sep: str = '_') -> Dict:
        """Flattens nested dictionaries for CSV"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(DataExporter._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, json.dumps(v, ensure_ascii=False, default=str)))
            else:
                items.append((new_key, v))
        return dict(items)
    
    @staticmethod
    def to_json(data: List[Dict[str, Any]], filename: str, indent: int = 2):
        """Export to JSON in a readable format"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=indent, default=str, ensure_ascii=False)
            print(f"[✓] Exported JSON: {filename} ({len(data)} records)")
            return True
        except Exception as e:
            print(f"[!] Error exporting JSON: {e}")
            return False
    
    @staticmethod
    def to_csv(data: List[Dict[str, Any]], filename: str, delimiter: str = ','):
        """Export to CSV with robust field handling"""
        if not data:
            print("[!] There is no data to export to CSV")
            return False
        
        try:
            # Flatten all records
            flat_data = []
            all_keys = set()
            
            for item in data:
                flat_item = DataExporter._flatten_dict(item)
                # Convert non-serializable types
                for key, value in flat_item.items():
                    if isinstance(value, (datetime, timedelta)):
                        flat_item[key] = str(value)
                    elif isinstance(value, (dict, list)):
                        flat_item[key] = json.dumps(value, ensure_ascii=False, default=str)
                flat_data.append(flat_item)
                all_keys.update(flat_item.keys())
            
            # Sort keys for consistency
            fieldnames = sorted(list(all_keys))
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=delimiter, 
                                       extrasaction='ignore')
                writer.writeheader()
                writer.writerows(flat_data)
            
            print(f"[✓] Exported CSV: {filename} ({len(data)} records)")
            return True
        except Exception as e:
            print(f"[!] Error exporting CSV: {e}")
            return False
    
    @staticmethod
    def to_pcap(data: List[Dict[str, Any]], filename: str):
        """Export to PCAP file for analysis with Wireshark"""
        try:
            from scapy.all import wrpcap
            from scapy.layers.inet import IP, UDP
            from scapy.layers.dns import DNS, DNSQR, DNSRR
            
            packets = []
            packet_count = 0
            
            for i, item in enumerate(data):
                try:
                    # Use index as ID
                    dns_id = i % 65535
                    
                    if item.get('is_query', True):
                        # Consultation package
                        pkt = IP(src=item.get('src_ip', '192.168.1.1'),
                                dst=item.get('dst_ip', '8.8.8.8')) / \
                              UDP(sport=54321, dport=53) / \
                              DNS(id=dns_id, qr=0, 
                                  qd=DNSQR(qname=item.get('domain', 'example.com')))
                    else:
                        # Response package
                        response_data = item.get('response_data', '192.168.1.1')
                        pkt = IP(src=item.get('src_ip', '8.8.8.8'),
                                dst=item.get('dst_ip', '192.168.1.1')) / \
                              UDP(sport=53, dport=54321) / \
                              DNS(id=dns_id, qr=1, aa=1, rd=1, ra=1,
                                  qd=DNSQR(qname=item.get('domain', 'example.com')),
                                  an=DNSRR(rrname=item.get('domain', 'example.com'),
                                          ttl=item.get('ttl', 300),
                                          rdata=response_data))
                    
                    packets.append(pkt)
                    packet_count += 1
                    
                except Exception as e:
                    continue
            
            if packets:
                wrpcap(filename, packets)
                print(f"[✓] Exported PCAP: {filename} ({packet_count} packets)")
                return True
            else:
                print("[!] Packets could not be created for PCAP")
                return False
                
        except Exception as e:
            print(f"[!] Error exporting PCAP: {e}")
            return False
    
    @staticmethod
    def to_html_report(data: List[Dict[str, Any]], filename: str, 
                      title: str = "DNS Analysis Report"):
        """Generates HTML report with statistics"""
        try:
            if not data:
                print("[!] There is no data for HTML report")
                return False
            
            # Process timestamps
            timestamps = []
            for item in data:
                ts = item.get('timestamp')
                if ts:
                    parsed_ts = DataExporter._parse_timestamp(ts)
                    timestamps.append(parsed_ts)
            
            if timestamps:
                start_time = min(timestamps)
                end_time = max(timestamps)
                duration = end_time - start_time
                duration_str = DataExporter._format_duration(duration)
            else:
                start_time = end_time = datetime.now()
                duration = timedelta(0)
                duration_str = "0s"
            
            # Calculate statistics
            queries = sum(1 for d in data if d.get('is_query', True))
            responses = len(data) - queries
            
            unique_clients = set()
            unique_domains = set()
            record_types = {}
            domain_counts = {}
            security_alerts = []
            
            for item in data:
                # Customers
                client = item.get('src_ip', '')
                if client and client != 'unknown':
                    unique_clients.add(client)
                
                # Domains
                domain = item.get('domain', '')
                if domain and domain != 'unknown':
                    unique_domains.add(domain)
                    domain_counts[domain] = domain_counts.get(domain, 0) + 1
                
                # Record types
                rtype = item.get('record_type', 'unknown')
                record_types[rtype] = record_types.get(rtype, 0) + 1
                
                # Security alerts
                if 'security_alerts' in item:
                    security_alerts.extend(item['security_alerts'])
            
            # Top domains
            top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Alert statistics
            alert_severity = {'high': 0, 'medium': 0, 'low': 0}
            alert_types = {}
            
            for alert in security_alerts:
                severity = alert.get('severity', 'medium')
                alert_severity[severity] = alert_severity.get(severity, 0) + 1
                alert_type = alert.get('type', 'unknown')
                alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
            
            # Generate HTML
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{ 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 20px; 
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }}
        h1 {{ 
            color: #333; 
            border-bottom: 4px solid #4CAF50; 
            padding-bottom: 15px;
            margin-bottom: 25px;
            font-size: 2.2em;
        }}
        h2 {{ 
            color: #555; 
            margin: 30px 0 20px 0;
            font-size: 1.6em;
        }}
        .stats-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 25px; 
            margin: 25px 0;
        }}
        .stat-card {{ 
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 25px; 
            border-radius: 15px; 
            border-left: 6px solid #4CAF50;
            transition: transform 0.3s;
        }}
        .stat-card:hover {{ transform: translateY(-5px); }}
        .stat-card h3 {{ 
            margin: 0 0 15px 0; 
            color: #333;
            font-size: 1.3em;
        }}
        .stat-card p {{ 
            margin: 10px 0; 
            color: #444;
            font-size: 1.1em;
        }}
        .alert {{ 
            padding: 20px; 
            border-radius: 12px; 
            margin: 15px 0;
            border-left: 6px solid;
            font-size: 1.1em;
        }}
        .alert.high {{ 
            background: linear-gradient(135deg, #fee 0%, #ffe5e5 100%);
            border-color: #dc3545;
            color: #721c24;
        }}
        .alert.medium {{ 
            background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
            border-color: #ffc107;
            color: #856404;
        }}
        .alert.low {{ 
            background: linear-gradient(135deg, #d1ecf1 0%, #bee5eb 100%);
            border-color: #17a2b8;
            color: #0c5460;
        }}
        table {{ 
            width: 100%; 
            border-collapse: collapse; 
            margin: 25px 0;
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        th, td {{ 
            padding: 15px; 
            text-align: left; 
            border-bottom: 1px solid #ddd;
        }}
        th {{ 
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
            color: white;
            font-weight: 600;
            text-transform: uppercase;
        }}
        tr:hover {{ background-color: #f5f5f5; }}
        .timestamp {{ 
            font-size: 0.9em; 
            color: #666; 
            margin-top: 30px;
            padding-top: 20px;
            border-top: 2px dashed #ddd;
            text-align: right;
        }}
        .badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
            margin: 5px;
        }}
        .badge.high {{ background: #dc3545; color: white; }}
        .badge.medium {{ background: #ffc107; color: black; }}
        .badge.low {{ background: #17a2b8; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 {title}</h1>
        <p style="font-size: 1.1em; color: #666;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total Records: {len(data)}</p>
        
        <h2>📊 Statistics Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <h3>📦 Traffic Volume</h3>
                <p><strong>Total Packets:</strong> {len(data):,}</p>
                <p><strong>Queries:</strong> {queries:,}</p>
                <p><strong>Responses:</strong> {responses:,}</p>
                <p><strong>Ratio:</strong> {responses/queries:.1%}</p>
            </div>
            <div class="stat-card">
                <h3>🌐 Network Info</h3>
                <p><strong>Unique Clients:</strong> {len(unique_clients):,}</p>
                <p><strong>Unique Domains:</strong> {len(unique_domains):,}</p>
                <p><strong>Record Types:</strong> {len(record_types)}</p>
            </div>
            <div class="stat-card">
                <h3>⏱️ Time Analysis</h3>
                <p><strong>Duration:</strong> {duration_str}</p>
                <p><strong>Avg QPS:</strong> {queries / max(duration.total_seconds(), 1):.2f}</p>
                <p><strong>Start:</strong> {start_time.strftime('%H:%M:%S')}</p>
                <p><strong>End:</strong> {end_time.strftime('%H:%M:%S')}</p>
            </div>
            <div class="stat-card">
                <h3>🛡️ Security Alerts</h3>
                <p><strong>Total Alerts:</strong> {len(security_alerts):,}</p>
                <p><span class="badge high">High: {alert_severity['high']}</span></p>
                <p><span class="badge medium">Medium: {alert_severity['medium']}</span></p>
                <p><span class="badge low">Low: {alert_severity['low']}</span></p>
            </div>
        </div>
        
        <h2>🏆 Top 10 Domains</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Domain</th>
                    <th>Queries</th>
                    <th>% of Total</th>
                </tr>
            </thead>
            <tbody>
"""
            
            for idx, (domain, count) in enumerate(top_domains[:10], 1):
                percentage = (count / max(queries, 1)) * 100
                display_domain = domain[:50] + '...' if len(domain) > 50 else domain
                html_content += f"""
                <tr>
                    <td>{idx}</td>
                    <td>{display_domain}</td>
                    <td><strong>{count:,}</strong></td>
                    <td>{percentage:.1f}%</td>
                </tr>
                """
            
            html_content += """
            </tbody>
        </table>
        
        <h2>🛡️ Security Alerts</h2>
"""
            
            if security_alerts:
                for alert in security_alerts[-10:]:  # Últimas 10 alertas
                    severity = alert.get('severity', 'medium')
                    alert_type = alert.get('type', 'Alert')
                    message = alert.get('message', 'No message')
                    details = alert.get('details', {})
                    
                    html_content += f"""
            <div class="alert {severity}">
                <strong>🚨 {alert_type.upper()}</strong><br>
                {message}<br>
                <small>Time: {details.get('timestamp', 'N/A')} | Client: {details.get('client', 'N/A')}</small>
            </div>
                    """
            else:
                html_content += """
            <div class="alert low">
                <strong>✅ No security alerts detected</strong><br>
                No suspicious activity was detected during this capture period.
            </div>
                """
            
            html_content += f"""
        <h2>📋 Record Types Distribution</h2>
        <table>
            <thead>
                <tr>
                    <th>Record Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
"""
            
            total_records = len(data)
            for rtype, count in sorted(record_types.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_records) * 100
                html_content += f"""
                <tr>
                    <td><strong>{rtype}</strong></td>
                    <td>{count:,}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
                """
            
            html_content += f"""
            </tbody>
        </table>
        
        <div class="timestamp">
            <p>Report generated by <strong>DNS Expert Monitor v0.2.0</strong></p>
            <p>For more information, visit: https://github.com/augustozarate/dns-expert-monitor</p>
            <p style="margin-top: 10px;">⚠️ This report contains security-sensitive information. Handle with care.</p>
        </div>
    </div>
</body>
</html>
            """
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"[✓] Exported HTML Report: {filename}")
            return True
            
        except Exception as e:
            print(f"[!] Error generating HTML report: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    @staticmethod
    def _format_duration(duration: timedelta) -> str:
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
    
    @staticmethod
    def to_yaml(data: List[Dict[str, Any]], filename: str):
        """Export to YAML for configuration and analysis"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            print(f"[✓] Exported YAML: {filename} ({len(data)} records)")
            return True
        except Exception as e:
            print(f"[!] Error exporting YAML: {e}")
            return False
    
    @staticmethod
    def export_all(data: List[Dict[str, Any]], basename: str, formats: List[str] = None):
        """Export to multiple formats simultaneously"""
        if formats is None:
            formats = ['json', 'csv', 'html', 'yaml', 'pcap']
        
        results = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for fmt in formats:
            filename = f"{basename}_{timestamp}.{fmt}" if fmt != 'pcap' else f"{basename}_{timestamp}.pcap"
            
            if fmt == 'json':
                results['json'] = DataExporter.to_json(data, filename)
            elif fmt == 'csv':
                results['csv'] = DataExporter.to_csv(data, filename)
            elif fmt == 'html':
                results['html'] = DataExporter.to_html_report(data, filename)
            elif fmt == 'yaml':
                results['yaml'] = DataExporter.to_yaml(data, filename)
            elif fmt == 'pcap':
                results['pcap'] = DataExporter.to_pcap(data, filename)
        
        return results
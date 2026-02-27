"""
Unified Security Detector Manager
"""
from typing import Dict, Any, List, Optional
import yaml
import os

from .dns_tunneling import DNSTunnelingDetector
from .poisoning_detector import PoisoningDetector
from .amplification_detector import AmplificationDetector
from .nxdomain_attack import NXDomainAttackDetector

class SecurityManager:
    """Orchestrates all security detectors"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.detectors = {}
        self.config = self._load_config(config_path)
        self.alerts = []
        
        # Complete default configurations for each detector
        self.default_configs = {
            'dns_tunneling': {
                'entropy_threshold': 4.5,
                'max_subdomain_length': 50,
                'max_queries_per_second': 100,
                'suspicious_record_types': ['TXT', 'NULL', 'KEY', 'OPT'],
                'max_subdomain_count': 5,
                'min_domain_length_for_check': 20,
                'high_entropy_suspicious': True,
                'check_base64_patterns': True,
                'check_hex_patterns': True
            },
            'poisoning_detector': {
                'min_ttl_for_alert': 30,
                'max_different_responses': 2,
                'time_window_minutes': 5,
                'check_ttl_anomalies': True,
                'check_multiple_responses': True,
                'check_unauthorized_servers': True,
                'authorized_servers': ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9']
            },
            'amplification_detector': {
                'min_amplification_ratio': 10,
                'max_queries_per_second': 100,
                'check_any_queries': True,
                'any_query_threshold': 50,
                'time_window_seconds': 60,
                'check_source_ip_spoofing': True,
                'suspicious_record_types': ['ANY', 'AAAA', 'MX', 'TXT']
            },
            'nxdomain_attack': {
                'nxdomain_percentage_threshold': 30,
                'nxdomain_per_minute_threshold': 100,
                'check_random_subdomains': True,
                'max_random_subdomains_per_domain': 50,
                'time_window_minutes': 5,
                'check_domain_generation_algorithms': True
            }
        }
        
        # Initialize detectors
        self._init_detectors()
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Carga configuración desde archivo YAML"""
        default_config = {
            'detectors': {
                'dns_tunneling': {'enabled': True},
                'poisoning_detector': {'enabled': True},
                'amplification_detector': {'enabled': True},
                'nxdomain_attack': {'enabled': True}
            },
            'alert_threshold': 'medium',
            'alert_cooldown_seconds': 60,
            'max_alerts_per_minute': 100
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    file_config = yaml.safe_load(f)
                    if file_config:
                        self._merge_dicts(default_config, file_config)
            except Exception as e:
                print(f"[!] Error loading configuration {config_path}: {e}")
                print("[i] Using default settings")
        
        return default_config
    
    def _merge_dicts(self, base: Dict, update: Dict):
        """Merge dictionaries recursively"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_dicts(base[key], value)
            else:
                base[key] = value
    
    def _init_detectors(self):
        """Initializes all enabled detectors"""
        detector_configs = self.config.get('detectors', {})
        
        # Tunneling configuration
        if detector_configs.get('dns_tunneling', {}).get('enabled', True):
            config = self.default_configs['dns_tunneling'].copy()
            user_config = detector_configs.get('dns_tunneling', {})
            config.update({k: v for k, v in user_config.items() if k != 'enabled'})
            
            try:
                self.detectors['tunneling'] = DNSTunnelingDetector(config)
                print(f"[✓] Tunneling detector initialized")
            except Exception as e:
                print(f"[!] Error initializing detector tunneling: {e}")
        
        # Settings for poisoning
        if detector_configs.get('poisoning_detector', {}).get('enabled', True):
            config = self.default_configs['poisoning_detector'].copy()
            user_config = detector_configs.get('poisoning_detector', {})
            config.update({k: v for k, v in user_config.items() if k != 'enabled'})
            
            try:
                self.detectors['poisoning'] = PoisoningDetector(config)
                print(f"[✓] Poisoning detector initialized")
            except Exception as e:
                print(f"[!] Error initializing poisoning detector: {e}")
        
        # Amplification settings
        if detector_configs.get('amplification_detector', {}).get('enabled', True):
            config = self.default_configs['amplification_detector'].copy()
            user_config = detector_configs.get('amplification_detector', {})
            config.update({k: v for k, v in user_config.items() if k != 'enabled'})
            
            try:
                self.detectors['amplification'] = AmplificationDetector(config)
                print(f"[✓] Amplification detector initialized")
            except Exception as e:
                print(f"[!] Error initializing detector amplification: {e}")
        
        # Configuration for nxdomain
        if detector_configs.get('nxdomain_attack', {}).get('enabled', True):
            config = self.default_configs['nxdomain_attack'].copy()
            user_config = detector_configs.get('nxdomain_attack', {})
            config.update({k: v for k, v in user_config.items() if k != 'enabled'})
            
            try:
                self.detectors['nxdomain'] = NXDomainAttackDetector(config)
                print(f"[✓] NXDOMAIN detector initialized")
            except Exception as e:
                print(f"[!] Error initializing nxdomain detector: {e}")
        
        print(f"[✓] {len(self.detectors)} initialized security detectors")
    
    def analyze_packet(self, packet_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze a packet with all detectors"""
        all_alerts = []
        
        for name, detector in self.detectors.items():
            try:
                if name == 'amplification':
                    # Simple estimate of package size
                    packet_size = 100 if packet_data.get('is_query', True) else 500
                    alerts = detector.detect(packet_data, packet_size)
                else:
                    alerts = detector.detect(packet_data)
                
                if alerts:
                    # Add detector name to each alert
                    for alert in alerts:
                        alert['detector'] = name
                    
                    # Filter by severity
                    filtered_alerts = self._filter_by_severity(alerts)
                    all_alerts.extend(filtered_alerts)
                
            except Exception as e:
                # Only show error once per type to avoid overloading
                if not hasattr(detector, '_error_shown'):
                    print(f"[!] Error en detector {name}: {type(e).__name__}")
                    detector._error_shown = True
        
        # Add to history
        self.alerts.extend(all_alerts)
        
        # Limit history size
        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-1000:]
        
        return all_alerts
    
    def _filter_by_severity(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter alerts by severity threshold"""
        threshold = self.config.get('alert_threshold', 'medium')
        
        severity_map = {
            'low': ['low', 'medium', 'high'],
            'medium': ['medium', 'high'],
            'high': ['high']
        }
        
        allowed_severities = severity_map.get(threshold, ['medium', 'high'])
        
        return [
            alert for alert in alerts
            if alert.get('severity', 'medium') in allowed_severities
        ]
    
    def get_alerts_summary(self, limit: int = 20) -> Dict[str, Any]:
        "Gets alert summary"
        recent_alerts = self.alerts[-limit:] if self.alerts else []
        
        by_type = {}
        by_severity = {'low': 0, 'medium': 0, 'high': 0}
        by_detector = {}
        
        for alert in recent_alerts:
            alert_type = alert.get('type', 'unknown')
            by_type[alert_type] = by_type.get(alert_type, 0) + 1
            
            severity = alert.get('severity', 'medium')
            by_severity[severity] = by_severity.get(severity, 0) + 1
            
            detector = alert.get('detector', 'unknown')
            by_detector[detector] = by_detector.get(detector, 0) + 1
        
        return {
            'total_alerts': len(self.alerts),
            'recent_alerts': len(recent_alerts),
            'by_type': by_type,
            'by_severity': by_severity,
            'by_detector': by_detector,
            'detectors_active': len(self.detectors),
            'recent_alerts_list': recent_alerts[-5:]  # Últimas 5 alertas
        }
    
    def get_detector_summary(self) -> Dict[str, Any]:
        """Gets a summary of all detectors"""
        summaries = {}
        
        for name, detector in self.detectors.items():
            try:
                if hasattr(detector, 'get_summary'):
                    summaries[name] = detector.get_summary()
                else:
                    summaries[name] = {'status': 'active', 'method': 'no_summary'}
            except Exception as e:
                summaries[name] = {
                    'status': 'error', 
                    'error': f"{type(e).__name__}: {str(e)[:50]}"
                }
        
        return summaries
    
    def get_detector(self, name: str):
        "Get a specific detector"
        return self.detectors.get(name)
    
    def reset(self):
        """Reset all detectors"""
        self.alerts.clear()
        for detector in self.detectors.values():
            if hasattr(detector, 'alerts'):
                detector.alerts.clear()
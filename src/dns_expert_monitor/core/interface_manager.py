"""
Intelligent cross-platform network interface management
"""
import sys
import platform
import subprocess
from typing import Optional, List, Dict, Any
import netifaces

class InterfaceManager:
    """Manage network interfaces in a compatible way between systems"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.interfaces = self._get_all_interfaces()
    
    def _get_all_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Gets all system interfaces"""
        try:
            if self.system == "windows":
                return self._get_windows_interfaces()
            elif self.system in ["linux", "darwin"]:
                return self._get_unix_interfaces()
            else:
                return self._get_fallback_interfaces()
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return self._get_fallback_interfaces()
    
    def _get_windows_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Interfaces in Windows"""
        interfaces = {}
        for iface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    
                    interfaces[iface] = {
                        'name': iface,
                        'ip': ip_info.get('addr', 'N/A'),
                        'netmask': ip_info.get('netmask', 'N/A'),
                        'active': True,
                        'type': self._get_interface_type(iface),
                        'description': self._get_interface_description(iface),
                        'mac': self._get_mac_address(iface)
                    }
            except:
                continue
        return interfaces
    
    def _get_unix_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Interfaces in Linux/macOS"""
        interfaces = {}
        
        # Use netifaces as a base
        for iface in netifaces.interfaces():
            interfaces[iface] = {
                'name': iface,
                'active': False,
                'type': self._get_interface_type(iface),
                'description': self._get_interface_description(iface),
                'mac': self._get_mac_address(iface)
            }
            
            try:
                addrs = netifaces.ifaddresses(iface)
                
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    interfaces[iface].update({
                        'ip': ip_info.get('addr'),
                        'netmask': ip_info.get('netmask'),
                        'active': True
                    })
                
                if netifaces.AF_LINK in addrs:
                    link_info = addrs[netifaces.AF_LINK][0]
                    interfaces[iface]['mac'] = link_info.get('addr')
                    
            except:
                pass
        
        return interfaces
    
    def _get_fallback_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Fallback using only names"""
        interfaces = {}
        try:
            import scapy.all as scapy
            for iface in scapy.get_if_list():
                interfaces[iface] = {
                    'name': iface,
                    'active': True,
                    'type': self._get_interface_type(iface),
                    'description': self._get_interface_description(iface)
                }
        except:
            pass
        return interfaces
    
    def _get_interface_type(self, iface_name: str) -> str:
        """Determine the type of interface"""
        iface_lower = iface_name.lower()
        
        if any(x in iface_lower for x in ['eth', 'enp', 'ens', 'eno', 'em']):
            return 'ethernet'
        elif any(x in iface_lower for x in ['wlan', 'wlp', 'wifi', 'wl']):
            return 'wifi'
        elif 'lo' in iface_lower or iface_name == 'lo':
            return 'loopback'
        elif any(x in iface_lower for x in ['docker', 'veth', 'br-', 'cni']):
            return 'virtual'
        elif any(x in iface_lower for x in ['tun', 'tap', 'vpn']):
            return 'tunnel'
        elif any(x in iface_lower for x in ['vmnet', 'vboxnet', 'virbr']):
            return 'virtualization'
        else:
            return 'unknown'
    
    def _get_interface_description(self, iface_name: str) -> str:
        """Get friendly description"""
        iface_type = self._get_interface_type(iface_name)
        
        descriptions = {
            'ethernet': 'Wired ethernet',
            'wifi': 'Wireless Wi-Fi',
            'loopback': 'Loopback interna',
            'virtual': 'Virtual interface',
            'tunnel': 'VPN tunnel',
            'virtualization': 'Virtual machine',
            'unknown': 'Unknown'
        }
        
        return descriptions.get(iface_type, 'Unknown')
    
    def _get_mac_address(self, iface_name: str) -> Optional[str]:
        """Get MAC address of the interface"""
        try:
            addrs = netifaces.ifaddresses(iface_name)
            if netifaces.AF_LINK in addrs:
                return addrs[netifaces.AF_LINK][0].get('addr')
        except:
            pass
        return None
    
    def get_active_interfaces(self) -> List[Dict[str, Any]]:
        """Returns only active interfaces with assigned IP"""
        active = []
        for iface in self.interfaces.values():
            if iface.get('active') and iface.get('ip') not in [None, 'N/A', '127.0.0.1']:
                active.append(iface)
        return active
    
    def get_default_interface(self) -> Optional[str]:
        """Gets the default interface (with gateway)"""
        try:
            gateways = netifaces.gateways()
            default = gateways.get('default', {})
            
            if netifaces.AF_INET in default:
                return default[netifaces.AF_INET][1]
        except:
            pass
        
        # Fallback: first active non-loopback interface
        active = self.get_active_interfaces()
        for iface in active:
            if iface['type'] != 'loopback':
                return iface['name']
        
        return None
    
    def print_interfaces_table(self):
        """Print interfaces to a formatted table"""
        from rich.console import Console
        from rich.table import Table
        
        console = Console()
        table = Table(title="📡 Available Network Interfaces")
        
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Type", style="green")
        table.add_column("IP", style="yellow")
        table.add_column("MAC", style="magenta")
        table.add_column("State", style="bold")
        
        default_iface = self.get_default_interface()
        
        for iface_name, info in sorted(self.interfaces.items()):
            status = "✅" if info.get('active') else "❌"
            ip = info.get('ip', 'No IP')
            mac = info.get('mac', 'N/A')[:17] if info.get('mac') else 'N/A'
            
            if iface_name == default_iface:
                iface_name = f"🌟 {iface_name}"
            
            table.add_row(
                iface_name,
                info.get('description', 'Unknown'),
                ip,
                mac,
                status
            )
        
        console.print(table)